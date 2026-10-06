//! Credential redaction and device oob_drift computation for tool output.
//!
//! Applied at the MCP tool boundary only, never inside [`crate::SdcClient`],
//! for the reason `projection.rs` gives: change-control reads the same
//! endpoints to capture before-state, and redacting there would hide drift.
//!
//! Generic key- and value-shape redaction (`secret`, `token`, `password`,
//! `psk`, `private_key`, `community`, `api_key`, crypt hashes, PEM blocks,
//! ...) is delegated to the shared [`mecmcp_redact`] crate, which every
//! mechub MCP server uses so a new denylist entry or value shape lands once,
//! not per server (MEC-345's shared-crate migration; MEC-14 H1b).
//!
//! Two things are real SDC-specific policy the generic scan cannot infer on
//! its own, declared here as a [`mecmcp_redact::Profile`] (MEC-1244) and
//! applied through [`mecmcp_redact::redact_json_value_with_profile`]:
//!
//! - `site_config` and `cpe_config` are withheld **as a whole**, not
//!   key-scanned. They are rendered device configuration bodies in a format
//!   SDC does not document, and SDC-generated IPsec config carries the IKE
//!   pre-shared key inline; there is no guarantee the generic line-oriented
//!   scan recognizes every secret shape SDC's CPE templates can produce, so
//!   the whole body is dropped rather than trusted to a best-effort scan.
//!   This runs *before* the generic scan.
//! - [`KEY_EXEMPTIONS`] exempts specific upstream field names that collide
//!   with the denylist substring but are not secrets: our own opaque paging
//!   cursors (`continuation_token`, and the upstream `nextPageToken` it
//!   mirrors — redacting them breaks paging, MEC-440 B1), and a set of SDC
//!   `session*`/`*session*` fields that are not credentials (session-logging
//!   flags, session counters, an SSL session cache toggle — over-redacting
//!   them can hide a policy rule's real logging state from the model
//!   reviewing a write, MEC-973 F1).
//!
//! ## Redaction policy
//!
//! `finish_redacted` is used for every read tool, with no per-family
//! exemption; see `REDACTED_TOOLS` in `tests/tool_contract.rs` for the
//! enforced, exhaustive list. Write tools (`prepare_*`/`apply_*`/
//! `approve_*`/`discard_*`) go through `finish_redacted` too: `prepare_*`
//! results echo the raw upstream before-state in `prepared_change`, and
//! `apply_*` results return a `plan: {before, after}`, so they carry the same
//! upstream fields the read path redacts. Only the tool output is redacted —
//! the stored action, the plan digest and the change-set id are untouched, so
//! approve/apply work unchanged.

use mecmcp_redact::Profile;
use serde_json::Value;

/// Marker substituted for a redacted value. Re-exported so callers building
/// their own fixtures can assert against it without duplicating the string.
pub const REDACTED: &str = "[REDACTED]";

/// Upstream field names that match the shared crate's denylist substring by
/// coincidence, not because they carry a secret. Exact match after
/// normalization, at any depth. Every SDC OpenAPI property name the shared
/// crate's denylist matches must be either an intentional secret or listed
/// here — see `spec_property_names_matching_the_denylist_are_accounted_for`
/// below, which fails if a spec refresh adds a new false positive silently.
///
/// - `continuationtoken` / `nextpagetoken`: opaque paging cursors the caller
///   must echo back to page past the first page (MEC-440 B1).
/// - The `session`-substring group (`sessioninitiatelog`, `sessioncloselog`,
///   `maxsessionnumber`, `noofsessions`, `disablesessionresumption`,
///   `sessionignoredlog`, `sessionsallowedlog`, `sessionsdroppedlog`,
///   `sessionswhitelistedlog`, `sslsessioncache`, `closesessionaction`,
///   `maxsessions`): firewall-rule logging flags and NAT/SSL/ICAP session
///   settings, not credentials. Over-redacting them can hide a policy rule's
///   real session-logging state from the model reviewing a write (MEC-973
///   F1).
const KEY_EXEMPTIONS: &[&str] = &[
    "continuationtoken",
    "nextpagetoken",
    "sessioninitiatelog",
    "sessioncloselog",
    "maxsessionnumber",
    "noofsessions",
    "disablesessionresumption",
    "sessionignoredlog",
    "sessionsallowedlog",
    "sessionsdroppedlog",
    "sessionswhitelistedlog",
    "sslsessioncache",
    "closesessionaction",
    "maxsessions",
];

/// SDC's declared extensions to the shared crate's generic denylist-and-shape
/// scan: `site_config` and `cpe_config` withheld wholesale, and
/// [`KEY_EXEMPTIONS`] carved out of the denylist. See the module docs for why
/// each needs to be declared rather than handled generically.
const PROFILE: Profile = Profile::new(&["siteconfig", "cpeconfig"], KEY_EXEMPTIONS);

/// Normalize a key for comparison: lowercase and remove `_` and `-`.
///
/// Matches [`mecmcp_redact::Profile`]'s own normalization, so a key
/// comparison made locally (in
/// `spec_property_names_matching_the_denylist_are_accounted_for`) agrees with
/// how the shared crate matches [`PROFILE`]'s entries.
#[cfg(test)]
fn normalize_key(key: &str) -> String {
    key.to_ascii_lowercase()
        .chars()
        .filter(|c| *c != '_' && *c != '-')
        .collect()
}

/// Replace every credential-bearing value in `value`, at any depth.
///
/// `null` stays `null`: it carries no secret, and rewriting it would claim
/// one existed.
#[must_use]
pub fn redact_secrets(mut value: Value) -> Value {
    mecmcp_redact::redact_json_value_with_profile(&mut value, &PROFILE);
    value
}

/// Whether `value` carries the [`REDACTED`] marker in any string, at any depth.
///
/// The shared crate's free-text scan can rewrite only part of a string (for
/// example `"... token rotation owner=netops"` becomes `"... token
/// [REDACTED]"`), so this checks for the marker as a substring rather than
/// requiring the whole string to equal it. Every write path must call this on
/// the caller-supplied request body and refuse the write if it returns
/// `true`: a model that echoes back a value it read through
/// [`redact_secrets`] without re-reading it out-of-band would otherwise write
/// the literal placeholder over the real field.
#[must_use]
pub fn contains_redaction_marker(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains(REDACTED),
        Value::Object(map) => map.values().any(contains_redaction_marker),
        Value::Array(items) => items.iter().any(contains_redaction_marker),
        _ => false,
    }
}

/// Redact license keys in an RMA state response.
///
/// Replaces each element of the top-level `missing_licenses` array with the
/// REDACTED marker, preserving array length so the count stays visible. The
/// spec describes `missing_licenses` as "Array of license keys that are missing",
/// so the keys are the array VALUES, not object keys.
///
/// Fails closed: if `missing_licenses` is present but not an array (API
/// regression), the entire value is replaced with REDACTED. `null` stays `null`.
///
/// Other fields are left untouched. This is SDC-specific business logic
/// (license keys, not credentials), so it stays local rather than moving to
/// the shared crate.
#[must_use]
pub fn redact_rma_state(mut value: Value) -> Value {
    if let Some(obj) = value.as_object_mut()
        && let Some(licenses) = obj.get_mut("missing_licenses")
    {
        if let Some(arr) = licenses.as_array_mut() {
            for item in arr.iter_mut() {
                *item = Value::String(REDACTED.to_owned());
            }
        } else if !licenses.is_null() {
            // Fail closed: non-array, non-null → replace wholesale
            *licenses = Value::String(REDACTED.to_owned());
        }
    }
    value
}

/// Clamp a string to a maximum length, removing control characters.
fn clamp_and_sanitize(s: &str, max_len: usize) -> String {
    let mut result = String::new();
    let mut len = 0;
    for c in s.chars() {
        // Skip control characters (keep printable space + newline + tab)
        if c.is_control() && c != '\n' && c != '\t' {
            continue;
        }
        if len >= max_len {
            break;
        }
        len += c.len_utf8();
        result.push(c);
    }
    result
}

/// Apply oob_drift computation to a device value.
///
/// Computes an advisory oob_drift block based on the device_config_state field:
/// - absent -> state: "none"
/// - "OUT_OF_BAND_CHANGED" -> state: "out_of_band_changed"
/// - anything else non-empty -> state: "unknown" (with raw value preserved)
///
/// The block contains only advisory text; no device configuration.
#[must_use]
pub fn apply_oob_drift(mut value: Value) -> Value {
    use serde_json::Map;

    if let Some(obj) = value.as_object_mut() {
        // Get the raw device_config_state
        let raw_state = obj.get("device_config_state").and_then(|v| v.as_str());

        // Clamp and sanitize the raw state
        let safe_raw = raw_state.map(|s| clamp_and_sanitize(s, 256));

        // Determine the state enum-like value
        let state = match raw_state {
            None => "none",
            Some("OUT_OF_BAND_CHANGED") => "out_of_band_changed",
            Some(_) => "unknown",
        };

        // Build the oob_drift block
        let mut oob_drift = Map::new();

        oob_drift.insert("state".to_string(), Value::String(state.to_string()));
        oob_drift.insert(
            "raw_device_config_state".to_string(),
            safe_raw.map_or(Value::Null, Value::String),
        );
        oob_drift.insert("resolution_available_here".to_string(), Value::Bool(false));

        // resolution_paths - always the portal action
        let mut portal_path = Map::new();
        portal_path.insert("action".to_string(), Value::String("portal".to_string()));
        portal_path.insert(
            "where".to_string(),
            Value::String("SDC portal → Devices → Resolve out-of-band changes".to_string()),
        );
        portal_path.insert(
            "accept_means".to_string(),
            Value::String(
                "SDC imports the device's change; the device is not modified".to_string(),
            ),
        );
        portal_path.insert(
            "reject_means".to_string(),
            Value::String(
                "the change is DELETED from the device; SDC never held a copy".to_string(),
            ),
        );
        let resolution_paths = vec![Value::Object(portal_path)];
        oob_drift.insert(
            "resolution_paths".to_string(),
            Value::Array(resolution_paths),
        );

        // not_a_remedy - list actions that don't resolve this
        let not_a_remedy = vec![Value::String(
            "apply_sdc_device_inventory_sync — inventory only, leaves this state untouched"
                .to_string(),
        )];
        oob_drift.insert("not_a_remedy".to_string(), Value::Array(not_a_remedy));

        obj.insert("oob_drift".to_string(), Value::Object(oob_drift));
    }
    value
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #[test]
    fn paging_tokens_survive_redaction() {
        // Percy B1 (MEC-440): the compound `*token` match redacted #172's
        // ListPage.continuation_token, breaking paging past page 1. The
        // shared mecmcp-redact crate has the identical `token` substring on
        // its denylist, so the key exemption must still hold.
        let items: Vec<Value> = (0..2)
            .map(|i| serde_json::json!({ "id": i, "blob": "x".repeat(40 * 1024) }))
            .collect();
        let page = crate::paging::page_list(
            &serde_json::json!({ "versions": items }),
            "versions",
            None,
            None,
            64 * 1024,
        )
        .expect("page");
        let token = page.continuation_token.clone().expect("a next page");
        let redacted = redact_secrets(serde_json::to_value(&page).expect("serialize"));
        assert_eq!(redacted["continuation_token"], Value::String(token));

        let upstream = redact_secrets(serde_json::json!({
            "nextPageToken": "abc", "accessToken": "QQsecret"
        }));
        assert_eq!(upstream["nextPageToken"], "abc");
        assert_eq!(upstream["accessToken"], REDACTED);
    }

    use super::*;
    use serde_json::json;

    #[test]
    fn icap_server_passwords_are_redacted_in_a_list_envelope() {
        let listed = json!({"items": [{
            "uuid": "u1", "name": "icap", "host": "10.0.0.1",
            "password_ascii": "hunter2", "password_base64": "aHVudGVyMg=="
        }], "count": 1});
        let out = redact_secrets(listed);
        assert_eq!(out["items"][0]["password_ascii"], REDACTED);
        assert_eq!(out["items"][0]["password_base64"], REDACTED);
        assert_eq!(out["items"][0]["host"], "10.0.0.1");
        assert_eq!(out["count"], 1);
    }

    #[test]
    fn nested_site_psk_and_config_body_are_redacted() {
        let site = json!({"site": {"site_name": "s1", "cpe_devices": [{
            "name": "cpe",
            "cpe_config": {"body": "...pre-shared-key...", "format": "set"},
            "mist_config": {"pre_shared_key": "k"},
            "cpe_interfaces": [{
                "psk": "shared", "ike_id": "id",
                "site_config": {"body": "set security ike ... pre-shared-key", "format": "set"}
            }]
        }]}});
        let out = redact_secrets(site);
        let device = &out["site"]["cpe_devices"][0];
        assert_eq!(device["cpe_config"], REDACTED);
        assert_eq!(device["mist_config"]["pre_shared_key"], REDACTED);
        let iface = &device["cpe_interfaces"][0];
        assert_eq!(iface["psk"], REDACTED);
        assert_eq!(iface["site_config"], REDACTED);
        assert_eq!(iface["ike_id"], "id");
    }

    #[test]
    fn key_match_is_case_insensitive_and_null_is_left_alone() {
        let out = redact_secrets(json!({"PSK": "x", "password": null}));
        assert_eq!(out["PSK"], REDACTED);
        assert!(out["password"].is_null());
    }

    #[test]
    fn a_value_without_credentials_is_unchanged() {
        let original = json!({"items": [{"name": "a", "keysize": "2048"}]});
        assert_eq!(redact_secrets(original.clone()), original);
    }

    #[test]
    fn camel_case_and_hyphenated_keys_are_redacted() {
        let out = redact_secrets(json!({
            "preSharedKey": "secret1",
            "cpeConfig": {"body": "config"},
            "siteConfig": {"format": "set"},
            "passwordBase64": "c2VjcmV0",
            "keysize": "2048",
            "pskHint": "over-redacted-on-purpose"
        }));
        assert_eq!(out["preSharedKey"], REDACTED);
        assert_eq!(out["cpeConfig"], REDACTED);
        assert_eq!(out["siteConfig"], REDACTED);
        assert_eq!(out["passwordBase64"], REDACTED);
        // Unrelated to any denylisted term: survives.
        assert_eq!(out["keysize"], "2048");
        // Unlike the old hand-rolled denylist (which deliberately excluded
        // `psk` from compound matching), the shared crate's `psk` denylist
        // entry substring-matches `pskHint` too. Over-redaction is the
        // shared crate's documented, accepted direction to be wrong in.
        assert_eq!(out["pskHint"], REDACTED);
    }

    #[test]
    fn secret_key_is_redacted() {
        let out = redact_secrets(json!({"secret": "hunter2", "name": "a"}));
        assert_eq!(out["secret"], REDACTED);
        assert_eq!(out["name"], "a");
    }

    #[test]
    fn token_key_is_redacted() {
        let out = redact_secrets(json!({"token": "abc123", "name": "a"}));
        assert_eq!(out["token"], REDACTED);
        assert_eq!(out["name"], "a");
    }

    #[test]
    fn api_key_is_redacted() {
        let out = redact_secrets(json!({"api_key": "abc123", "apiKey": "def456", "name": "a"}));
        assert_eq!(out["api_key"], REDACTED);
        assert_eq!(out["apiKey"], REDACTED);
        assert_eq!(out["name"], "a");
    }

    #[test]
    fn private_key_is_redacted() {
        // A synthetic, non-PEM-shaped placeholder: a real PEM body here trips
        // the full-history Gitleaks scan on every future squash merge (a new
        // commit SHA needs a new `.gitleaksignore` entry each time).
        let out = redact_secrets(json!({
            "private_key": "synthetic-private-key-material",
            "public_key_algorithm": "rsa"
        }));
        assert_eq!(out["private_key"], REDACTED);
        // Public key metadata is not a secret and must survive.
        assert_eq!(out["public_key_algorithm"], "rsa");
    }

    #[test]
    fn community_string_is_redacted() {
        let out = redact_secrets(json!({"community": "public", "name": "a"}));
        assert_eq!(out["community"], REDACTED);
        assert_eq!(out["name"], "a");
    }

    /// Compound key names, which never equal a shared-crate denylist entry
    /// exactly, are still caught by its prefix/suffix substring match.
    #[test]
    fn compound_credential_key_names_are_redacted() {
        let out = redact_secrets(json!({
            "accessToken": "a",
            "authToken": "b",
            "apiToken": "c",
            "clientSecret": "d",
            "snmpCommunity": "e",
            "communityString": "f",
            "privateKeyPem": "g",
            "current_password": "h",
            "name": "unaffected",
        }));
        for key in [
            "accessToken",
            "authToken",
            "apiToken",
            "clientSecret",
            "snmpCommunity",
            "communityString",
            "privateKeyPem",
            "current_password",
        ] {
            assert_eq!(out[key], REDACTED, "{key} should be redacted");
        }
        assert_eq!(out["name"], "unaffected");
    }

    /// Proves IPS/ECF-shaped output is still redacted after the shared-crate
    /// migration (MEC-345 closed the local gap; MEC-14 H1b swapped the
    /// backend). Before MEC-345, IPS/ECF handlers called plain `finish` and
    /// skipped redaction entirely.
    #[test]
    fn ips_and_ecf_shaped_responses_are_redacted() {
        let ips_rule = json!({
            "uuid": "r1",
            "name": "block-scan",
            "community": "public",
            "action": "drop"
        });
        let out = redact_secrets(ips_rule);
        assert_eq!(out["community"], REDACTED);
        assert_eq!(out["action"], "drop");

        let ecf_rule_set = json!({
            "items": [{"uuid": "s1", "name": "blocklist", "token": "ecf-abc123"}],
            "count": 1
        });
        let out = redact_secrets(ecf_rule_set);
        assert_eq!(out["items"][0]["token"], REDACTED);
        assert_eq!(out["items"][0]["name"], "blocklist");
        assert_eq!(out["count"], 1);
    }

    #[test]
    fn rma_state_missing_licenses_are_redacted() {
        let state = json!({
            "device_id": "dev1",
            "rma_state": "ACTIVE",
            "missing_licenses": ["LIC-KEY-123", "LIC-KEY-456", "LIC-KEY-789"],
            "other_field": "untouched"
        });
        let out = redact_rma_state(state);
        assert_eq!(
            out["missing_licenses"]
                .as_array()
                .expect("missing_licenses should be an array")
                .len(),
            3
        );
        assert_eq!(out["missing_licenses"][0], REDACTED);
        assert_eq!(out["missing_licenses"][1], REDACTED);
        assert_eq!(out["missing_licenses"][2], REDACTED);
        assert_eq!(out["device_id"], "dev1");
        assert_eq!(out["other_field"], "untouched");
    }

    #[test]
    fn rma_state_without_missing_licenses_is_unchanged() {
        let state = json!({"device_id": "dev1", "rma_state": "ACTIVE"});
        let out = redact_rma_state(state.clone());
        assert_eq!(out, state);
    }

    #[test]
    fn rma_state_empty_missing_licenses_stays_empty() {
        let state = json!({"missing_licenses": []});
        let out = redact_rma_state(state);
        assert_eq!(
            out["missing_licenses"]
                .as_array()
                .expect("missing_licenses should be an array")
                .len(),
            0
        );
    }

    #[test]
    fn rma_state_non_array_missing_licenses_is_redacted() {
        // Fail closed: if missing_licenses is a string (API regression), redact it
        let state = json!({"device_id": "dev1", "missing_licenses": "LIC-KEY-MALFORMED"});
        let out = redact_rma_state(state);
        assert_eq!(out["missing_licenses"], REDACTED);
        assert_eq!(out["device_id"], "dev1");
    }

    #[test]
    fn rma_state_null_missing_licenses_stays_null() {
        // null carries no secret, so leave it alone
        let state = json!({"device_id": "dev1", "missing_licenses": null});
        let out = redact_rma_state(state);
        assert!(out["missing_licenses"].is_null());
        assert_eq!(out["device_id"], "dev1");
    }

    /// Percy F1 (MEC-973): the shared denylist's `session` substring caught
    /// firewall-rule logging flags and NAT/SSL/ICAP session settings that are
    /// not credentials. Over-redacting them hides a policy rule's real
    /// logging state from the model reviewing a write.
    #[test]
    fn session_logging_and_related_fields_survive_redaction() {
        let out = redact_secrets(json!({
            "session_initiate_log": true,
            "session_close_log": false,
            "max_session_number": 12,
            "no_of_sessions": 3,
            "disable_session_resumption": false,
            "session_ignored_log": true,
            "sessions_allowed_log": true,
            "sessions_dropped_log": true,
            "sessions_white_listed_log": true,
            "ssl_session_cache": "enabled",
            "close_session_action": "drop",
            "max_sessions": 100,
            "session_id": "still-a-secret"
        }));
        for key in [
            "session_initiate_log",
            "session_close_log",
            "max_session_number",
            "no_of_sessions",
            "disable_session_resumption",
            "session_ignored_log",
            "sessions_allowed_log",
            "sessions_dropped_log",
            "sessions_white_listed_log",
            "ssl_session_cache",
            "close_session_action",
            "max_sessions",
        ] {
            assert_ne!(
                out[key],
                Value::String(REDACTED.to_owned()),
                "{key} should not be redacted"
            );
        }
        // Only the exempted names above survive; an unlisted `session*` field
        // must still be caught by the shared crate's denylist.
        assert_eq!(out["session_id"], REDACTED);
    }

    /// Percy F1 (MEC-973): every SDC OpenAPI property name the shared crate's
    /// denylist matches must be either an intentional secret or on
    /// [`KEY_EXEMPTIONS`], so a spec refresh that adds a new
    /// denylist-colliding field name cannot silently over-redact it again.
    #[test]
    fn spec_property_names_matching_the_denylist_are_accounted_for() {
        const INTENTIONAL_SECRETS: &[&str] = &[
            "current_password",
            "new_password",
            "pass_phrase",
            "passphrase",
            "password",
            "password_ascii",
            "password_base64",
            "pre_shared_key",
            "psk",
            "root_pwd",
            "skip_password_from_config",
        ];

        let spec_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/sdc-api/security-director-cloud-apis-openapi3.json"
        );
        let spec: Value = serde_json::from_str(
            &std::fs::read_to_string(spec_path).expect("SDC OpenAPI spec must be readable"),
        )
        .expect("SDC OpenAPI spec must be valid JSON");

        let mut property_names = std::collections::BTreeSet::new();
        collect_property_names(&spec, &mut property_names);
        assert!(
            property_names.len() > 100,
            "sanity check: the spec walk should find far more than {} properties",
            property_names.len()
        );

        for name in property_names {
            if !mecmcp_redact::denylist::is_denylisted_key(&name) {
                continue;
            }
            let normalized = normalize_key(&name);
            let is_intentional_secret = INTENTIONAL_SECRETS
                .iter()
                .any(|secret| normalize_key(secret) == normalized);
            let is_exempted = KEY_EXEMPTIONS.contains(&normalized.as_str());
            assert!(
                is_intentional_secret || is_exempted,
                "spec property {name:?} is newly caught by the shared denylist; \
                 add it to INTENTIONAL_SECRETS in this test if it is a real \
                 secret, or to KEY_EXEMPTIONS in redact.rs if it is not"
            );
        }
    }

    /// Percy's MEC-1244 design review (F4): a vendor profile's own test
    /// suite must assert its exemption list doesn't carve out a whole
    /// denylist term.
    #[test]
    fn profile_exemptions_do_not_carve_out_a_denylist_term() {
        PROFILE
            .check_exemptions()
            .expect("no exemption should exactly match a denylist term");
    }

    /// Collect every key of every JSON object nested under a `"properties"`
    /// object, anywhere in `value`.
    fn collect_property_names(value: &Value, names: &mut std::collections::BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                if let Some(Value::Object(properties)) = map.get("properties") {
                    names.extend(properties.keys().cloned());
                }
                for child in map.values() {
                    collect_property_names(child, names);
                }
            }
            Value::Array(items) => {
                for item in items {
                    collect_property_names(item, names);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn apply_oob_drift_adds_block_to_device_with_no_state() {
        let device = serde_json::json!({
            "uuid": "12345678-1234-1234-1234-123456789abc"
        });

        let result = apply_oob_drift(device);

        assert!(result.get("oob_drift").is_some());
        let drift = result
            .get("oob_drift")
            .expect("oob_drift field should be present");
        assert_eq!(
            drift
                .get("state")
                .expect("state field should be present")
                .as_str()
                .expect("state should be a string"),
            "none"
        );
        assert!(drift.get("raw_device_config_state").unwrap().is_null());
    }

    #[test]
    fn apply_oob_drift_adds_block_to_device_with_out_of_band_state() {
        let device = serde_json::json!({
            "uuid": "12345678-1234-1234-1234-123456789abc",
            "device_config_state": "OUT_OF_BAND_CHANGED"
        });

        let result = apply_oob_drift(device);

        let drift = result
            .get("oob_drift")
            .expect("oob_drift field should be present");
        assert_eq!(
            drift
                .get("state")
                .expect("state field should be present")
                .as_str()
                .expect("state should be a string"),
            "out_of_band_changed"
        );
        assert_eq!(
            drift
                .get("raw_device_config_state")
                .unwrap()
                .as_str()
                .unwrap(),
            "OUT_OF_BAND_CHANGED"
        );
    }

    #[test]
    fn apply_oob_drift_adds_block_to_device_with_other_state() {
        let device = serde_json::json!({
            "uuid": "12345678-1234-1234-1234-123456789abc",
            "device_config_state": "some_other_value"
        });

        let result = apply_oob_drift(device);

        let drift = result
            .get("oob_drift")
            .expect("oob_drift field should be present");
        assert_eq!(
            drift
                .get("state")
                .expect("state field should be present")
                .as_str()
                .expect("state should be a string"),
            "unknown"
        );
        assert_eq!(
            drift
                .get("raw_device_config_state")
                .unwrap()
                .as_str()
                .unwrap(),
            "some_other_value"
        );
    }

    #[test]
    fn apply_oob_drift_preserves_other_fields() {
        let device = serde_json::json!({
            "uuid": "12345678-1234-1234-1234-123456789abc",
            "name": "test-device",
            "device_config_state": "OUT_OF_BAND_CHANGED",
            "status": "connected"
        });

        let result = apply_oob_drift(device);

        assert_eq!(
            result
                .get("name")
                .expect("name field should be present")
                .as_str()
                .expect("should be string"),
            "test-device"
        );
        assert_eq!(
            result
                .get("status")
                .expect("status field should be present")
                .as_str()
                .expect("should be string"),
            "connected"
        );
    }
}
