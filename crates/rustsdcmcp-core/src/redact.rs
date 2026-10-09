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
//! A third thing is handled outside the generic scan entirely, not through
//! the `Profile`: `config_diff` (the rendered firewall-policy preview/deploy
//! body) is pulled out of the tree, redacted by [`redact_config_diff`], and
//! spliced back in — see that function's doc comment for why the generic
//! scan must never see its raw *or* its redacted form.
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
///
/// `config_diff` fields are pulled out before the generic scan runs and
/// spliced back in afterward, redacted by `redact_config_diff` instead —
/// see that function's doc comment for why.
#[must_use]
pub fn redact_secrets(mut value: Value) -> Value {
    let diffs = take_config_diffs(&mut value);
    mecmcp_redact::redact_json_value_with_profile(&mut value, &PROFILE);
    restore_config_diffs(&mut value, diffs);
    value
}

/// Redact one `config_diff` body (the rendered firewall-policy preview or
/// deploy diff `prepare_sdc_policy_deploy`, `get_sdc_preview_device_result`,
/// and `get_sdc_deploy_device_result` return).
///
/// SDC renders this field as a *single line*, in one of two vendor shapes
/// depending on which endpoint produced it: `preview_device_result` always
/// requests `format=XML` (Junos NETCONF-style XML); `deploy_device_result`
/// always requests `format=CLI` (Junos `set`-command text). Both shapes are
/// hostile input to [`mecmcp_redact`]'s generic, line-oriented `redact_text`
/// pass: that pass treats a denylisted-key substring match (`session` is on
/// the shared denylist for real `session_id`/`session_token` fields, MEC-537)
/// as licence to redact to the end of the *line* — and because this
/// particular line is the entire document, a `<session-init/>` element deep
/// in a Junos XML diff, or a bare `then log session-init;` statement, wipes
/// everything after it, including an `operation="delete"` entry later in the
/// same diff (mecmcp/rustsdcmcp#238) — exactly what the preview exists to
/// show.
///
/// This instead dispatches on `config_diff`'s own shape to the matching
/// structure- or vocabulary-aware redactor, each of which already
/// distinguishes a real secret (`<pre-shared-key>`, `encrypted-password`,
/// an SNMP community string, a crypt hash, ...) from Junos syntax that
/// merely contains the word "session":
/// - XML-shaped: [`mecmcp_redact::redact_xml_str`], which redacts only the
///   text/attributes under a denylisted *element*, not an entire sibling
///   subtree. Fails closed to [`REDACTED`] wholesale if the body does not
///   parse — this crate never guesses at malformed XML.
/// - Otherwise (Junos CLI `set`-command text): [`redact_cli_text`], which
///   runs [`mecmcp_redact::junos::redact_log_text`] — a closed,
///   Junos-specific keyword vocabulary that already excludes
///   `session`/`limit-session`/`session-init` (it has no `session` entry at
///   all) — under the generic floor for every line that is not itself a
///   `session` statement, so a secret shape outside that closed vocabulary
///   (a PEM block, an upper-case `PRE-SHARED-KEY`, `key: value`, a URL
///   credential, ...) does not pass through either (mecmcp/rustsdcmcp#241
///   review F1). See that function's doc comment for why the floor cannot
///   simply run over every line unconditionally.
///
/// The shape check happens *before* either redactor runs, never by trying
/// one and falling back on a parse error: picking the path by parse outcome
/// is a parser differential (two diffs of the same kind could take
/// different redaction paths over incidental byte content), the same
/// reasoning `mecmcp_redact::junos`'s own shape-based dispatch uses.
fn redact_config_diff(raw: &str) -> String {
    if looks_like_xml_shaped(raw) {
        mecmcp_redact::redact_xml_str(raw).unwrap_or_else(|_| REDACTED.to_owned())
    } else {
        redact_cli_text(raw)
    }
}

/// Redact a Junos CLI `set`-command `config_diff` body.
///
/// [`mecmcp_redact::junos::redact_log_text`] alone (what this called before)
/// is the closed Junos keyword vocabulary: it never over-redacts a
/// `session`-bearing statement, but it also only knows the secret shapes
/// Junos itself names (`pre-shared-key`, `*-password`, a crypt hash, ...). A
/// secret shape outside that vocabulary — a bare PEM block, an upper-case
/// `PRE-SHARED-KEY` statement (the vocabulary match is case-sensitive), a
/// `key: value` or URL-userinfo credential, a `passphrase`/`api-token`
/// statement — passed straight through
/// (mecmcp/rustsdcmcp#241 review F1). [`mecmcp_redact::redact_text`] is the
/// generic floor every other tool-output scan runs under, and it does catch
/// all of those, but it is also the pass whose denylisted-key substring
/// match on `session` caused the over-redaction this crate's `config_diff`
/// handling exists to avoid (see [`redact_config_diff`]'s doc comment and
/// mecmcp/rustsdcmcp#238).
///
/// This runs the generic floor under the Junos pass, like
/// [`mecmcp_redact::junos::redact_log_artefact`] does, but only over the
/// contiguous runs of lines that do not themselves contain `session`
/// (ASCII case-insensitive, matching every statement the vocabulary already
/// protects: `session-init`, `session-close`, `limit-session`, ...) — a
/// `session`-bearing line skips the floor entirely and goes through the
/// vocabulary pass alone, so it can never be over-redacted.
///
/// Splitting into runs (rather than every line standalone) keeps the
/// floor's own cross-line state — an open PEM block, a YAML block scalar —
/// intact for any run that does not itself contain a `session` line; one
/// that opens across a `session` line boundary is not reconstructed, the
/// same accepted cost as a non-vocabulary secret sharing a line with a
/// `session` word (mecmcp/rustsdcmcp#241 review F1's documented residual
/// risk).
fn redact_cli_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut run = String::new();
    for line in raw.split_inclusive('\n') {
        if is_session_line(line) {
            if !run.is_empty() {
                out.push_str(&floor_then_junos(&run));
                run.clear();
            }
            out.push_str(&mecmcp_redact::junos::redact_log_text(line));
        } else {
            run.push_str(line);
        }
    }
    if !run.is_empty() {
        out.push_str(&floor_then_junos(&run));
    }
    out
}

/// The generic denylist/shape floor, then the Junos vocabulary pass on top —
/// see [`redact_cli_text`] for why both run over a `session`-free run.
fn floor_then_junos(run: &str) -> String {
    mecmcp_redact::junos::redact_log_text(&mecmcp_redact::redact_text(run))
}

/// Whether `line` contains the substring `session`, ASCII case-insensitive —
/// the same substring [`mecmcp_redact`]'s shared denylist matches on real
/// `session_id`/`session_token` fields, and the reason a Junos
/// `session-init`/`limit-session` statement must skip the generic floor
/// (see [`redact_cli_text`]).
fn is_session_line(line: &str) -> bool {
    line.to_ascii_lowercase().contains("session")
}

/// Whether `input` is shaped like XML: trimmed of leading whitespace, it
/// starts with `<` followed by an XML name-start character, a `?`
/// (`<?xml ...?>`), or a `!` (`<!--`/`<!DOCTYPE`). A shape test only, not a
/// parse — see [`redact_config_diff`] for why the dispatch must not be
/// parse-outcome-based.
fn looks_like_xml_shaped(input: &str) -> bool {
    let mut chars = input.trim_start().chars();
    chars.next() == Some('<')
        && matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || matches!(c, '_' | ':' | '?' | '!'))
}

/// Remove every `config_diff` string field from `value`, at any depth
/// (`device_results[*].config_diff` for the batch preview shape,
/// `config_diff` at the top level for the single-device shape), returning
/// each one's raw content keyed by the JSON Pointer to its *parent* object.
///
/// Removing rather than leaving the raw text in place is what keeps the
/// generic denylist-and-shape scan in [`redact_secrets`] from ever seeing
/// it: that scan's line-oriented `redact_text` pass is exactly the one
/// [`redact_config_diff`] exists to route around, and it would otherwise
/// corrupt the body before this function's own, more precise pass ever ran.
fn take_config_diffs(value: &mut Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    take_config_diffs_inner(value, &mut String::new(), &mut out);
    out
}

fn take_config_diffs_inner(
    value: &mut Value,
    pointer: &mut String,
    out: &mut Vec<(String, String)>,
) {
    match value {
        Value::Object(map) => {
            if matches!(map.get("config_diff"), Some(Value::String(_)))
                && let Some(Value::String(raw)) = map.remove("config_diff")
            {
                out.push((pointer.clone(), raw));
            }
            for (key, child) in map.iter_mut() {
                let mark = pointer.len();
                pointer.push('/');
                pointer.push_str(&key.replace('~', "~0").replace('/', "~1"));
                take_config_diffs_inner(child, pointer, out);
                pointer.truncate(mark);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                let mark = pointer.len();
                pointer.push('/');
                pointer.push_str(&index.to_string());
                take_config_diffs_inner(item, pointer, out);
                pointer.truncate(mark);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Redact each `(parent pointer, raw config_diff)` pair [`take_config_diffs`]
/// removed, via [`redact_config_diff`], and reinsert it into `value` at its
/// original location. A pointer that no longer resolves to an object (should
/// never happen — nothing between removal and this call can reshape `value`)
/// is skipped rather than panicking: losing one diff is safer than a panic
/// on tool-output redaction, which every read tool depends on.
fn restore_config_diffs(value: &mut Value, diffs: Vec<(String, String)>) {
    for (pointer, raw) in diffs {
        if let Some(Value::Object(map)) = value.pointer_mut(&pointer) {
            map.insert(
                "config_diff".to_owned(),
                Value::String(redact_config_diff(&raw)),
            );
        }
    }
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

/// Clamp a string to a maximum length (in bytes), keeping only ASCII
/// printable graphic characters and spaces.
///
/// This is an allowlist, not a control-character blacklist: the upstream
/// value is an enum-like token, so dropping everything outside
/// `is_ascii_graphic() || ' '` also removes bidi/format characters (for
/// example U+202E RIGHT-TO-LEFT OVERRIDE, Unicode category Cf, which
/// `char::is_control` does not flag) and ANSI escape sequences, not just
/// C0/C1 control bytes.
fn clamp_and_sanitize(s: &str, max_len: usize) -> String {
    let mut result = String::new();
    let mut len = 0;
    for c in s.chars() {
        if !(c.is_ascii_graphic() || c == ' ') {
            continue;
        }
        if len + c.len_utf8() > max_len {
            break;
        }
        len += c.len_utf8();
        result.push(c);
    }
    result
}

/// Raw `device_config_state` tokens the vendored SDC spec documents as
/// in-sync. `Device.device_config_state` is an unconstrained string and
/// names no in-sync token, so this list is empty and [`apply_oob_drift`]
/// does not emit `state: "none"`. Add a token here only after the spec
/// documents it.
const DOCUMENTED_IN_SYNC_DEVICE_CONFIG_STATE: &[&str] = &[];

/// Static limit carried on every `oob_drift` block. No device data.
const OOB_DRIFT_ADVISORY: &str = "state \"none\" is reserved for a documented in-sync device_config_state value. The vendored spec names no such token. \"not_reported\" means the field was absent. An absent field does not prove the device matches SDC, and neither does device_sync_status IN_SYNC. Compare the device's committed configuration with SDC's policy.";

fn is_documented_in_sync_device_config_state(raw: &str) -> bool {
    DOCUMENTED_IN_SYNC_DEVICE_CONFIG_STATE.contains(&raw)
}

/// Apply oob_drift computation to a device value.
///
/// Computes an advisory oob_drift block based on the device_config_state field:
/// - absent -> state: "not_reported"
/// - a documented in-sync token -> state: "none" (raw value preserved).
///   No such token is documented yet, so this state is not emitted.
/// - `"OUT_OF_BAND_CHANGED"` -> state: "out_of_band_changed" (raw value preserved)
/// - any other string -> state: "unknown" (raw value preserved)
/// - present but not a string -> state: "unknown" (no raw value to report)
///
/// `"none"` is never the default. The block contains only advisory text; no
/// device configuration.
#[must_use]
pub fn apply_oob_drift(mut value: Value) -> Value {
    use serde_json::Map;

    if let Some(obj) = value.as_object_mut() {
        // Matched against the field's `Value`, not a `&str` projection, so a
        // present-but-non-string field stays distinct from an absent field.
        let (state, safe_raw) = match obj.get("device_config_state") {
            None => ("not_reported", None),
            Some(Value::String(s)) if s == "OUT_OF_BAND_CHANGED" => {
                ("out_of_band_changed", Some(clamp_and_sanitize(s, 256)))
            }
            Some(Value::String(s)) if is_documented_in_sync_device_config_state(s) => {
                ("none", Some(clamp_and_sanitize(s, 256)))
            }
            Some(Value::String(s)) => ("unknown", Some(clamp_and_sanitize(s, 256))),
            Some(_) => ("unknown", None),
        };

        // Build the oob_drift block
        let mut oob_drift = Map::new();

        oob_drift.insert("state".to_string(), Value::String(state.to_string()));
        oob_drift.insert(
            "raw_device_config_state".to_string(),
            safe_raw.map_or(Value::Null, Value::String),
        );
        oob_drift.insert("resolution_available_here".to_string(), Value::Bool(false));
        oob_drift.insert(
            "advisory".to_string(),
            Value::String(OOB_DRIFT_ADVISORY.to_string()),
        );

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

    /// mecmcp/rustsdcmcp#238: a one-line XML `config_diff` with a
    /// `<session-init/>` element must not lose everything after it,
    /// including a later `operation="delete"` entry — the preview exists to
    /// show deletes. The exact shape from the issue report, condensed: a
    /// `create` policy whose `then log` clause uses `session-init`, followed
    /// by a `delete` policy.
    #[test]
    fn config_diff_xml_session_init_does_not_swallow_a_later_delete() {
        let config_diff = concat!(
            "<policy operation=\"create\"><name>BLOCK-SHOPPING-KALI</name>",
            "<then><log><session-init/><session-close/></log><deny/></then></policy>",
            "<policy operation=\"delete\"><name>OLD-RULE</name></policy>",
        );
        let out = redact_secrets(json!({ "config_diff": config_diff }));
        let redacted = out["config_diff"]
            .as_str()
            .expect("config_diff is a string");
        assert!(
            redacted.contains(r#"operation="delete""#),
            "the delete entry after session-init must survive: {redacted}"
        );
        assert!(
            redacted.contains("OLD-RULE"),
            "the deleted rule's name must survive: {redacted}"
        );
        assert!(
            redacted.contains("session-init") && redacted.contains("session-close"),
            "session-init/session-close are not secrets and must survive: {redacted}"
        );
    }

    /// The same XML `config_diff` shape, but with a real secret
    /// (`pre-shared-key`) alongside the non-secret `session-init` element:
    /// the secret must still be redacted structurally.
    #[test]
    fn config_diff_xml_still_redacts_a_real_secret_alongside_session_init() {
        let config_diff = concat!(
            "<policy operation=\"create\"><name>P1</name>",
            "<then><log><session-init/></log></then></policy>",
            "<ike><pre-shared-key><ascii-text>QQsupersecret1</ascii-text></pre-shared-key></ike>",
        );
        let out = redact_secrets(json!({ "config_diff": config_diff }));
        let redacted = out["config_diff"]
            .as_str()
            .expect("config_diff is a string");
        assert!(
            !redacted.contains("QQsupersecret1"),
            "the real secret must be redacted: {redacted}"
        );
        assert!(
            redacted.contains("session-init"),
            "session-init must survive: {redacted}"
        );
    }

    /// Malformed XML fails closed: the whole `config_diff` body is withheld
    /// rather than guessed at or passed through unredacted.
    #[test]
    fn config_diff_malformed_xml_fails_closed_to_wholesale_redaction() {
        let out = redact_secrets(json!({ "config_diff": "<policy><unclosed>" }));
        assert_eq!(out["config_diff"], REDACTED);
    }

    /// `config_diff` nested under `device_results[*]` — the shape
    /// `prepare_sdc_policy_deploy`'s batch preview returns — must be found
    /// and redacted the same way as the top-level, single-device shape.
    #[test]
    fn config_diff_nested_under_device_results_array_is_redacted() {
        let config_diff = concat!(
            "<policy operation=\"create\"><then><log><session-init/></log></then></policy>",
            "<policy operation=\"delete\"><name>OLD</name></policy>",
        );
        let out = redact_secrets(json!({
            "device_results": [
                { "device_id": "d1", "config_diff": config_diff },
                { "device_id": "d2", "config_diff": "<policy/>" },
            ]
        }));
        let first = out["device_results"][0]["config_diff"]
            .as_str()
            .expect("config_diff is a string");
        assert!(first.contains(r#"operation="delete""#), "got: {first}");
        assert!(first.contains("session-init"), "got: {first}");
        assert_eq!(out["device_results"][0]["device_id"], "d1");
        assert_eq!(out["device_results"][1]["config_diff"], "<policy/>");
    }

    /// mecmcp/rustjunosmcp#522's CLI-text counterpart: `deploy_device_result`
    /// always requests `format=CLI`, so its `config_diff` is Junos
    /// `set`-command text, not XML. `then log session-init;`/
    /// `limit-session X` must survive; a real secret statement must not.
    #[test]
    fn config_diff_cli_text_session_words_survive_but_a_real_secret_is_redacted() {
        let config_diff = "set security policies ... then log session-init session-close\n\
             set security screen ids-option X limit-session destination-ip-based 1000\n\
             set system root-authentication encrypted-password \"$9$QQfakehash\"";
        let out = redact_secrets(json!({ "config_diff": config_diff }));
        let redacted = out["config_diff"]
            .as_str()
            .expect("config_diff is a string");
        assert!(redacted.contains("session-init"), "got: {redacted}");
        assert!(redacted.contains("session-close"), "got: {redacted}");
        assert!(redacted.contains("limit-session"), "got: {redacted}");
        assert!(
            !redacted.contains("QQfakehash"),
            "the real secret must still be redacted: {redacted}"
        );
    }

    /// mecmcp/rustsdcmcp#241 review F1: the generic floor's PEM-block
    /// handling must still run on a CLI-text `config_diff`, not just the
    /// closed Junos vocabulary — a PEM body is not a shape
    /// `redact_log_text` alone knows about.
    #[test]
    fn config_diff_cli_text_pem_block_is_redacted() {
        // gitleaks:allow -- fabricated base64 body ("AAAA"), not a real key
        let config_diff = "set security ike policy IKE-1 proposal-set basic\n\
             -----BEGIN RSA PRIVATE KEY-----\n\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
             -----END RSA PRIVATE KEY-----\n\
             set security ike policy IKE-1 mode main";
        let out = redact_secrets(json!({ "config_diff": config_diff }));
        let redacted = out["config_diff"]
            .as_str()
            .expect("config_diff is a string");
        assert!(
            !redacted.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            "the PEM key body must be redacted: {redacted}"
        );
        assert!(
            redacted.contains("-----BEGIN RSA PRIVATE KEY-----"),
            "the PEM header is not secret and must survive: {redacted}"
        );
    }

    /// mecmcp/rustsdcmcp#241 review F1: a Junos secret statement outside the
    /// closed `redact_log_text` vocabulary (`passphrase`, `api-token`,
    /// upper-case `PRE-SHARED-KEY`) must still be caught by the generic
    /// floor.
    #[test]
    fn config_diff_cli_text_non_vocabulary_secret_keywords_are_redacted() {
        let config_diff = "set services ssl initiation-profile p1 passphrase PASSZZ1\n\
             set system services rest api-token TOKZZ1\n\
             SET SECURITY IKE PROPOSAL P1 PRE-SHARED-KEY ASCII-TEXT PSKZZ3";
        let out = redact_secrets(json!({ "config_diff": config_diff }));
        let redacted = out["config_diff"]
            .as_str()
            .expect("config_diff is a string");
        assert!(!redacted.contains("PASSZZ1"), "got: {redacted}");
        assert!(!redacted.contains("TOKZZ1"), "got: {redacted}");
        assert!(!redacted.contains("PSKZZ3"), "got: {redacted}");
    }

    /// mecmcp/rustsdcmcp#241 review F1: a URL-embedded credential and a
    /// `password:`/JSON-style key-value pair are shapes the closed Junos
    /// vocabulary does not look for at all, but the generic floor does.
    #[test]
    fn config_diff_cli_text_url_and_keyvalue_credentials_are_redacted() {
        let config_diff = "set system syslog host x structured-data\n\
             # upstream source url https://user:URLPWZZ1@host/x\n\
             password: PWZZ1";
        let out = redact_secrets(json!({ "config_diff": config_diff }));
        let redacted = out["config_diff"]
            .as_str()
            .expect("config_diff is a string");
        assert!(!redacted.contains("URLPWZZ1"), "got: {redacted}");
        assert!(!redacted.contains("PWZZ1"), "got: {redacted}");
    }

    /// mecmcp/rustsdcmcp#241 review F1: a `config_diff` that is not
    /// XML-shaped by [`looks_like_xml_shaped`] (it does not start with `<`)
    /// but still carries an embedded XML secret element later on must not
    /// have that element pass through just because it took the CLI path.
    #[test]
    fn config_diff_non_xml_shaped_body_with_embedded_secret_element_is_redacted() {
        let config_diff = "Warning: preview truncated\n\
             <a><pre-shared-key><ascii-text>PSKZZW</ascii-text></pre-shared-key></a>";
        let out = redact_secrets(json!({ "config_diff": config_diff }));
        let redacted = out["config_diff"]
            .as_str()
            .expect("config_diff is a string");
        assert!(!redacted.contains("PSKZZW"), "got: {redacted}");
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
            "not_reported"
        );
        assert!(drift.get("raw_device_config_state").unwrap().is_null());
        assert_eq!(
            drift.get("advisory").and_then(Value::as_str),
            Some(OOB_DRIFT_ADVISORY)
        );
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

    /// A present-but-non-string `device_config_state` is `"unknown"`, never
    /// `"none"`. `"none"` is reserved for a documented in-sync token.
    #[test]
    fn apply_oob_drift_non_string_state_is_unknown_not_none() {
        for raw in [json!(null), json!(7), json!({"x": 1}), json!([1, 2])] {
            let device = json!({"device_config_state": raw.clone()});
            let result = apply_oob_drift(device);
            let drift = result.get("oob_drift").expect("oob_drift present");
            assert_eq!(
                drift.get("state").unwrap().as_str().unwrap(),
                "unknown",
                "raw value {raw:?} must not collapse to \"none\""
            );
            assert!(drift.get("raw_device_config_state").unwrap().is_null());
        }
    }

    /// Absent field, documented in-sync token, exact drift token, and
    /// unrecognized value. Only the documented in-sync allowlist may read
    /// `"none"`.
    #[test]
    fn apply_oob_drift_state_matrix() {
        let absent = apply_oob_drift(json!({"uuid": "x"}));
        assert_eq!(absent["oob_drift"]["state"], "not_reported");
        assert!(absent["oob_drift"]["raw_device_config_state"].is_null());

        for raw in DOCUMENTED_IN_SYNC_DEVICE_CONFIG_STATE {
            let drift = apply_oob_drift(json!({"device_config_state": raw}));
            assert_eq!(drift["oob_drift"]["state"], "none", "raw {raw}");
            assert_eq!(drift["oob_drift"]["raw_device_config_state"], *raw);
        }

        let drifted = apply_oob_drift(json!({"device_config_state": "OUT_OF_BAND_CHANGED"}));
        assert_eq!(drifted["oob_drift"]["state"], "out_of_band_changed");

        // Lookalikes and garbage are not the reserved in-sync result. The
        // sibling status token `IN_SYNC` is not a documented value of this
        // field, and the spec names no in-sync token at all.
        for raw in [
            "IN_SYNC",
            "NONE",
            "none",
            "NO_CHANGE",
            "SYNCHRONIZED",
            "",
            "some_other_value",
        ] {
            assert!(
                !is_documented_in_sync_device_config_state(raw),
                "{raw} must not be treated as documented in-sync"
            );
            let drift = apply_oob_drift(json!({"device_config_state": raw}));
            assert_ne!(
                drift["oob_drift"]["state"], "none",
                "raw {raw:?} must not read as none"
            );
            assert_eq!(drift["oob_drift"]["state"], "unknown", "raw {raw:?}");
        }
    }

    /// Spoofing check: a pre-existing upstream `oob_drift` key must be
    /// overwritten with the computed block, never trusted as-is.
    #[test]
    fn apply_oob_drift_overwrites_a_preexisting_upstream_block() {
        let device = json!({
            "device_config_state": "OUT_OF_BAND_CHANGED",
            "oob_drift": {"state": "none"}
        });
        let result = apply_oob_drift(device);
        let drift = result.get("oob_drift").expect("oob_drift present");
        assert_eq!(
            drift.get("state").unwrap().as_str().unwrap(),
            "out_of_band_changed"
        );
    }

    /// F2 (MEC-1995 review of #216): bidi/format characters must not survive
    /// the sanitizer. U+202E is Unicode category Cf (format), which
    /// `char::is_control` does not flag, so the old control-char blacklist
    /// let it through.
    #[test]
    fn clamp_and_sanitize_strips_bidi_override_characters() {
        let out = clamp_and_sanitize("A\u{202E}B", 256);
        assert_eq!(out, "AB");
    }

    /// F2: newlines and tabs were explicitly kept by the old blacklist;
    /// the allowlist drops them too, since the field is a single enum-like
    /// token, not a text block.
    #[test]
    fn clamp_and_sanitize_strips_newlines_and_tabs() {
        let out = clamp_and_sanitize("A\nB\tC", 256);
        assert_eq!(out, "ABC");
    }

    /// F2: an ANSI escape sequence is only partially removed by a
    /// control-char blacklist (the ESC byte is a control character, but the
    /// `[31m` that follows it is plain printable text).
    #[test]
    fn clamp_and_sanitize_strips_the_esc_control_byte() {
        let out = clamp_and_sanitize("A\u{1b}[31mB", 256);
        // The allowlist drops the ESC control byte. `[31m` is plain ASCII
        // graphic text, so it is not an escape sequence once ESC is gone —
        // the allowlist does not parse ANSI sequences as a unit.
        assert_eq!(out, "A[31mB");
    }

    /// F2: the length check used to run *before* the push, so a multi-byte
    /// character straddling the cap could leave the result up to
    /// `max_len + char_len - 1` bytes long. Confirm the cap is now a hard
    /// byte-length ceiling.
    #[test]
    fn clamp_and_sanitize_enforces_a_hard_byte_length_cap() {
        let input = "x".repeat(300);
        let out = clamp_and_sanitize(&input, 256);
        assert_eq!(out.len(), 256);
    }

    #[test]
    fn clamp_and_sanitize_keeps_plain_ascii_text() {
        let out = clamp_and_sanitize("OUT_OF_BAND_CHANGED", 256);
        assert_eq!(out, "OUT_OF_BAND_CHANGED");
    }
}
