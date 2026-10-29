//! Regression tests for `--validate-package`.
//!
//! This validation replaced a shell-out to `jq` (rustsdcmcp#94). The
//! replacement is only worth having if it rejects everything the `jq` version
//! rejected, and two ways it initially did not are covered here:
//!
//! - a `mecmcp-*` component whose `version` is missing or non-string was
//!   silently dropped by a `filter_map`, so the exact-set comparison still
//!   passed. `jq` kept it as `[name, null]` and rejected it.
//! - a forbidden marker written as a JSON escape (`v0.8.0`) never appears
//!   literally in the raw bytes, so a raw-text search missed it — while
//!   searching *only* the re-serialized tree opens the opposite hole, because
//!   `serde_json` keeps the last value for duplicate object members.
//!
//! The validator therefore searches both surfaces. These tests exist so that
//! "simplifying" it back to one fails loudly.

use std::fs;
use std::path::Path;
use std::process::Command;

/// A package config example that satisfies every `validate_config_file` check,
/// so a failure in these tests is always attributable to the SBOM.
const GOOD_CONFIG: &str = r#"{
  "version": 1,
  "tenant": "example-tenant",
  "credential_env": "RUSTSDCMCP_TOKEN",
  "endpoint": "https://sdc.example.com",
  "changeset_state_file": "/var/lib/rustsdcmcp/changeset-state.json"
}"#;

/// The eight `mecmcp-*` components the validator requires, at the pinned version.
fn mecmcp_components() -> String {
    [
        "mecmcp-audit",
        "mecmcp-auth",
        "mecmcp-changeset",
        "mecmcp-redact",
        "mecmcp-runtime",
        "mecmcp-secret",
        "mecmcp-server",
        "mecmcp-transport",
    ]
    .iter()
    .map(|n| format!(r#"{{"name":"{n}","version":"0.31.0"}}"#))
    .collect::<Vec<_>>()
    .join(",")
}

/// Build an SBOM whose components array is the expected set plus `extra`.
fn sbom_with_extra(extra: &str) -> String {
    let mut components = mecmcp_components();
    components.push_str(r#",{"name":"serde","version":"1.0.0"}"#);
    if !extra.is_empty() {
        components.push(',');
        components.push_str(extra);
    }
    format!(
        r#"{{"bomFormat":"CycloneDX","specVersion":"1.5",
"metadata":{{"component":{{"name":"rustsdcmcp","version":"0.0.5"}}}},
"components":[{components}]}}"#
    )
}

/// Write a package directory and run `--validate-package` against it.
fn validate(sbom: &str) -> std::process::Output {
    let dir = tempfile::tempdir().expect("tempdir");
    let root: &Path = dir.path();
    fs::create_dir_all(root.join("config")).expect("mkdir config");
    fs::write(root.join("config/sdc.json.example"), GOOD_CONFIG).expect("write config");
    fs::write(root.join("SBOM.cdx.json"), sbom).expect("write sbom");

    Command::new(env!("CARGO_BIN_EXE_rustsdcmcp"))
        .arg("--validate-package")
        .arg(root)
        .output()
        .expect("run validator")
}

#[test]
fn accepts_a_well_formed_package() {
    let out = validate(&sbom_with_extra(""));
    assert!(
        out.status.success(),
        "a valid package must pass; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn rejects_mecmcp_component_with_null_version() {
    // The expected set is all present; this entry is an *extra* whose version
    // is null. A `filter_map` that drops it leaves the exact-set comparison
    // satisfied and the package passes.
    let out = validate(&sbom_with_extra(
        r#"{"name":"mecmcp-smuggled","version":null}"#,
    ));
    assert!(
        !out.status.success(),
        "a mecmcp-* component with a null version must be rejected, not filtered out"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("missing or non-string version"),
        "expected a version-shape error, got:\n{stderr}"
    );
}

#[test]
fn rejects_forbidden_marker_hidden_by_json_escaping() {
    // The escape sequence below decodes to "v0.8.0" but that string never
    // appears literally in the bytes, so a raw-bytes search alone misses it.
    // Written in a Rust raw string, so the backslashes reach the JSON verbatim.
    let sbom =
        sbom_with_extra(r#"{"name":"probe","version":"\u0076\u0030\u002e\u0038\u002e\u0030"}"#);
    assert!(
        !sbom.contains("v0.8.0"),
        "fixture bug: the marker must NOT appear literally, or this test proves nothing"
    );
    let out = validate(&sbom);
    assert!(
        !out.status.success(),
        "a JSON-escaped forbidden marker must be caught via the decoded tree"
    );
}

#[test]
fn rejects_forbidden_marker_hidden_by_duplicate_keys() {
    // serde_json keeps the LAST value for duplicate members, so re-serializing
    // discards the forbidden one. Only a raw-bytes search still sees it.
    let out = validate(&sbom_with_extra(
        r#"{"name":"probe","version":"v0.8.0","version":"safe"}"#,
    ));
    assert!(
        !out.status.success(),
        "a forbidden marker shadowed by a duplicate key must be caught via the raw bytes"
    );
}

#[test]
fn rejects_absolute_build_paths() {
    let out = validate(&sbom_with_extra(
        r#"{"name":"probe","version":"1.0.0","description":"/home/builder/src"}"#,
    ));
    assert!(
        !out.status.success(),
        "absolute build paths must not survive into a shipped SBOM"
    );
}

#[test]
fn rejects_marker_escaped_inside_a_discarded_duplicate() {
    // The composition of the previous two techniques, and the one that defeated
    // the two-surface check: the forbidden marker is escaped (so the raw bytes
    // never contain it) AND sits in a member that a later duplicate discards
    // (so the re-serialized tree never contains it either).
    //
    // The fix is not a third search surface — it is refusing the shape. An SBOM
    // with repeated object members is malformed per RFC 8259 and is rejected at
    // parse time.
    let sbom = sbom_with_extra(
        r#"{"name":"probe","version":"\u0076\u0030\u002e\u0038\u002e\u0030","version":"safe"}"#,
    );
    assert!(
        !sbom.contains("v0.8.0"),
        "fixture bug: the marker must not appear literally, or this test proves nothing"
    );
    let out = validate(&sbom);
    assert!(
        !out.status.success(),
        "an escaped marker inside a discarded duplicate member must not validate"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("duplicate object member"),
        "expected rejection at parse time naming the duplicate, got:\n{stderr}"
    );
}
