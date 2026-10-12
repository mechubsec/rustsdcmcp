//! Enforces the coherent released mecmcp dependency pin.

use std::{fs, path::Path};

/// Declared directly in the workspace manifest. Each must appear verbatim.
const PACKAGES: [&str; 7] = [
    "mecmcp-audit",
    "mecmcp-auth",
    "mecmcp-changeset",
    "mecmcp-redact",
    "mecmcp-runtime",
    "mecmcp-server",
    "mecmcp-transport",
];

/// Every `mecmcp-*` crate the lockfile may contain, including ones reached
/// transitively rather than declared here. `mecmcp-secret` is pulled in by
/// `mecmcp-auth`, `-changeset` and `-transport` as the workspace's single
/// hardened file/secret reader; it has no direct declaration, but it must still
/// come from the one approved tag. Checking only the declared six would let a
/// transitive mecmcp crate enter from a different source unnoticed, which is
/// the exact thing this file exists to prevent.
const LOCKED_PACKAGES: [&str; 8] = [
    "mecmcp-audit",
    "mecmcp-auth",
    "mecmcp-changeset",
    "mecmcp-redact",
    "mecmcp-runtime",
    "mecmcp-secret",
    "mecmcp-server",
    "mecmcp-transport",
];
const VERSION: &str = "0.27.0";
const TAG: &str = "v0.27.0";
const COMMIT: &str = "19401120439cd1420701bb59b6495bfdd3718b93";
const REPOSITORY: &str = "https://github.com/mechubsec/mecmcp";

fn validate_mecmcp_lockfile(lock: &str) -> Result<(), String> {
    let source = format!("git+{REPOSITORY}?tag={TAG}#{COMMIT}");
    let mut expected = LOCKED_PACKAGES
        .map(|package| (package.to_owned(), VERSION.to_owned(), source.clone()))
        .to_vec();
    let document = lock
        .parse::<toml::Table>()
        .map_err(|error| format!("lockfile must be valid TOML: {error}"))?;
    let package_tables = document
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| "lockfile must contain package tables".to_owned())?;
    let mut actual = Vec::new();
    for (index, package) in package_tables.iter().enumerate() {
        let table = package
            .as_table()
            .ok_or_else(|| format!("lockfile package {index} must be a table"))?;
        let name = table
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("lockfile package {index} must have a string name"))?;
        if !name.starts_with("mecmcp-") {
            continue;
        }
        let version = table
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("{name} lockfile block lacks a version"))?;
        let package_source = table
            .get("source")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("{name} lockfile block lacks a source"))?;
        actual.push((
            name.to_owned(),
            version.to_owned(),
            package_source.to_owned(),
        ));
    }

    expected.sort();
    actual.sort();
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "lockfile mecmcp package tuples differ from the exact approved set: {actual:?}"
        ))
    }
}

#[test]
fn all_mecmcp_crates_use_one_released_tag_and_commit() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_root.join("../..");
    let manifest =
        fs::read_to_string(workspace_root.join("Cargo.toml")).expect("read workspace manifest");
    let lock =
        fs::read_to_string(workspace_root.join("Cargo.lock")).expect("read workspace lockfile");

    for package in PACKAGES {
        let declaration = format!(
            r#"{package} = {{ version = "{VERSION}", git = "{REPOSITORY}", tag = "{TAG}" }}"#
        );
        assert!(
            manifest.lines().any(|line| line == declaration),
            "{package} must use the exact coherent workspace declaration"
        );
    }

    validate_mecmcp_lockfile(&lock).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn rejects_rogue_mecmcp_package_from_another_source() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut lock =
        fs::read_to_string(crate_root.join("../../Cargo.lock")).expect("read workspace lockfile");
    lock.push_str(
        r#"
[[package]]
name = "mecmcp-rogue"
version = "9.9.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    );

    assert!(
        validate_mecmcp_lockfile(&lock).is_err(),
        "an alternate-source mecmcp package must invalidate the dependency contract"
    );
}

#[test]
fn rejects_noncanonical_toml_rogue_packages() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lock =
        fs::read_to_string(crate_root.join("../../Cargo.lock")).expect("read workspace lockfile");
    let rogue_blocks = [
        (
            "indented keys",
            r#"
[[package]]
    name = "mecmcp-indented"
    version = "0.3.7"
    source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        ),
        (
            "literal strings",
            r#"
[[package]]
name = 'mecmcp-literal'
version = '0.3.7'
source = 'registry+https://github.com/rust-lang/crates.io-index'
"#,
        ),
        (
            "spaced array-table header",
            r#"
[[ package ]]
name = "mecmcp-spaced-header"
version = "0.3.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        ),
    ];

    for (case, rogue_block) in rogue_blocks {
        let candidate = format!("{lock}{rogue_block}");
        candidate
            .parse::<toml::Table>()
            .unwrap_or_else(|error| panic!("{case} fixture must be valid TOML: {error}"));
        assert!(
            validate_mecmcp_lockfile(&candidate).is_err(),
            "{case} must not hide a rogue mecmcp package"
        );
    }
}

#[test]
fn rejects_any_non_exact_mecmcp_package_set() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lock =
        fs::read_to_string(crate_root.join("../../Cargo.lock")).expect("read workspace lockfile");
    let approved_source = format!("git+{REPOSITORY}?tag={TAG}#{COMMIT}");
    let auth_block = lock
        .split("[[package]]")
        .find(|block| block.contains("\nname = \"mecmcp-auth\"\n"))
        .expect("mecmcp-auth package block");

    let mut extra = lock.clone();
    extra.push_str(
        r#"
[[package]]
name = "mecmcp-rogue"
version = "0.3.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    );
    let duplicate = format!("{lock}\n[[package]]{auth_block}");
    let missing = lock.replacen(&format!("[[package]]{auth_block}"), "", 1);
    let wrong_source = lock.replacen(
        &approved_source,
        "git+https://example.invalid/mecmcp?tag=v0.0.0#0000000000000000000000000000000000000000",
        1,
    );
    assert_ne!(
        wrong_source, lock,
        "the different-source mutation must actually change the lockfile"
    );
    // Derived from VERSION rather than written out: hardcoding the version here
    // meant that when the pin moved, `replacen` silently matched nothing, the
    // "different version" case stopped mutating anything, and this test began
    // asserting that an *unmodified* lockfile is invalid. A negative test that
    // quietly stops testing is worse than no negative test.
    let wrong_version = lock.replacen(
        &format!("name = \"mecmcp-auth\"\nversion = \"{VERSION}\""),
        "name = \"mecmcp-auth\"\nversion = \"0.0.0-not-the-pin\"",
        1,
    );
    assert_ne!(
        wrong_version, lock,
        "the different-version mutation must actually change the lockfile"
    );

    for (case, candidate) in [
        ("extra", extra),
        ("duplicate", duplicate),
        ("missing", missing),
        ("different source", wrong_source),
        ("different version", wrong_version),
    ] {
        assert!(
            validate_mecmcp_lockfile(&candidate).is_err(),
            "{case} mecmcp package set must be rejected"
        );
    }
}
