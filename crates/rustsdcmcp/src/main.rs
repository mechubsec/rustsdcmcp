//! Security Director Cloud MCP server executable.

use anyhow::{Context, Result};
use mecmcp_auth::{NoGrant, TokenStoreFile};
use mecmcp_runtime::cli::{Cli, Command, ParsedCli, Transport};
use rmcp::ServiceExt as _;
use rustsdcmcp::{KNOWN_TOOLS, SdcHandler, serve_http};
use rustsdcmcp_core::{ChangeManager, SdcClient, SdcConfig};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

/// Security Director Cloud MCP server.
//
// This is the shared `mecmcp` CLI plus the three standardized change-set
// flags. `mecmcp/docs/PACKAGING.md` standardizes `--lab-mode`, `--state-file`,
// and `--approval-timeout-secs` across every server in the family, and
// specifies that each server declares them on *its own* CLI type rather than in
// the shared `Cli` — `parse_with_provenance` parses this struct, not that one.
// Flattening keeps every shared flag while adding the three here.
//
// Doc comments on this struct become `--help` text, so the rationale stays in
// ordinary comments and only the description above is a doc comment.
#[derive(Debug, clap::Parser)]
struct ServerCli {
    /// Arguments shared by every mecmcp server.
    #[command(flatten)]
    shared: Cli,

    /// Run without two-person control; change sets are approved on creation.
    ///
    /// Off by default. The waiver is recorded, never fabricated: a waived
    /// change set carries `approver: null` alongside
    /// `approval_waiver: "lab-mode"`, and its own digest, so it stays
    /// distinguishable from a genuine two-person approval.
    #[arg(long)]
    lab_mode: bool,

    /// Absolute path to the change-set and operation state file.
    ///
    /// Falls back to `changeset_state_file` in the product configuration.
    #[arg(long)]
    state_file: Option<PathBuf>,

    /// How long an approval stays valid, in seconds. Must be greater than zero.
    ///
    /// Falls back to `approval_ttl_secs` in the product configuration.
    ///
    /// `SdcConfig` refuses a zero TTL, but an explicit flag bypasses that
    /// validation, and zero expires every change set at the instant it is
    /// created — approval fails, and lab mode's waiver reports the window
    /// already closed. Constrained here so the whole write surface cannot be
    /// disabled by one plausible-looking argument.
    #[arg(
        long,
        default_value_t = DEFAULT_APPROVAL_TIMEOUT_SECS,
        value_parser = clap::value_parser!(u64).range(1..),
    )]
    approval_timeout_secs: u64,

    /// Validate package configuration and SBOM, then exit.
    ///
    /// Validates config/sdc.json.example and SBOM.cdx.json in the package
    /// directory. Used by the installer to verify package integrity without
    /// requiring external dependencies like jq.
    #[arg(long)]
    validate_package: Option<PathBuf>,

    /// Expose unauthenticated Prometheus metrics at /metrics (streamable-http only).
    ///
    /// Off by default: `/metrics` carries no MCP bearer auth of its own (see
    /// mecmcp-transport's docs/METRICS.md), so turning it on is an operator
    /// decision, not a default.
    #[arg(long)]
    enable_metrics: bool,

    /// Max requests per second per source IP address. Set together with
    /// `--max-request-burst-per-ip`; `0`/`0` disables per-IP rate limiting.
    ///
    /// Defaults match `mecmcp_transport::LimitsConfig::default()`, spelled out
    /// here rather than read from the dependency so a fresh install gets a
    /// non-zero limit even while this crate's `mecmcp-transport` pin lags the
    /// version that default landed in.
    #[arg(long, default_value_t = 50)]
    max_requests_per_second_per_ip: u64,

    /// Max immediate request burst per source IP address. Set together with
    /// `--max-requests-per-second-per-ip`; `0`/`0` disables per-IP rate limiting.
    #[arg(long, default_value_t = 100)]
    max_request_burst_per_ip: u64,

    /// Max requests per second per bearer token. Set together with
    /// `--max-request-burst-per-token`; `0`/`0` disables per-token rate limiting.
    #[arg(long, default_value_t = 20)]
    max_requests_per_second_per_token: u64,

    /// Max immediate request burst per bearer token. Set together with
    /// `--max-requests-per-second-per-token`; `0`/`0` disables per-token rate limiting.
    #[arg(long, default_value_t = 40)]
    max_request_burst_per_token: u64,
}

/// Parser default for `--approval-timeout-secs`.
///
/// Only reached when neither the flag nor product configuration supplies a
/// value, because `SdcConfig` carries its own serde default.
const DEFAULT_APPROVAL_TIMEOUT_SECS: u64 = 900;

/// Resolve one standard flag against product configuration.
///
/// The rule is `mecmcp/docs/PACKAGING.md`'s: an explicitly supplied CLI value
/// wins, otherwise product configuration, otherwise the built-in default.
///
/// The trap is deciding "explicitly supplied". A defaulted flag is
/// indistinguishable from a typed one by value alone, so comparing against the
/// default gets it wrong in both directions — it ignores a flag the operator
/// did type, and it overrides a configured value with a default nobody chose.
/// `was_supplied` answers from clap's own provenance instead.
fn resolve<T>(supplied_on_cli: bool, from_cli: T, from_config: T) -> T {
    if supplied_on_cli {
        from_cli
    } else {
        from_config
    }
}

/// Resolve the token store, applying the legacy fallback ONLY for the canonical path.
///
/// The migration fallback exists so an upgrade that has not yet moved
/// `/etc/rustsdcmcp/tokens.json` still starts. It must not apply to an operator's own
/// path: if `--tokens-file /srv/custom.json` is missing — a typo, or a deleted
/// store — falling back to the legacy file would silently reactivate unrelated
/// or revoked credentials. A non-canonical path is loaded directly and fails if
/// absent, which is the honest outcome.
fn resolve_tokens(configured: &std::path::Path) -> Result<mecmcp_auth::ResolvedTokenPath> {
    resolve_tokens_with(
        configured,
        std::path::Path::new("/var/lib/rustsdcmcp/tokens.json"),
        std::path::Path::new("/etc/rustsdcmcp/tokens.json"),
    )
}

/// The rule behind [`resolve_tokens`], with the two well-known paths injected so
/// it can be exercised against real files in a test rather than against absolute
/// paths that never exist there.
fn resolve_tokens_with(
    configured: &std::path::Path,
    canonical: &std::path::Path,
    legacy: &std::path::Path,
) -> Result<mecmcp_auth::ResolvedTokenPath> {
    // Byte-exact, not `Path` equality. `Path` comparison normalizes away trailing
    // separators and `.` components, so `/var/lib/rustsdcmcp/tokens.json/` compares
    // EQUAL to the canonical path — while `metadata()` on that spelling returns
    // NotFound when the file is absent, indistinguishable from the plain form.
    // A typo would therefore pass this gate and activate the legacy store, which
    // is exactly the fail-closed behaviour this check exists to provide.
    if configured.as_os_str() != canonical.as_os_str() {
        return Ok(mecmcp_auth::ResolvedTokenPath {
            path: configured.to_path_buf(),
            used_fallback: false,
            fallback_from: None,
        });
    }

    mecmcp_auth::resolve_token_path(configured, legacy).context("resolving token file path")
}

/// Pre-provision the audit HMAC key file at `path` if it is absent or empty,
/// mirroring `packaging/lxc/install.sh`'s own key-generation step so every
/// entry point -- LXC install, systemd start, or a container's first run --
/// converges on the same keyed-audit posture instead of only the LXC path
/// doing it (mecmcp#376 / MEC-978). `--audit-redact` still defaults to empty
/// (redaction stays opt-in), so this alone does not turn redaction on; it
/// just means the key is already there the moment an operator flips
/// `--audit-redact ...=hmac` on, instead of failing with `HmacKeyUnreadable`
/// on that first restart.
///
/// A zero-byte key file is indistinguishable from "never generated" and
/// would make every HMAC output constant, so rewriting it here is a repair,
/// not data loss. A non-empty file is never rotated -- that would silently
/// break verification of every audit record signed under the old key.
fn ensure_audit_hmac_key(path: &std::path::Path) -> Result<()> {
    if std::fs::metadata(path)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
    {
        return Ok(());
    }

    let mut key = [0u8; 32];
    use rand::TryRng as _;
    rand::rngs::SysRng.try_fill_bytes(&mut key).map_err(|e| {
        anyhow::anyhow!("generating audit HMAC key: OS entropy source unavailable: {e}")
    })?;
    let hex_key: String = key.iter().map(|b| format!("{b:02x}")).collect();

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating audit HMAC key file {}", path.display()))?;
        use std::io::Write as _;
        file.write_all(hex_key.as_bytes())
            .with_context(|| format!("writing audit HMAC key file {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &hex_key)
            .with_context(|| format!("writing audit HMAC key file {}", path.display()))?;
    }

    Ok(())
}

/// Refuse `--otel-endpoint` rather than silently dropping the export this
/// binary cannot send.
///
/// This binary does not build `mecmcp-audit`'s `otel` feature, so
/// `init_tracing`'s `AuditConfig::otel` is always `None` below regardless of
/// what the flag says. Starting up anyway would contradict the flag's own
/// `--help` text, which promises the export happens.
fn reject_unsupported_otel_endpoint(otel_endpoint: Option<&str>) -> Result<()> {
    if otel_endpoint.is_some() {
        anyhow::bail!(
            "--otel-endpoint requires a build of rustsdcmcp with mecmcp-audit's `otel` feature, \
             which this binary does not enable"
        );
    }
    Ok(())
}

/// Load `--approval-digest-key-file`, if set.
///
/// `None` keeps the change-set coordinator on the unkeyed v5 approval digest
/// (today's default). A bad path must fail startup rather than being
/// swallowed: an operator who set this flag believes approvals are keyed, and
/// silently falling back to unkeyed on a load error would make that belief
/// false.
fn load_approval_digest_key(
    path: Option<&Path>,
) -> Result<Option<mecmcp_changeset::ApprovalDigestKey>> {
    path.map(|path| {
        mecmcp_changeset::ApprovalDigestKey::load_from_file(path)
            .with_context(|| format!("loading --approval-digest-key-file {}", path.display()))
    })
    .transpose()
}

/// Bearer-token boundary selected for the Streamable HTTP listener.
#[derive(Debug, PartialEq, Eq)]
enum AuthMode {
    /// Load and enforce this bearer-token store.
    Tokens(PathBuf),
    /// Serve unauthenticated. `mecmcp_runtime::cli_validate` confines this to loopback.
    NoAuth,
}

/// Decide the listener's authentication boundary, refusing every combination
/// that would otherwise resolve to a silently unauthenticated listener.
///
/// `mecmcp_runtime::cli_validate` already refuses a listener with neither flag
/// and confines `--allow-no-auth` to loopback, but it accepts both flags
/// together. Selecting a mode here rather than falling through to `None` keeps
/// that combination from dropping the token store without a diagnostic.
fn resolve_auth_mode(
    tokens_file: Option<&Path>,
    allow_no_auth: bool,
) -> Result<AuthMode, &'static str> {
    match (tokens_file, allow_no_auth) {
        (Some(path), false) => Ok(AuthMode::Tokens(path.to_owned())),
        (None, true) => Ok(AuthMode::NoAuth),
        (Some(_), true) => Err(
            "--tokens-file and --allow-no-auth are mutually exclusive: pass --tokens-file for an authenticated listener, or --allow-no-auth alone for an unauthenticated loopback one",
        ),
        (None, false) => Err(
            "--transport streamable-http requires --tokens-file (or --allow-no-auth on loopback)",
        ),
    }
}

/// Decide the listener's authentication boundary for the selected transport.
///
/// Stdio has no HTTP boundary, so `--tokens-file` is never consulted there —
/// a container `ENTRYPOINT` that bakes in a fixed `--tokens-file` path must
/// not block a stdio start when nothing is mounted at that path (MEC-2121).
/// Extracted from `run` so this transport split is unit-testable without a
/// live SDC endpoint, which `run` requires for the tenant-scope check.
fn resolve_listener_auth_mode(
    transport: Transport,
    tokens_file: Option<&Path>,
    allow_no_auth: bool,
) -> Result<Option<AuthMode>, &'static str> {
    match transport {
        Transport::Stdio => Ok(None),
        Transport::StreamableHttp => resolve_auth_mode(tokens_file, allow_no_auth).map(Some),
    }
}

/// Cancel `shutdown` on the first SIGTERM or SIGINT.
///
/// `mecmcp_runtime::shutdown::GracefulShutdown` now handles both SIGINT and
/// SIGTERM, so we just subscribe to its unified signal.
fn install_shutdown_signals(shutdown: CancellationToken) -> Result<()> {
    let coordinator = mecmcp_runtime::shutdown::GracefulShutdown::new()
        .context("installing shutdown signal handlers")?;
    let interrupt = coordinator.subscribe();
    tokio::spawn(async move {
        // Hold the coordinator so its signal handlers stay alive.
        let _coordinator = coordinator;
        interrupt.await;
        shutdown.cancel();
    });
    Ok(())
}

/// Validate package configuration file.
///
/// Checks that config/sdc.json.example:
/// - Parses as valid JSON with the expected structure
/// - Has version == 1
/// - Has non-empty tenant and credential_env
/// - Has endpoint starting with "https://"
/// - Has changeset_state_file == "/var/lib/rustsdcmcp/changeset-state.json"
fn validate_config_file(package_dir: &Path) -> Result<()> {
    let config_path = package_dir.join("config/sdc.json.example");
    let content = fs::read_to_string(&config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;

    let value: serde_json::Value =
        serde_json::from_str(&content).context("config example is not valid JSON")?;

    // Check version
    if value.get("version") != Some(&serde_json::json!(1)) {
        anyhow::bail!("config example version must be 1");
    }

    // Check tenant is non-empty string
    if !value
        .get("tenant")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty())
    {
        anyhow::bail!("config example tenant must be a non-empty string");
    }

    // Check credential_env is non-empty string
    if !value
        .get("credential_env")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty())
    {
        anyhow::bail!("config example credential_env must be a non-empty string");
    }

    // Check endpoint starts with https://
    if !value
        .get("endpoint")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.starts_with("https://"))
    {
        anyhow::bail!("config example endpoint must start with 'https://'");
    }

    // Check changeset_state_file
    if value.get("changeset_state_file")
        != Some(&serde_json::json!(
            "/var/lib/rustsdcmcp/changeset-state.json"
        ))
    {
        anyhow::bail!(
            "config example changeset_state_file must be '/var/lib/rustsdcmcp/changeset-state.json'"
        );
    }

    Ok(())
}

/// Parse JSON while rejecting duplicate object members.
///
/// `serde_json::Value` silently keeps the **last** value for a repeated name.
/// For a supply-chain gate that is a bypass, not a convenience: a forbidden
/// marker can be hidden in a member that is then discarded by a duplicate.
///
/// Neither surface of the forbidden-string check sees it on its own —
///
/// ```text
/// {"version":"\u0076\u0030\u002e\u0038\u002e\u0030","version":"safe"}
/// ```
///
/// — the raw bytes contain no literal `v0.8.0` because it is escaped, and the
/// re-serialized tree contains only `safe` because the duplicate collapsed it.
/// Composing the two techniques defeats both checks, which is why parsing has
/// to refuse the shape rather than the checks chasing every encoding of it.
///
/// RFC 8259 says object names SHOULD be unique; a shipped SBOM with repeated
/// members is malformed, so rejecting is correct as well as safe.
fn parse_json_rejecting_duplicate_keys(text: &str) -> Result<serde_json::Value> {
    struct Strict(serde_json::Value);

    struct StrictVisitor;

    impl<'de> serde::de::Visitor<'de> for StrictVisitor {
        type Value = Strict;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("JSON with unique object member names")
        }

        fn visit_unit<E>(self) -> std::result::Result<Strict, E> {
            Ok(Strict(serde_json::Value::Null))
        }

        fn visit_bool<E>(self, v: bool) -> std::result::Result<Strict, E> {
            Ok(Strict(v.into()))
        }

        fn visit_i64<E>(self, v: i64) -> std::result::Result<Strict, E> {
            Ok(Strict(v.into()))
        }

        fn visit_u64<E>(self, v: u64) -> std::result::Result<Strict, E> {
            Ok(Strict(v.into()))
        }

        fn visit_f64<E>(self, v: f64) -> std::result::Result<Strict, E> {
            Ok(Strict(v.into()))
        }

        fn visit_str<E>(self, v: &str) -> std::result::Result<Strict, E> {
            Ok(Strict(v.into()))
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Strict, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut items = Vec::new();
            while let Some(Strict(v)) = seq.next_element::<Strict>()? {
                items.push(v);
            }
            Ok(Strict(serde_json::Value::Array(items)))
        }

        fn visit_map<A>(self, mut map: A) -> std::result::Result<Strict, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut out = serde_json::Map::new();
            while let Some(key) = map.next_key::<String>()? {
                let Strict(value) = map.next_value::<Strict>()?;
                if out.insert(key.clone(), value).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate object member '{key}'"
                    )));
                }
            }
            Ok(Strict(serde_json::Value::Object(out)))
        }
    }

    impl<'de> serde::Deserialize<'de> for Strict {
        fn deserialize<D>(d: D) -> std::result::Result<Strict, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            d.deserialize_any(StrictVisitor)
        }
    }

    let Strict(value) = serde_json::from_str::<Strict>(text)?;
    Ok(value)
}

/// Validate package SBOM file.
///
/// Checks that SBOM.cdx.json:
/// - Has bomFormat == "CycloneDX"
/// - Has metadata.component.name == "rustsdcmcp"
/// - Has non-empty components array containing "serde"
/// - Has exactly the expected mecmcp-* components at version 0.16.0
/// - Does not contain the forbidden version tag or commit hash
/// - Does not contain absolute repository paths
fn validate_sbom_file(package_dir: &Path) -> Result<()> {
    let sbom_path = package_dir.join("SBOM.cdx.json");
    let content = fs::read_to_string(&sbom_path)
        .with_context(|| format!("reading {}", sbom_path.display()))?;

    let value = parse_json_rejecting_duplicate_keys(&content)
        .context("SBOM is not valid JSON with unique object members")?;

    // Check bomFormat
    if value.get("bomFormat").and_then(|v| v.as_str()) != Some("CycloneDX") {
        anyhow::bail!("SBOM bomFormat must be 'CycloneDX'");
    }

    // Check metadata.component.name
    if value
        .get("metadata")
        .and_then(|m| m.get("component"))
        .and_then(|c| c.get("name"))
        .and_then(|n| n.as_str())
        != Some("rustsdcmcp")
    {
        anyhow::bail!("SBOM metadata.component.name must be 'rustsdcmcp'");
    }

    // Check components is non-empty array
    let components = value
        .get("components")
        .and_then(|c| c.as_array())
        .ok_or_else(|| anyhow::anyhow!("SBOM components must be a non-empty array"))?;

    if components.is_empty() {
        anyhow::bail!("SBOM components array must not be empty");
    }

    // Check for serde
    if !components
        .iter()
        .any(|c| c.get("name").and_then(|n| n.as_str()) == Some("serde"))
    {
        anyhow::bail!("SBOM must contain 'serde' component");
    }

    // Check mecmcp-* components
    let expected_mecmcp_components = [
        ("mecmcp-audit", "0.26.0"),
        ("mecmcp-auth", "0.26.0"),
        ("mecmcp-changeset", "0.26.0"),
        ("mecmcp-redact", "0.26.0"),
        ("mecmcp-runtime", "0.26.0"),
        ("mecmcp-secret", "0.26.0"),
        ("mecmcp-server", "0.26.0"),
        ("mecmcp-transport", "0.26.0"),
    ];

    let mut found_mecmcp: Vec<(String, String)> = Vec::new();
    for c in components {
        if let Some(name) = c
            .get("name")
            .and_then(|n| n.as_str())
            .filter(|n| n.starts_with("mecmcp-"))
        {
            let version = c.get("version").and_then(|v| v.as_str()).ok_or_else(|| {
                anyhow::anyhow!(
                    "SBOM mecmcp-* component '{}' has missing or non-string version",
                    name
                )
            })?;
            found_mecmcp.push((name.to_string(), version.to_string()));
        }
    }
    found_mecmcp.sort();

    let expected: Vec<(String, String)> = expected_mecmcp_components
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();

    if found_mecmcp != expected {
        anyhow::bail!(
            "SBOM mecmcp-* components mismatch. Expected: {:?}, Found: {:?}",
            expected,
            found_mecmcp
        );
    }

    // Check for forbidden strings in BOTH the raw bytes and the decoded/normalized
    // JSON tree. Neither alone is sufficient:
    //
    // - raw only: a marker written as an escape sequence (`v\u0030.8.0`) decodes to
    //   `v0.8.0` but never appears literally, so a raw search misses it.
    // - normalized only: `serde_json` keeps the LAST value for duplicate object
    //   members, so `{"probe":"v0.8.0","probe":"safe"}` re-serializes with the
    //   forbidden value discarded and passes. The raw search still catches it.
    //
    // Searching both closes each gap with the other. Do not "simplify" this to one.
    let normalized = serde_json::to_string(&value)
        .context("re-serializing SBOM for forbidden-string validation")?;

    let contains_forbidden = |needle: &str| content.contains(needle) || normalized.contains(needle);

    if contains_forbidden("v0.8.0") {
        anyhow::bail!("SBOM must not contain 'v0.8.0'");
    }

    if contains_forbidden("70ac3d8fb5f27db3257d11aef28bd09587f085e1") {
        anyhow::bail!("SBOM must not contain forbidden commit hash");
    }

    // Check for absolute paths
    if contains_forbidden("/home/")
        || contains_forbidden("/workspace/")
        || contains_forbidden("/workspaces/")
    {
        anyhow::bail!("SBOM contains an absolute repository or worktree path");
    }

    Ok(())
}

/// Validate both package configuration and SBOM.
fn validate_package(package_dir: &Path) -> Result<()> {
    validate_config_file(package_dir).context("config validation failed")?;
    validate_sbom_file(package_dir).context("SBOM validation failed")?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // `parse_for`/`parse_with_provenance` name the binary and its version, so
    // `--version` answers instead of failing as an unknown argument. Parsing
    // the shared `Cli` directly leaves it with no version of its own
    // (mecmcp#159), which breaks the package-identity check a deployment runs.
    let parsed: ParsedCli<ServerCli> = mecmcp_runtime::cli::parse_with_provenance::<ServerCli>(
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
    );

    // Handle --validate-package before any other setup. This must run
    // synchronously and exit immediately, so the installer can use it without
    // credentials, configuration, or a network connection.
    if let Some(package_dir) = &parsed.cli.validate_package {
        return validate_package(package_dir).map(|()| {
            println!("Package validation successful");
        });
    }

    // Read provenance before consuming `parsed.cli`; `Command` is not `Clone`,
    // so the shared arguments have to be moved out rather than borrowed.
    let state_file_supplied = parsed.was_supplied("state_file");
    let approval_timeout_supplied = parsed.was_supplied("approval_timeout_secs");
    let ServerCli {
        shared: args,
        lab_mode,
        state_file: cli_state_file,
        approval_timeout_secs: cli_approval_timeout_secs,
        validate_package: _,
        enable_metrics,
        max_requests_per_second_per_ip,
        max_request_burst_per_ip,
        max_requests_per_second_per_token,
        max_request_burst_per_token,
    } = parsed.cli;
    mecmcp_runtime::cli_validate::validate(&args).map_err(|error| anyhow::anyhow!("{error}"))?;

    // Decide the listener's authentication boundary alongside the rest of the
    // CLI refusals, before anything reads a credential or contacts SDC. Only
    // loading the selected store is deferred, so an unusable flag combination
    // is reported as itself rather than as a downstream credential error.
    let auth_mode = resolve_listener_auth_mode(
        args.transport,
        args.tokens_file.as_deref(),
        args.allow_no_auth,
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;

    if let Some(key_path) = args.audit_hmac_key_file.as_deref() {
        ensure_audit_hmac_key(key_path).context("pre-provisioning audit HMAC key file")?;
    }

    let redaction = if args.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            mecmcp_audit::AuditRedaction::parse(
                &args.audit_redact,
                args.audit_hmac_key_file.as_deref(),
            )
            .map_err(|error| anyhow::anyhow!("invalid --audit-redact: {error}"))?,
        )
    };
    // This binary does not build mecmcp-audit's `otel` feature, so exporting
    // is not possible; refusing to start is the fail-closed answer here.
    reject_unsupported_otel_endpoint(args.otel_endpoint.as_deref())?;
    let audit_sink = mecmcp_audit::init_tracing(&mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
        journald: args.audit_journald,
        otel: None,
    })
    .context("initializing audit tracing")?;
    mecmcp_audit::install_duration_metric_name("sdcmcp_tool_duration_seconds");

    // The shared CLI retains its historic `device_mapping` field. For this
    // management-plane consumer, `-f/--device-mapping` selects sdc.json until
    // the target-neutral CLI work tracked in mecmcp#91 lands.
    let config = SdcConfig::from_path(&args.device_mapping)
        .with_context(|| format!("loading {}", args.device_mapping.display()))?;

    if let Some(Command::Token { action }) = args.command {
        return mecmcp_runtime::token_cmd::run(action, &[config.tenant], KNOWN_TOOLS)
            .map_err(anyhow::Error::from);
    }

    // Explicit CLI beats product configuration, but only when actually typed.
    let state_file = resolve(
        state_file_supplied,
        cli_state_file,
        config.changeset_state_file.clone(),
    );
    let approval_ttl_secs = resolve(
        approval_timeout_supplied,
        cli_approval_timeout_secs,
        config.approval_ttl_secs,
    );

    if lab_mode {
        // A relaxed security control should be visible where someone will see
        // it, not inferred from flags typed weeks ago.
        tracing::warn!(
            "--lab-mode: two-person control is DISABLED. Change sets are approved on \
             creation with approver=null and approval_waiver=\"lab-mode\". Every \
             mutation still goes through prepare and apply, and waived approvals stay \
             distinguishable from genuine ones in the audit trail."
        );
    }
    tracing::info!(
        lab_mode,
        approval_ttl_secs,
        state_file = state_file
            .as_deref()
            .and_then(Path::to_str)
            .unwrap_or("<in-memory>"),
        "change-control configuration resolved"
    );

    let provider = rustls::crypto::ring::default_provider();
    provider
        .clone()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install the rustls ring crypto provider"))?;

    // 16 KiB, not mecmcp-secret's 8 KiB default: matches the ceiling `SdcClient`
    // has always enforced, so adopting the hardened loader does not silently
    // tighten what credential length operators may already be running with.
    let credential = mecmcp_secret::load_from_env(
        &config.credential_env,
        mecmcp_secret::SecretLimits {
            max_bytes: 16 * 1024,
        },
    )
    .map_err(anyhow::Error::from)
    .context("loading SDC credential")?;
    // `GracefulShutdown` installs a Ctrl-C handler only. systemd stops this
    // unit with SIGTERM (`KillSignal=SIGTERM`), which that coordinator does not
    // observe, so feed SIGTERM into the same trigger rather than standing up a
    // second coordinator beside it. The upstream gap is mecmcp's to close.
    let shutdown = CancellationToken::new();
    install_shutdown_signals(shutdown.clone())?;

    let client = SdcClient::new(&config, credential)
        .context("building SDC client")?
        .with_shutdown(shutdown.clone());
    client
        .verify_tenant(&config.expected_tenant_id, &shutdown)
        .await
        .context("verifying SDC credential tenant scope")?;

    // Built before the change manager because its coordinator takes the
    // recorder, and started eagerly so a misconfiguration stops the server here
    // rather than at the first change.
    let evidence = match args.evidence.into_config() {
        Ok(Some(config)) => {
            tracing::info!(
                server_id = %config.server_id,
                run_id = %config.run_id,
                "SSDF evidence pipeline enabled"
            );
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let transport = Arc::new(
                mecmcp_transport::evidence_transport::EvidenceHttpTransport::new(
                    args.evidence.ca_file(),
                    provider,
                )
                .context("building the SSDF evidence transport")?,
            );
            Some(
                mecmcp_audit::EvidenceService::start_with_transport(config, transport)
                    .context("starting the SSDF evidence pipeline")?,
            )
        }
        Ok(None) => None,
        Err(error) => anyhow::bail!("SSDF evidence configuration: {error}"),
    };

    let approval_digest_key = load_approval_digest_key(args.approval_digest_key_file.as_deref())?;

    let changes = Arc::new(ChangeManager::load(
        client.clone(),
        config.tenant.clone(),
        config.endpoint.clone(),
        state_file.as_deref(),
        Duration::from_secs(approval_ttl_secs),
        lab_mode,
        evidence
            .as_ref()
            .map(mecmcp_audit::EvidenceService::recorder),
        approval_digest_key,
    )?);
    let handler = SdcHandler::new(Arc::<str>::from(config.tenant.as_str()), client, changes);

    let token_store = match auth_mode {
        None => None,
        Some(AuthMode::Tokens(path)) => {
            let resolved = resolve_tokens(&path)?;

            if resolved.used_fallback {
                tracing::warn!(
                    primary = %"/var/lib/rustsdcmcp/tokens.json",
                    fallback = %resolved.path.display(),
                    "Token file not found at primary location; using fallback. \
                     Migration required: move the token file to the primary location \
                     and update any site-specific overrides."
                );
            }

            let store = Arc::new(
                TokenStoreFile::<NoGrant>::load(&resolved.path)
                    .with_context(|| format!("loading {}", resolved.path.display()))?,
            );
            tracing::info!(
                tokens = store.store().len(),
                path = %resolved.path.display(),
                "token store loaded"
            );

            // Warn about stale secrets in the token directory (#95).
            // Parent directory resolution: /var/lib/rustsdcmcp/tokens.json → /var/lib/rustsdcmcp
            if let Some(token_dir) = resolved.path.parent() {
                let token_filename = resolved
                    .path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("tokens.json");

                let stale = mecmcp_auth::find_stale_secrets(token_dir, &[token_filename]);
                if !stale.is_empty() {
                    tracing::warn!("Stale secret files detected in {}:", token_dir.display());
                    for s in &stale {
                        tracing::warn!(
                            "  {} ({})",
                            s.path.display(),
                            match s.reason {
                                mecmcp_auth::StaleReason::SupersededToken =>
                                    "superseded token file",
                                mecmcp_auth::StaleReason::RetiredKey => "retired TLS key",
                                mecmcp_auth::StaleReason::Backup => "backup file",
                            }
                        );
                    }
                    tracing::warn!(
                        "These files should be reviewed and deleted during a maintenance window. \
                         Revocations do not reach backup copies."
                    );
                }
            }

            Some(store)
        }
        Some(AuthMode::NoAuth) => {
            tracing::warn!(
                "--allow-no-auth: Streamable HTTP accepts unauthenticated requests on loopback"
            );
            None
        }
    };

    // SIGHUP hot reload (unix only): reopen the audit file for lossless log
    // rotation, then — when configured — re-read the token store and swap it
    // in. Gated on the audit sink OR the token store, not the token store
    // alone: a deployment with only `--audit-log-file` set (no
    // `--tokens-file`) still needs a handler, or SIGHUP's default
    // disposition (terminate) kills the process on the very signal logrotate
    // sends it.
    rustsdcmcp::install_sighup_handler(audit_sink, token_store.clone())
        .context("installing SIGHUP handler")?;

    // Bound rather than propagated with `?`, so the flush below runs whichever
    // way serving ended. `EvidenceService::Drop` deliberately does not spool --
    // a Drop performing network I/O turns teardown into an unpredictable stall
    // -- so returning the error directly would lose every record the recorder
    // still held, on exactly the failure the trail exists to describe.
    let served: anyhow::Result<()> = async {
        match args.transport {
            Transport::Stdio => {
                // serve_with_ct rather than serve: `serve` does not return until
                // the client sends `initialize`, so a token installed afterwards
                // would miss a signal arriving during the handshake and leave the
                // process blocked on an open stdin. The token owns the service
                // here, and cancelling it cascades to every in-flight request
                // context, so a signal abandons running SDC work rather than
                // waiting out the job-poll deadline.
                let service = match handler
                    .serve_with_ct((tokio::io::stdin(), tokio::io::stdout()), shutdown)
                    .await
                {
                    Ok(service) => service,
                    // A signal arriving before the client sends `initialize` is the
                    // exact case this cancellation path exists for. rmcp reports it
                    // as ServerInitializeError::Cancelled; propagating that would
                    // exit non-zero and record a clean stop as a startup failure.
                    Err(rmcp::service::ServerInitializeError::Cancelled) => {
                        tracing::info!("shutdown signalled before initialization; exiting cleanly");
                        return Ok(());
                    }
                    Err(error) => {
                        return Err(anyhow::Error::new(error))
                            .context("starting MCP stdio service");
                    }
                };
                service
                    .waiting()
                    .await
                    .context("MCP stdio service exited with error")?;
            }
            Transport::StreamableHttp => {
                let address = format!("{}:{}", args.host, args.port)
                    .parse()
                    .with_context(|| format!("parsing {}:{}", args.host, args.port))?;
                let tls = match (&args.tls_cert, &args.tls_key) {
                    (Some(cert), Some(key)) => Some(
                        mecmcp_transport::load_tls(cert, key, Arc::new(provider))
                            .context("loading listener TLS")?,
                    ),
                    _ => None,
                };
                let limits = mecmcp_transport::LimitsConfig {
                    max_requests_per_second_per_ip,
                    max_request_burst_per_ip,
                    max_requests_per_second_per_token,
                    max_request_burst_per_token,
                    ..mecmcp_transport::LimitsConfig::default()
                };
                limits
                    .validate()
                    .map_err(|error| anyhow::anyhow!("{error}"))?;
                serve_http(
                    handler,
                    address,
                    token_store,
                    args.allowed_host,
                    args.allowed_origin,
                    limits,
                    enable_metrics,
                    args.allow_insecure_bind,
                    tls,
                    shutdown,
                    Duration::from_secs(10),
                )
                .await?;
            }
        }
        Ok(())
    }
    .await;

    // Deliver what is still spooled. The drain ships on an interval, so without
    // this every record since the last tick waits for the next start, and a
    // segment still open has never been spooled at all.
    if let Some(service) = evidence
        && let Err(error) = service.shutdown()
    {
        tracing::error!(%error, "the SSDF evidence pipeline did not flush cleanly");
    }

    served
}

#[cfg(test)]
mod tests {
    use super::{
        AuthMode, DEFAULT_APPROVAL_TIMEOUT_SECS, ParsedCli, ServerCli, resolve, resolve_auth_mode,
        resolve_listener_auth_mode,
    };
    use mecmcp_runtime::cli::Transport;
    use std::path::{Path, PathBuf};

    #[test]
    fn stdio_never_consults_the_tokens_file() {
        // A container `ENTRYPOINT` bakes in a fixed `--tokens-file` path, so
        // this must stay `Ok(None)` even when that path does not exist --
        // the missing-file case an image's stdio start hits in practice.
        assert_eq!(
            resolve_listener_auth_mode(
                Transport::Stdio,
                Some(Path::new("/does/not/exist/tokens.json")),
                false,
            ),
            Ok(None),
        );
        assert_eq!(
            resolve_listener_auth_mode(Transport::Stdio, None, false),
            Ok(None),
            "stdio must not require --tokens-file or --allow-no-auth either"
        );
    }

    #[test]
    fn streamable_http_still_requires_an_auth_decision() {
        assert_eq!(
            resolve_listener_auth_mode(Transport::StreamableHttp, None, false),
            Err(
                "--transport streamable-http requires --tokens-file (or --allow-no-auth on loopback)"
            ),
        );
        assert_eq!(
            resolve_listener_auth_mode(
                Transport::StreamableHttp,
                Some(Path::new("/etc/rustsdcmcp/tokens.json")),
                false,
            ),
            Ok(Some(AuthMode::Tokens(PathBuf::from(
                "/etc/rustsdcmcp/tokens.json"
            )))),
        );
    }

    #[test]
    fn a_tokens_file_alone_selects_an_authenticated_listener() {
        assert_eq!(
            resolve_auth_mode(Some(Path::new("/etc/rustsdcmcp/tokens.json")), false),
            Ok(AuthMode::Tokens(PathBuf::from(
                "/etc/rustsdcmcp/tokens.json"
            ))),
        );
    }

    #[test]
    fn allow_no_auth_alone_selects_the_unauthenticated_listener() {
        assert_eq!(resolve_auth_mode(None, true), Ok(AuthMode::NoAuth));
    }

    #[test]
    fn a_tokens_file_is_never_silently_dropped_by_allow_no_auth() {
        let refusal = resolve_auth_mode(Some(Path::new("/etc/rustsdcmcp/tokens.json")), true)
            .expect_err("supplying a token store and --allow-no-auth must be refused");
        assert!(refusal.contains("mutually exclusive"));
    }

    #[test]
    fn a_listener_with_no_authentication_decision_is_refused() {
        assert!(resolve_auth_mode(None, false).is_err());
    }

    /// Parse an argument list through the same path `main` uses.
    fn parse(args: &[&str]) -> ParsedCli<ServerCli> {
        mecmcp_runtime::cli::try_parse_from::<ServerCli, _, _>("rustsdcmcp", "0.0.0-test", args)
            .expect("parses")
    }

    #[test]
    fn version_answers_instead_of_erroring() {
        // Parsing the shared `Cli` directly made `--version` an unknown
        // argument, which broke the package-identity check a deployment runs
        // (mecmcp#159). The error carries the rendered version, not a failure.
        let error = mecmcp_runtime::cli::try_parse_from::<ServerCli, _, _>(
            "rustsdcmcp",
            "9.9.9-test",
            ["rustsdcmcp", "--version"],
        )
        .expect_err("--version exits through clap");
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(
            error.to_string().contains("9.9.9-test"),
            "--version must name this binary's version, got: {error}"
        );
    }

    #[test]
    fn omitted_flags_fall_back_to_product_configuration() {
        let parsed = parse(&["rustsdcmcp", "--transport", "stdio"]);
        assert!(!parsed.was_supplied("approval_timeout_secs"));
        assert!(!parsed.was_supplied("state_file"));

        // The parser default must not win over a configured value.
        assert_eq!(
            resolve(
                parsed.was_supplied("approval_timeout_secs"),
                parsed.cli.approval_timeout_secs,
                3600
            ),
            3600
        );
    }

    #[test]
    fn an_explicit_flag_beats_product_configuration() {
        let parsed = parse(&["rustsdcmcp", "--approval-timeout-secs", "120"]);
        assert!(parsed.was_supplied("approval_timeout_secs"));
        assert_eq!(
            resolve(
                parsed.was_supplied("approval_timeout_secs"),
                parsed.cli.approval_timeout_secs,
                3600
            ),
            120
        );
    }

    #[test]
    fn a_flag_typed_with_the_default_value_still_wins() {
        // The trap PACKAGING.md names: comparing against the default cannot
        // tell a typed value from a defaulted one, so it would silently hand
        // this operator the configured 3600 they were overriding.
        let typed = format!("{DEFAULT_APPROVAL_TIMEOUT_SECS}");
        let parsed = parse(&["rustsdcmcp", "--approval-timeout-secs", &typed]);
        assert!(parsed.was_supplied("approval_timeout_secs"));
        assert_eq!(
            resolve(
                parsed.was_supplied("approval_timeout_secs"),
                parsed.cli.approval_timeout_secs,
                3600
            ),
            DEFAULT_APPROVAL_TIMEOUT_SECS
        );
    }

    #[test]
    fn state_file_resolves_without_moving_an_existing_deployment() {
        // Adoption must not silently relocate durable state. With the flag
        // absent, the configured path must survive untouched.
        let configured = Some(PathBuf::from("/var/lib/rustsdcmcp/changeset-state.json"));
        let parsed = parse(&["rustsdcmcp"]);
        assert_eq!(
            resolve(
                parsed.was_supplied("state_file"),
                parsed.cli.state_file.clone(),
                configured.clone()
            ),
            configured
        );

        let parsed = parse(&["rustsdcmcp", "--state-file", "/tmp/other.json"]);
        assert_eq!(
            resolve(
                parsed.was_supplied("state_file"),
                parsed.cli.state_file.clone(),
                configured
            ),
            Some(PathBuf::from("/tmp/other.json"))
        );
    }

    #[test]
    fn fresh_install_gets_nonzero_rate_limits_without_operator_action() {
        // MEC-347: a fresh install must not silently run unrate-limited.
        let parsed = parse(&["rustsdcmcp", "--transport", "stdio"]);
        assert!(parsed.cli.max_requests_per_second_per_ip > 0);
        assert!(parsed.cli.max_request_burst_per_ip > 0);
        assert!(parsed.cli.max_requests_per_second_per_token > 0);
        assert!(parsed.cli.max_request_burst_per_token > 0);
    }

    #[test]
    fn metrics_are_off_by_default_but_operator_configurable() {
        let parsed = parse(&["rustsdcmcp", "--transport", "stdio"]);
        assert!(!parsed.cli.enable_metrics);

        let parsed = parse(&["rustsdcmcp", "--transport", "stdio", "--enable-metrics"]);
        assert!(parsed.cli.enable_metrics);
    }

    #[test]
    fn rate_limits_are_operator_configurable() {
        let parsed = parse(&[
            "rustsdcmcp",
            "--transport",
            "stdio",
            "--max-requests-per-second-per-ip",
            "5",
            "--max-request-burst-per-ip",
            "10",
            "--max-requests-per-second-per-token",
            "2",
            "--max-request-burst-per-token",
            "4",
        ]);
        assert_eq!(parsed.cli.max_requests_per_second_per_ip, 5);
        assert_eq!(parsed.cli.max_request_burst_per_ip, 10);
        assert_eq!(parsed.cli.max_requests_per_second_per_token, 2);
        assert_eq!(parsed.cli.max_request_burst_per_token, 4);
    }

    #[test]
    fn a_zero_approval_timeout_is_refused() {
        // Zero expires every change set at creation, so approval fails and
        // lab mode's waiver reports the window already closed. SdcConfig
        // rejects it, but an explicit flag bypasses that validation.
        let error = mecmcp_runtime::cli::try_parse_from::<ServerCli, _, _>(
            "rustsdcmcp",
            "0.0.0-test",
            ["rustsdcmcp", "--approval-timeout-secs", "0"],
        )
        .expect_err("a zero approval timeout must be refused");
        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);

        // One second is unhelpful but coherent, so it is the operator's call.
        assert_eq!(
            parse(&["rustsdcmcp", "--approval-timeout-secs", "1"])
                .cli
                .approval_timeout_secs,
            1
        );
    }

    #[test]
    fn lab_mode_is_off_unless_asked_for() {
        assert!(!parse(&["rustsdcmcp"]).cli.lab_mode);
        assert!(parse(&["rustsdcmcp", "--lab-mode"]).cli.lab_mode);
    }

    #[test]
    fn the_shared_flags_survive_flattening() {
        // Declaring the standard flags locally must not drop any shared one.
        let parsed = parse(&[
            "rustsdcmcp",
            "--transport",
            "streamable-http",
            "--host",
            "0.0.0.0",
            "--port",
            "30032",
            "--allowed-host",
            "rustsdcmcp-612.mechub.org:30032",
            "--lab-mode",
        ]);
        assert_eq!(parsed.cli.shared.host, "0.0.0.0");
        assert_eq!(parsed.cli.shared.port, 30032);
        assert_eq!(
            parsed.cli.shared.allowed_host,
            vec!["rustsdcmcp-612.mechub.org:30032".to_owned()]
        );
        assert!(parsed.cli.lab_mode);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod token_path_tests {
    use super::resolve_tokens_with;

    /// The canonical path is absent and the legacy store exists: the fallback
    /// must fire, so an upgrade that has not migrated yet still starts.
    #[test]
    fn canonical_path_falls_back_to_an_existing_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").unwrap();

        let resolved = resolve_tokens_with(&canonical, &canonical, &legacy).unwrap();
        assert_eq!(
            resolved.path, legacy,
            "the legacy store should have been used"
        );
        assert!(resolved.used_fallback);
    }

    /// The same legacy store exists, but the operator configured a DIFFERENT
    /// path. Falling back here would silently reactivate credentials they did
    /// not ask for — a typo or a deleted store must fail, not resurrect tokens.
    #[test]
    fn a_custom_path_never_falls_back_to_the_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").unwrap();
        let custom = dir.path().join("operator-chosen.json");

        let resolved = resolve_tokens_with(&custom, &canonical, &legacy).unwrap();
        assert_eq!(
            resolved.path, custom,
            "an operator-supplied path must be used verbatim"
        );
        assert!(
            !resolved.used_fallback,
            "a custom path must never resolve to the legacy /etc store"
        );
    }

    /// A malformed spelling of the canonical path must NOT reach the fallback.
    ///
    /// `Path` equality normalizes away a trailing separator, so
    /// `.../tokens.json/` compares equal to the canonical path; and when the
    /// file is absent `metadata()` returns NotFound for that spelling too,
    /// indistinguishable from the plain form. A typo would therefore activate
    /// the legacy store — the opposite of fail-closed. The comparison is
    /// byte-exact for this reason.
    #[test]
    fn a_trailing_slash_spelling_does_not_reach_the_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").unwrap();

        let mut malformed = canonical.clone().into_os_string();
        malformed.push("/");
        let malformed = std::path::PathBuf::from(malformed);

        let resolved = resolve_tokens_with(&malformed, &canonical, &legacy).unwrap();
        assert!(
            !resolved.used_fallback,
            "a trailing-slash spelling must not activate the legacy store"
        );
    }

    /// Regression test for #162: an explicit legacy path is not shadowed by
    /// the canonical store.
    ///
    /// When the operator explicitly configured `--tokens-file /etc/rustsdcmcp/tokens.json`,
    /// the old code called `resolve_token_path(primary, legacy)` because
    /// `path == fallback_path`, which let any file at the canonical location
    /// shadow the explicitly configured legacy path — even an empty
    /// `{"version":1,"tokens":[]}`. This meant every bearer token was rejected.
    #[test]
    fn an_explicit_legacy_path_is_not_shadowed_by_the_canonical_store() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");

        // Canonical file exists but is empty
        std::fs::write(&canonical, r#"{"version":1,"tokens":[]}"#).unwrap();

        // Legacy file exists with a real store
        std::fs::write(&legacy, r#"{"version":1,"tokens":[{"id":"test"}]}"#).unwrap();

        // Configured = legacy path → should use legacy, not canonical
        let resolved = resolve_tokens_with(&legacy, &canonical, &legacy).unwrap();
        assert_eq!(
            resolved.path, legacy,
            "an explicit legacy path must be used, not shadowed by canonical"
        );
        assert!(
            !resolved.used_fallback,
            "explicitly configuring the legacy path is not a fallback"
        );
    }

    /// When the canonical path is configured and the file exists at that
    /// location, it should be used without fallback.
    #[test]
    fn canonical_configured_and_present_uses_canonical() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");

        // Canonical file exists
        std::fs::write(&canonical, r#"{"version":1,"tokens":[{"id":"test"}]}"#).unwrap();

        // Configured = canonical path → should use canonical
        let resolved = resolve_tokens_with(&canonical, &canonical, &legacy).unwrap();
        assert_eq!(
            resolved.path, canonical,
            "canonical path should be used when present"
        );
        assert!(
            !resolved.used_fallback,
            "no fallback should occur when canonical is present"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod audit_hmac_key_tests {
    use super::ensure_audit_hmac_key;

    /// The common case: no entry point has ever run here before (fresh
    /// container volume, fresh LXC install). A key must be created, be
    /// non-empty, and be mode 0600 so it is not group/world-readable.
    #[test]
    fn generates_a_key_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-hmac.key");

        ensure_audit_hmac_key(&path).unwrap();

        let contents = std::fs::read(&path).unwrap();
        assert!(!contents.is_empty(), "generated key file must not be empty");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key file must be mode 0600");
        }
    }

    /// A key already exists (install.sh ran, or this is not the first
    /// container start against this volume). It must be left byte-for-byte
    /// untouched -- rotating it here would silently break verification of
    /// every audit record HMAC'd under the old key.
    #[test]
    fn does_not_rotate_an_existing_nonempty_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-hmac.key");
        std::fs::write(&path, b"existing-key-material").unwrap();

        ensure_audit_hmac_key(&path).unwrap();

        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, b"existing-key-material");
    }

    /// A zero-byte key file is indistinguishable from "never generated" (a
    /// truncated write, an `install -m 0600 /dev/null ...` placeholder, an
    /// interrupted first run) and would make every HMAC output constant. It
    /// must be repaired, not treated as already-present.
    #[test]
    fn repairs_an_empty_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-hmac.key");
        std::fs::write(&path, b"").unwrap();

        ensure_audit_hmac_key(&path).unwrap();

        let contents = std::fs::read(&path).unwrap();
        assert!(!contents.is_empty(), "empty key file must be repaired");
    }

    /// Two independent calls must not produce the same key -- otherwise the
    /// "random" key is really a constant and every deployment's audit HMAC
    /// is forgeable by anyone who reads this test.
    #[test]
    fn successive_generations_differ() {
        let dir = tempfile::tempdir().unwrap();
        let path_a = dir.path().join("a.key");
        let path_b = dir.path().join("b.key");

        ensure_audit_hmac_key(&path_a).unwrap();
        ensure_audit_hmac_key(&path_b).unwrap();

        let a = std::fs::read(&path_a).unwrap();
        let b = std::fs::read(&path_b).unwrap();
        assert_ne!(a, b, "two generated keys must not collide");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod approval_digest_key_tests {
    use super::load_approval_digest_key;
    use std::os::unix::fs::PermissionsExt;

    /// No `--approval-digest-key-file` keeps the coordinator unkeyed, same as
    /// today.
    #[test]
    fn no_approval_digest_key_file_is_fine() {
        assert!(
            load_approval_digest_key(None)
                .expect("no path is not an error")
                .is_none()
        );
    }

    /// A valid key file is loaded and returned.
    #[test]
    fn a_valid_approval_digest_key_file_is_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, b"a-sufficiently-long-test-key-value").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let key = load_approval_digest_key(Some(&path))
            .expect("a valid key file must load")
            .expect("Some(path) must produce Some(key)");
        assert_eq!(&*key, b"a-sufficiently-long-test-key-value");
    }

    /// A key file that fails `mecmcp-changeset`'s checks (here: too short)
    /// must fail startup, not fall back to running unkeyed.
    #[test]
    fn a_too_short_approval_digest_key_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, b"short").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let error = load_approval_digest_key(Some(&path))
            .expect_err("a too-short key file must be refused, not silently skipped");
        assert!(
            error.to_string().contains("approval-digest-key-file"),
            "{error}"
        );
    }

    /// A missing key file must fail startup rather than silently starting
    /// unkeyed -- the operator asked for a keyed digest and typo'd the path.
    #[test]
    fn a_missing_approval_digest_key_file_fails_closed() {
        let error = load_approval_digest_key(Some(std::path::Path::new(
            "/nonexistent/does-not-exist/key",
        )))
        .expect_err("a missing key file must be refused, not silently skipped");
        assert!(
            error.to_string().contains("approval-digest-key-file"),
            "{error}"
        );
    }
}

#[cfg(test)]
mod otel_endpoint_tests {
    use super::reject_unsupported_otel_endpoint;

    /// `--otel-endpoint` must refuse startup rather than silently dropping
    /// the export this binary cannot send.
    #[test]
    fn otel_endpoint_set_refuses_to_start() {
        let error = reject_unsupported_otel_endpoint(Some("http://127.0.0.1:4318"))
            .expect_err("--otel-endpoint must be refused by this binary");
        assert!(error.to_string().contains("--otel-endpoint"), "{error}");
    }

    /// No `--otel-endpoint` keeps today's behaviour: audit initializes with
    /// `otel: None`.
    #[test]
    fn no_otel_endpoint_starts_normally() {
        reject_unsupported_otel_endpoint(None).expect("no --otel-endpoint must not be refused");
    }
}
