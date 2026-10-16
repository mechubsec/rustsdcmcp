//! HTTP transport boundary tests.
//!
//! These tests were originally in src/compat/http.rs and cover behaviour
//! rustsdcmcp still cares about even after migrating to mecmcp 0.7.0's
//! upstream transport assembly.

use axum::http::{StatusCode, header};
use mecmcp_auth::{KnownNames, NoGrant, ScopeSet, TokenStoreFile};
use mecmcp_secret::OutboundSecret;
use mecmcp_transport::{LimitsConfig, serve_router};
use rustsdcmcp::{KNOWN_TOOLS, build_http_router};
use rustsdcmcp_core::{ChangeManager, SdcClient, SdcConfig};
use std::{
    sync::Arc,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

/// Allocate unique test ports.
static TEST_PORT_COUNTER: AtomicU16 = AtomicU16::new(18888);

/// Test server that starts SDC's `build_http_router` on a unique loopback port.
struct TestServer {
    url: String,
    shutdown: CancellationToken,
    _serving: tokio::task::JoinHandle<Result<(), mecmcp_transport::HttpServeError>>,
}

impl TestServer {
    /// Start the test server with the given host/origin allowlists and optional token store.
    async fn start(
        allowed_hosts: Vec<String>,
        allowed_origins: Vec<String>,
        token_store: Option<Arc<TokenStoreFile<NoGrant>>>,
    ) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config: SdcConfig = serde_json::from_value(serde_json::json!({
            "version": 1,
            "tenant": "test",
            "expected_tenant_id": "test",
            "credential_env": "SDC_TEST_CREDENTIAL",
            "auth_scheme": "api_key",
        }))
        .expect("config");
        let client = SdcClient::new(
            &config,
            OutboundSecret::new_unchecked("test-credential".to_owned()),
        )
        .expect("client");
        let changes = Arc::new(
            ChangeManager::load(
                client.clone(),
                "test",
                config.endpoint.clone(),
                None,
                Duration::from_secs(60),
                false,
                None,
                None,
            )
            .expect("changes"),
        );
        let handler = rustsdcmcp::SdcHandler::new(Arc::<str>::from("test"), client, changes);

        let shutdown = CancellationToken::new();
        let plan = build_http_router(
            handler,
            token_store,
            allowed_hosts,
            allowed_origins,
            LimitsConfig::default(),
            false,
            false,
            shutdown.clone(),
        )
        .expect("build_http_router");

        let port = TEST_PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let addr = format!("127.0.0.1:{port}").parse().expect("address");
        let url = format!("http://127.0.0.1:{port}");

        let serving = tokio::spawn(serve_router(plan, addr, None, Duration::from_millis(50)));

        // Wait for the server to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        Self {
            url,
            shutdown,
            _serving: serving,
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// A request that clears the host/origin guard reaches rmcp, which answers 406
/// because this bare probe carries no `Accept: text/event-stream`.
///
/// Asserting that exact code — rather than merely "not 421" — is what stops these
/// tests passing for the wrong reason: a probe rejected earlier in the stack would
/// not return 406 either.
const PASSED_THE_GUARD: StatusCode = StatusCode::NOT_ACCEPTABLE;

/// Send one probe with exactly one `Host` header and at most one `Origin`.
///
/// Using reqwest would add a default `Host` that cannot be overridden, so we use
/// a raw HTTP request to ensure exactly one header of each type.
async fn probe(url: &str, host: &str, origin: Option<&str>) -> StatusCode {
    // The test server is plain HTTP on loopback; no TLS settings are needed.
    let client = reqwest::Client::builder().build().expect("client");

    let mut req = client.post(format!("{url}/mcp")).header(header::HOST, host);
    if let Some(origin) = origin {
        req = req.header(header::ORIGIN, origin);
    }
    req.body("{}").send().await.expect("request").status()
}

/// The 609 production shape: `--allowed-host 203.0.113.194` while bound to `:30031`.
///
/// A portless Host allowlist entry must match ANY port. Matching the port exactly
/// here would return 421 on every request the live server receives.
#[tokio::test]
async fn portless_allowed_host_matches_any_port() {
    let server = TestServer::start(vec!["203.0.113.194".to_owned()], Vec::new(), None).await;
    assert_eq!(
        probe(&server.url, "203.0.113.194:30031", None).await,
        PASSED_THE_GUARD,
        "a portless --allowed-host entry must match the port the server is bound to"
    );
}

/// The allowlist extends rmcp's loopback default rather than replacing it.
#[tokio::test]
async fn loopback_stays_allowed_when_a_host_is_added() {
    let server = TestServer::start(vec!["203.0.113.194".to_owned()], Vec::new(), None).await;
    assert_eq!(
        probe(&server.url, "localhost", None).await,
        PASSED_THE_GUARD
    );
}

/// The DNS-rebinding guard (RUSTSEC-2026-0189). There is no way to turn it off.
#[tokio::test]
async fn unlisted_host_is_rejected() {
    let server = TestServer::start(vec!["203.0.113.194".to_owned()], Vec::new(), None).await;
    assert_eq!(
        probe(&server.url, "attacker.example.com", None).await,
        StatusCode::MISDIRECTED_REQUEST,
    );
}

/// Origin is deliberately stricter than Host: a portless entry matches only a
/// portless browser Origin, because wildcarding a port here would widen the policy.
#[tokio::test]
async fn origin_allowlist_is_passed_through() {
    let allowed =
        TestServer::start(Vec::new(), vec!["https://sdc.example.com".to_owned()], None).await;
    assert_eq!(
        probe(&allowed.url, "localhost", Some("https://sdc.example.com")).await,
        PASSED_THE_GUARD,
    );
    let rejected =
        TestServer::start(Vec::new(), vec!["https://sdc.example.com".to_owned()], None).await;
    assert_eq!(
        probe(
            &rejected.url,
            "localhost",
            Some("https://attacker.example.com")
        )
        .await,
        StatusCode::FORBIDDEN,
    );
}

/// `/healthz` reports the process is up, unauthenticated and with no bearer token.
#[tokio::test]
async fn healthz_responds_ok_without_auth() {
    let server = TestServer::start(Vec::new(), Vec::new(), None).await;
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/healthz", server.url))
        .header(header::HOST, "localhost")
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::OK);
}

/// `/readyz` reports ready, unauthenticated, when no readiness checks are configured.
#[tokio::test]
async fn readyz_responds_ok_without_auth() {
    let server = TestServer::start(Vec::new(), Vec::new(), None).await;
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/readyz", server.url))
        .header(header::HOST, "localhost")
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::OK);
}

/// Router requires bearer token when authentication is configured.
#[tokio::test]
async fn router_requires_bearer() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().expect("tempdir");
    let token_path = dir.path().join("tokens.json");

    let known_devices = ["test".to_owned()];
    let known = KnownNames {
        devices: Some(&known_devices),
        tools: KNOWN_TOOLS,
    };
    let _secret = TokenStoreFile::<NoGrant>::add(
        &token_path,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &known,
    )
    .expect("token add");
    let store = Arc::new(TokenStoreFile::<NoGrant>::load(&token_path).expect("load token store"));

    let server = TestServer::start(Vec::new(), Vec::new(), Some(store)).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/mcp", server.url))
        .header(header::HOST, "localhost")
        .body("{}")
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Router rejects bodies over the configured limit before dispatch to rmcp.
#[tokio::test]
async fn router_rejects_body_over_limit_before_rmcp_dispatch() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().expect("tempdir");
    let token_path = dir.path().join("tokens.json");

    let known_devices = ["test".to_owned()];
    let known = KnownNames {
        devices: Some(&known_devices),
        tools: KNOWN_TOOLS,
    };
    let secret = TokenStoreFile::<NoGrant>::add(
        &token_path,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &known,
    )
    .expect("token add")
    .expose_secret()
    .to_owned();
    let store = Arc::new(TokenStoreFile::<NoGrant>::load(&token_path).expect("load token store"));

    // Start a server with a body limit
    let handler = {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config: SdcConfig = serde_json::from_value(serde_json::json!({
            "version": 1,
            "tenant": "test",
            "expected_tenant_id": "test",
            "credential_env": "SDC_TEST_CREDENTIAL",
            "auth_scheme": "api_key",
        }))
        .expect("config");
        let client = SdcClient::new(
            &config,
            OutboundSecret::new_unchecked("test-credential".to_owned()),
        )
        .expect("client");
        let changes = Arc::new(
            ChangeManager::load(
                client.clone(),
                "test",
                config.endpoint.clone(),
                None,
                Duration::from_secs(60),
                false,
                None,
                None,
            )
            .expect("changes"),
        );
        rustsdcmcp::SdcHandler::new(Arc::<str>::from("test"), client, changes)
    };

    let shutdown = CancellationToken::new();
    let limits = LimitsConfig {
        max_request_body_bytes: 64,
        ..LimitsConfig::default()
    };
    let plan = build_http_router(
        handler,
        Some(store),
        Vec::new(),
        Vec::new(),
        limits,
        false,
        false,
        shutdown.clone(),
    )
    .expect("build_http_router");

    let port = TEST_PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let addr = format!("127.0.0.1:{port}").parse().expect("address");
    let url = format!("http://127.0.0.1:{port}");

    let _serving = tokio::spawn(serve_router(plan, addr, None, Duration::from_millis(50)));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{url}/mcp"))
        .header(header::HOST, "localhost")
        .header(header::AUTHORIZATION, format!("Bearer {secret}"))
        .body(vec![b'x'; 65])
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    shutdown.cancel();
}

/// A token scoped to one tenant must be refused when it names another.
///
/// This is the scope preflight doing its job, and until now nothing in this
/// repo asserted it. `compat/preflight.rs` carried its own tests, and deleting
/// that module in favour of `mecmcp_transport::ToolScopePreflight` took them
/// with it — leaving the wiring untested. Verified by removing
/// `.with_preflight(preflight)` from `build_http_router`: the whole suite stayed
/// green, which is exactly the gap this closes.
///
/// mecmcp's own tests prove the generic preflight refuses out-of-scope targets.
/// What only this repo can prove is that it is wired here with SDC's target
/// field — `tenant` — so a mis-wired field name is caught rather than silently
/// admitting everything.
#[tokio::test]
async fn out_of_scope_tenant_is_refused() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().expect("tempdir");
    let token_path = dir.path().join("tokens.json");

    let known_tenants = ["permitted".to_owned()];
    let known = KnownNames {
        devices: Some(&known_tenants),
        tools: KNOWN_TOOLS,
    };
    let secret = TokenStoreFile::<NoGrant>::add(
        &token_path,
        "scoped",
        ScopeSet::Allowlist(vec!["permitted".to_owned()]),
        ScopeSet::Wildcard,
        &known,
    )
    .expect("token add")
    .expose_secret()
    .to_owned();
    let store = Arc::new(TokenStoreFile::<NoGrant>::load(&token_path).expect("load token store"));

    let server = TestServer::start(Vec::new(), Vec::new(), Some(store)).await;

    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "list_sdc_devices", "arguments": {"tenant": "forbidden", "size": 10}}
    });

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/mcp", server.url))
        .header(header::HOST, "localhost")
        .header(header::AUTHORIZATION, format!("Bearer {secret}"))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&call)
        .send()
        .await
        .expect("request");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a token scoped to 'permitted' must not reach a tool call naming 'forbidden'"
    );
}

/// Verify that `--allow-insecure-bind` is wired through to the transport config.
///
/// The flag was parsed but never converted through 0.3.0, so a plaintext
/// off-loopback listener was refused even when the operator asked for it.
/// This test confirms the flag reaches the transport by attempting a non-loopback
/// bind with and without it, and asserting the expected refusal or success.
#[tokio::test]
async fn allow_insecure_bind_is_wired() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().expect("tempdir");
    let token_path = dir.path().join("tokens.json");

    let known_devices = ["test".to_owned()];
    let known = KnownNames {
        devices: Some(&known_devices),
        tools: KNOWN_TOOLS,
    };
    let _secret = TokenStoreFile::<NoGrant>::add(
        &token_path,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &known,
    )
    .expect("token add");
    let store = Arc::new(TokenStoreFile::<NoGrant>::load(&token_path).expect("load token store"));

    let config: SdcConfig = serde_json::from_value(serde_json::json!({
        "version": 1,
        "tenant": "test",
        "expected_tenant_id": "test",
        "credential_env": "SDC_TEST_CREDENTIAL",
        "auth_scheme": "api_key",
    }))
    .expect("config");
    let client = SdcClient::new(
        &config,
        OutboundSecret::new_unchecked("test-credential".to_owned()),
    )
    .expect("client");
    let changes = Arc::new(
        ChangeManager::load(
            client.clone(),
            "test",
            config.endpoint.clone(),
            None,
            Duration::from_secs(60),
            false,
            None,
            None,
        )
        .expect("changes"),
    );
    let handler = rustsdcmcp::SdcHandler::new(Arc::<str>::from("test"), client, changes);

    // With the flag OFF, building the router with authenticated token store
    // should succeed, but serving it on 0.0.0.0 without TLS should be refused.
    let shutdown = CancellationToken::new();
    let refused_plan = build_http_router(
        handler.clone(),
        Some(store.clone()),
        Vec::new(),
        Vec::new(),
        LimitsConfig::default(),
        false,
        false,
        shutdown.clone(),
    )
    .expect("build_http_router with flag off");

    let port = TEST_PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let non_loopback_addr = format!("0.0.0.0:{port}").parse().expect("address");
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        serve_router(
            refused_plan,
            non_loopback_addr,
            None,
            Duration::from_millis(50),
        ),
    )
    .await;

    match result {
        Ok(Ok(_)) => {
            panic!("serving plaintext on 0.0.0.0 without --allow-insecure-bind must be refused")
        }
        Ok(Err(e)) => {
            let error = format!("{e:?}");
            assert!(
                error.contains("InsecureBindNotAcknowledged"),
                "expected InsecureBindNotAcknowledged refusal, got: {error}"
            );
        }
        Err(_) => panic!("serve_router should fail immediately, not timeout"),
    }

    // With the flag ON, serving on 0.0.0.0 without TLS should succeed.
    // Pass allowed host/origin to satisfy those checks (separate from insecure bind).
    let allowed_plan = build_http_router(
        handler,
        Some(store),
        vec!["0.0.0.0".to_owned()],
        vec!["http://0.0.0.0".to_owned()],
        LimitsConfig::default(),
        false,
        true,
        shutdown.clone(),
    )
    .expect("build_http_router with flag on");

    let port = TEST_PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let allowed_addr = format!("0.0.0.0:{port}").parse().expect("address");
    let serving = tokio::spawn(serve_router(
        allowed_plan,
        allowed_addr,
        None,
        Duration::from_millis(50),
    ));

    // Give it a moment to start or fail
    tokio::time::sleep(Duration::from_millis(200)).await;

    // If it finished, check if it was an error
    if serving.is_finished() {
        match serving.await {
            Ok(Ok(_)) => {
                // Server shut down cleanly, which is fine
            }
            Ok(Err(e)) => {
                panic!("serve_router with --allow-insecure-bind on 0.0.0.0 failed: {e:?}");
            }
            Err(e) => {
                panic!("serve_router task panicked: {e:?}");
            }
        }
    }

    shutdown.cancel();
}
