//! Regression test for rustsdcmcp#217: a `server/discover` probe sent before
//! `initialize` must not poison the rest of the session.
//!
//! Before rmcp 3.5.1, the stdio session latched `request_metadata_required`
//! on any client that opened with `server/discover`, and never cleared it even
//! after the client fell back to the classic (`initialize`-negotiated)
//! lifecycle. Every later request without `_meta` -- including a completely
//! ordinary `tools/list` -- was then rejected with -32602 "request _meta is
//! missing or has malformed required fields", so the client loaded zero
//! tools. Upstream fix: modelcontextprotocol/rust-sdk#1248.
//!
//! This test drives the exact wire sequence from the issue's repro over an
//! in-memory stdio-shaped transport: `server/discover` (with the 2026-07-28
//! draft's required `_meta`) -> `initialize` (protocolVersion 2025-11-25) ->
//! `notifications/initialized` -> `tools/list` with no `_meta` at all.

use rmcp::ServiceExt as _;
use rustsdcmcp::{KNOWN_TOOLS, SdcHandler};
use rustsdcmcp_core::{ChangeManager, SdcClient, SdcConfig};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;

async fn write_line(write: &mut (impl AsyncWrite + Unpin), value: Value) {
    let mut bytes = serde_json::to_vec(&value).expect("serialize JSON-RPC message");
    bytes.push(b'\n');
    write
        .write_all(&bytes)
        .await
        .expect("write JSON-RPC message");
    write.flush().await.expect("flush JSON-RPC message");
}

async fn read_line(reader: &mut (impl AsyncBufRead + Unpin)) -> Value {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .expect("read JSON-RPC message");
    serde_json::from_str(line.trim_end()).expect("parse JSON-RPC message")
}

fn test_handler() -> SdcHandler {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config: SdcConfig = serde_json::from_value(json!({
        "version": 1,
        "tenant": "test",
        "expected_tenant_id": "test",
        "credential_env": "SDC_TEST_CREDENTIAL",
        "auth_scheme": "api_key",
    }))
    .expect("config");
    let client = SdcClient::new(
        &config,
        mecmcp_secret::OutboundSecret::new_unchecked("test-credential".to_owned()),
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
    SdcHandler::new(Arc::<str>::from("test"), client, changes)
}

#[tokio::test]
async fn discover_before_initialize_does_not_poison_tools_list() {
    let handler = test_handler();
    let (server_stream, client_stream) = tokio::io::duplex(64 * 1024);
    let shutdown = CancellationToken::new();

    let serve_shutdown = shutdown.clone();
    let serving = tokio::spawn(async move {
        if let Ok(service) = handler.serve_with_ct(server_stream, serve_shutdown).await {
            let _ = service.waiting().await;
        }
    });

    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let mut client_read = BufReader::new(client_read);

    // 1. `server/discover`, carrying the 2026-07-28 draft's required `_meta`
    //    keys -- the exact probe Claude Code (and similar clients) send
    //    before deciding whether to use the modern or classic lifecycle.
    write_line(
        &mut client_write,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        }),
    )
    .await;
    let discover_response = read_line(&mut client_read).await;
    assert!(
        discover_response.get("error").is_none(),
        "server/discover should succeed: {discover_response:?}"
    );

    // 2. Classic `initialize` negotiating 2025-11-25, with no `_meta`.
    write_line(
        &mut client_write,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "mec-2045-regression-client", "version": "0.0.0"},
            },
        }),
    )
    .await;
    let initialize_response = read_line(&mut client_read).await;
    assert!(
        initialize_response.get("error").is_none(),
        "initialize should succeed: {initialize_response:?}"
    );

    // 3. `notifications/initialized` -- no response expected.
    write_line(
        &mut client_write,
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }),
    )
    .await;

    // 4. `tools/list` with no `_meta` at all: the shape any classic client
    //    sends, and the one the pre-3.5.1 rmcp pin rejected with -32602
    //    because `server/discover` had permanently required it.
    write_line(
        &mut client_write,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
        }),
    )
    .await;
    let tools_response = read_line(&mut client_read).await;
    assert!(
        tools_response.get("error").is_none(),
        "tools/list with no _meta must succeed under the classic lifecycle, got: {tools_response:?}"
    );

    let returned_tools: BTreeSet<String> = tools_response["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name").to_owned())
        .collect();
    let expected_tools: BTreeSet<String> =
        KNOWN_TOOLS.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(
        returned_tools, expected_tools,
        "tools/list must return every known tool"
    );

    shutdown.cancel();
    drop(client_write);
    drop(client_read);
    let _ = serving.await;
}
