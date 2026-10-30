//! Product contract tests against the pinned SDC OpenAPI shapes.

use mecmcp_secret::OutboundSecret;
use rustsdcmcp_core::{
    AuthScheme, DeploymentStatus, DeviceDeploymentStatus, JobStatus, ListRequest, PolicyOperation,
    PolicyType, SdcClient, SdcConfig, Target,
};

fn test_config() -> SdcConfig {
    serde_json::from_value(serde_json::json!({
        "version": 1,
        "tenant": "production",
        "expected_tenant_id": "tenant-123",
        "credential_env": "SDC_TOKEN",
        "auth_scheme": "oauth2_token",
        "endpoint": "https://api.sdcloud.juniperclouds.net/"
    }))
    .expect("valid config")
}

#[test]
fn config_names_the_credential_variable_and_carries_no_field_for_its_value() {
    let config = test_config();
    assert_eq!(config.auth_scheme, AuthScheme::Oauth2Token);
    assert_eq!(config.credential_env, "SDC_TOKEN");

    // The config names the variable; the value lives only in the environment.
    let serialized = serde_json::to_string(&config).expect("config serializes");
    assert!(serialized.contains("SDC_TOKEN"));

    // Feed in a key the struct does not declare. Round-tripping the struct's
    // own output would prove nothing here -- serialization can only emit
    // declared fields, so that assertion passes with or without
    // `deny_unknown_fields`. Rejection of injected input is the actual
    // invariant: no key can smuggle a secret into a config file.
    let smuggled = serde_json::json!({
        "version": 1,
        "tenant": "production",
        "expected_tenant_id": "tenant-123",
        "credential_env": "SDC_TOKEN",
        "auth_scheme": "oauth2_token",
        "endpoint": "https://api.sdcloud.juniperclouds.net/",
        "credential": "smuggled-secret-value"
    });
    let rejected = serde_json::from_value::<SdcConfig>(smuggled)
        .expect_err("an undeclared credential field must be refused");
    assert!(
        rejected.to_string().contains("credential"),
        "rejection should name the offending key, got: {rejected}"
    );
}

#[test]
fn a_credential_never_reaches_the_client_debug_representation() {
    // This is the leak that matters: `SdcClient` is held across the handler and
    // change manager, so any Debug/tracing render of it would put a tenant-wide
    // credential into the audit log.
    const SECRET: &str = "sdc-credential-that-must-never-be-rendered";
    let _ = rustls::crypto::ring::default_provider().install_default();

    let client = SdcClient::new(
        &test_config(),
        OutboundSecret::new_unchecked(SECRET.to_owned()),
    )
    .expect("client builds");
    let rendered = format!("{client:?}");
    assert!(
        !rendered.contains(SECRET),
        "credential leaked into SdcClient Debug output: {rendered}"
    );
    assert!(
        rendered.contains("REDACTED"),
        "credential field must render as redacted, got: {rendered}"
    );
}

#[test]
fn page_size_zero_and_oversized_pages_are_refused() {
    assert!(ListRequest::new(0, 0, 200).is_err());
    assert!(ListRequest::new(0, 201, 200).is_err());
    assert_eq!(
        ListRequest::new(40, 20, 200)
            .expect("bounded page")
            .query_pairs(),
        vec![
            ("from".to_owned(), "40".to_owned()),
            ("size".to_owned(), "20".to_owned())
        ]
    );
}

#[test]
fn preview_operation_matches_the_pinned_openapi_shape() {
    let operation = PolicyOperation {
        policy_id: "policy-1".to_owned(),
        policy_type: PolicyType::Firewall,
        deploy_targets: vec![Target::device("device-1")],
        undeploy_targets: Vec::new(),
    };
    assert_eq!(
        serde_json::to_value(operation).expect("operation serializes"),
        serde_json::json!({
            "policy_id": "policy-1",
            "policy_type": "FIREWALL",
            "deploy_targets": [{"target_id": "device-1", "target_type": "DEVICE"}],
            "undeploy_targets": []
        })
    );
}

#[test]
fn an_undocumented_status_is_preserved_rather_than_failing_the_read() {
    // SDC adds states over time. A status this build predates must degrade one
    // classification, not fail every tool that returns a job status.
    let job: JobStatus = serde_json::from_value(serde_json::json!({
        "status": "ROLLBACK_IN_PROGRESS",
        "device_deployment_status": [{
            "device_id": "device-1",
            "status": "DEVICE_STATUS_QUARANTINED",
            "message": ""
        }],
        "message": ""
    }))
    .expect("an unknown status must not fail deserialization");

    assert_eq!(
        job.status,
        DeploymentStatus::Unrecognized("ROLLBACK_IN_PROGRESS".to_owned())
    );
    assert_eq!(
        job.device_deployment_status[0].status,
        DeviceDeploymentStatus::Unrecognized("DEVICE_STATUS_QUARANTINED".to_owned())
    );

    // Never terminal, never successful: polling reports an indeterminate
    // outcome instead of inventing a verdict for a state it cannot classify.
    assert!(!job.status.is_terminal());
    assert!(!job.status.succeeded());

    // The vendor's own string survives into the audit and preview artifacts.
    let round_trip = serde_json::to_value(&job).expect("job serializes");
    assert_eq!(round_trip["status"], "ROLLBACK_IN_PROGRESS");
    assert_eq!(
        round_trip["device_deployment_status"][0]["status"],
        "DEVICE_STATUS_QUARANTINED"
    );
}

#[test]
fn documented_statuses_round_trip_to_their_exact_wire_values() {
    for (status, wire) in [
        (DeploymentStatus::Unknown, "DEPLOY_STATUS_UNKNOWN"),
        (DeploymentStatus::Pending, "PENDING"),
        (DeploymentStatus::InProgress, "IN_PROGRESS"),
        (DeploymentStatus::Completed, "COMPLETED"),
        (DeploymentStatus::PartialSuccess, "PARTIAL_SUCCESS"),
        (DeploymentStatus::Failed, "FAILED"),
    ] {
        assert_eq!(status.as_wire(), wire);
        assert_eq!(
            serde_json::to_value(&status).expect("serializes"),
            serde_json::json!(wire)
        );
        let parsed: DeploymentStatus =
            serde_json::from_value(serde_json::json!(wire)).expect("deserializes");
        assert_eq!(parsed, status);
    }
}

#[test]
fn deployment_status_classifier_uses_only_documented_states() {
    assert!(!DeploymentStatus::Pending.is_terminal());
    assert!(!DeploymentStatus::InProgress.is_terminal());
    assert!(DeploymentStatus::Completed.succeeded());
    assert!(DeploymentStatus::PartialSuccess.is_terminal());
    assert!(!DeploymentStatus::PartialSuccess.succeeded());
    assert!(DeploymentStatus::Failed.is_terminal());
}

#[test]
fn endpoint_must_be_the_exact_sdc_host_without_port() {
    // The correct SDC endpoint
    let valid = serde_json::from_value::<SdcConfig>(serde_json::json!({
        "version": 1,
        "tenant": "test",
        "expected_tenant_id": "tenant-1",
        "credential_env": "SDC_TOKEN",
        "auth_scheme": "api_key",
        "endpoint": "https://api.sdcloud.juniperclouds.net/"
    }))
    .expect("valid test config");
    assert!(valid.validate().is_ok(), "valid endpoint should parse");

    // Wrong host
    let wrong_host = serde_json::from_value::<SdcConfig>(serde_json::json!({
        "version": 1,
        "tenant": "test",
        "expected_tenant_id": "tenant-1",
        "credential_env": "SDC_TOKEN",
        "auth_scheme": "api_key",
        "endpoint": "https://other.host.com/"
    }))
    .expect("wrong host test config");
    assert!(
        wrong_host.validate().is_err(),
        "wrong host should be rejected"
    );

    // Non-default port
    let wrong_port = serde_json::from_value::<SdcConfig>(serde_json::json!({
        "version": 1,
        "tenant": "test",
        "expected_tenant_id": "tenant-1",
        "credential_env": "SDC_TOKEN",
        "auth_scheme": "api_key",
        "endpoint": "https://api.sdcloud.juniperclouds.net:8443/"
    }))
    .expect("wrong port test config");
    assert!(
        wrong_port.validate().is_err(),
        "non-default port should be rejected"
    );
}

#[test]
fn egress_proxy_is_unset_by_default_and_validated_when_configured() {
    let unset = test_config();
    assert_eq!(unset.egress_proxy, None);
    assert!(unset.validate().is_ok());

    let mut with_proxy = test_config();
    with_proxy.egress_proxy = Some("http://proxy.example.internal:3128".to_owned());
    assert!(
        with_proxy.validate().is_ok(),
        "a plain http(s) proxy URL with a host must be accepted"
    );

    // The SDC endpoint itself stays fixed; the proxy setting only routes
    // outbound connections through an intermediary, so no scheme other than
    // http/https and no missing host is accepted.
    for invalid in [
        "not a url",
        "socks5://proxy.example.internal:1080",
        "ftp://proxy.example.internal",
    ] {
        let mut bad_proxy = test_config();
        bad_proxy.egress_proxy = Some(invalid.to_owned());
        assert!(
            bad_proxy.validate().is_err(),
            "{invalid} should be rejected as an egress proxy"
        );
    }
}

#[test]
fn config_debug_prints_only_the_egress_proxy_origin() {
    // Built with setters so no credential-shaped literal trips secret scanners.
    let mut proxy =
        url::Url::parse("http://proxy.example.internal:3128/p?token=q").expect("valid URL");
    proxy
        .set_username("proxyuser")
        .expect("http URL takes userinfo");
    proxy
        .set_password(Some("s3cret"))
        .expect("http URL takes userinfo");
    let mut config = test_config();
    config.egress_proxy = Some(proxy.into());
    let printed = format!("{config:?}");
    assert!(printed.contains("\"http://proxy.example.internal:3128\""));
    for secret in ["proxyuser", "s3cret", "token"] {
        assert!(!printed.contains(secret), "{secret} leaked: {printed}");
    }

    // An unparsable value is withheld whole: it may still hold credentials.
    config.egress_proxy = Some("s3cret is not a url".to_owned());
    let printed = format!("{config:?}");
    assert!(printed.contains("<unparsable>") && !printed.contains("s3cret"));
}
