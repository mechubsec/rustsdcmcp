//! Bounded SDC HTTPS client.
//!
//! The product-specific implementation here is intentionally isolated while
//! its reusable foundations are tracked in mecmcp issue #90.

use crate::{
    DeployRequest, DeploymentStatus, DeviceConfigSection, ImageJob, JobStatus, ListRequest,
    ListRequestError, PolicyOperation, PreviewRequest, ResourceKind, SdcConfig, SdcPreparedChange,
    SdcPreparedTarget, TenantScope, WritableResource,
    models::{DeployResponse, PreviewResponse},
};
use futures::StreamExt as _;
use mecmcp_secret::OutboundSecret;
use reqwest::{Method, StatusCode, header::HeaderValue};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::Semaphore,
    time::{self, Instant},
};
use tokio_util::sync::CancellationToken;
use url::Url;

/// Additional `GET` attempts allowed after a rate-limited or overloaded
/// response, on top of the first attempt.
const MAX_RETRY_ATTEMPTS: u32 = 3;

/// Upper bound on any single retry delay, regardless of what SDC's
/// `Retry-After` header requests. Protects against an unreasonable or
/// hostile value stalling a caller far past the whole-request deadline.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// Backoff used for a retryable status with no usable `Retry-After` header.
const BASE_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Outcome of one wire attempt: status, an optional retry hint, and the body
/// read (or the reason it could not be read).
struct SendOutcome {
    status: StatusCode,
    retry_after: Option<Duration>,
    body: Result<Vec<u8>, SdcError>,
}

/// Delay before the next retry attempt.
///
/// Honours a server-provided `Retry-After`, capped so a hostile or
/// unreasonable value cannot stall a caller far past the whole-request
/// deadline; falls back to capped exponential backoff otherwise. Either way
/// a small jitter is added so concurrent callers rate-limited at the same
/// moment do not retry in lockstep.
fn retry_delay(retry_after: Option<Duration>, attempt: u32) -> Duration {
    let base = retry_after.unwrap_or_else(|| {
        BASE_RETRY_DELAY.saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX))
    });
    let capped = base.min(MAX_RETRY_DELAY);
    let jitter_bound_ms = u64::try_from(capped.as_millis() / 4)
        .unwrap_or(u64::MAX)
        .max(1);
    let jitter_ms = jitter_nanos() % jitter_bound_ms;
    capped + Duration::from_millis(jitter_ms)
}

/// Cheap, non-cryptographic entropy source for retry jitter.
///
/// This only needs to desynchronize concurrent retries, not resist
/// prediction, so wall-clock sub-second precision is sufficient and avoids
/// adding an RNG dependency.
fn jitter_nanos() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::from(elapsed.subsec_nanos()))
        .unwrap_or_default()
}

/// Cloneable, bounded client for one SDC tenant.
#[derive(Clone)]
pub struct SdcClient {
    http: reqwest::Client,
    base_url: Url,
    credential: Arc<OutboundSecret>,
    auth_scheme: crate::AuthScheme,
    request_timeout: Duration,
    max_response_bytes: usize,
    concurrency: Arc<Semaphore>,
    poll: crate::config::PollSettings,
    max_page_size: u32,
    list_page_budget_bytes: usize,
    shutdown: CancellationToken,
}

impl std::fmt::Debug for SdcClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SdcClient")
            .field("base_url", &self.base_url)
            .field("credential", &"OutboundSecret([REDACTED])")
            .field("auth_scheme", &self.auth_scheme)
            .field("request_timeout", &self.request_timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_page_size", &self.max_page_size)
            .finish_non_exhaustive()
    }
}

impl SdcClient {
    /// Build a production HTTPS-only client from a separately resolved credential.
    ///
    /// The consuming binary must install a rustls crypto provider first.
    ///
    /// # Errors
    ///
    /// Returns stable, credential-free configuration or client-construction errors.
    pub fn new(config: &SdcConfig, credential: OutboundSecret) -> Result<Self, SdcError> {
        config
            .validate()
            .map_err(|error| SdcError::Config(error.to_string()))?;
        if credential.expose().is_empty() || credential.expose().len() > 16 * 1024 {
            return Err(SdcError::Credential);
        }
        let egress_proxy = config
            .egress_proxy_url()
            .map_err(|error| SdcError::Config(error.to_string()))?;
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
            .pool_idle_timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(config.max_concurrency)
            .user_agent(format!("rustsdcmcp/{}", env!("CARGO_PKG_VERSION")));
        builder = match egress_proxy {
            // Operator opted into one explicit proxy; environment variables
            // still never redirect traffic.
            Some(proxy_url) => builder
                .proxy(reqwest::Proxy::all(proxy_url).map_err(|_| SdcError::ClientConstruction)?),
            None => builder.no_proxy(),
        };
        let http = builder.build().map_err(|_| SdcError::ClientConstruction)?;
        Self::from_parts(config, credential, http)
    }

    fn from_parts(
        config: &SdcConfig,
        credential: OutboundSecret,
        http: reqwest::Client,
    ) -> Result<Self, SdcError> {
        Ok(Self {
            http,
            base_url: config
                .base_url()
                .map_err(|error| SdcError::Config(error.to_string()))?,
            credential: Arc::new(credential),
            auth_scheme: config.auth_scheme,
            request_timeout: Duration::from_millis(config.request_timeout_ms),
            max_response_bytes: config.max_response_bytes,
            concurrency: Arc::new(Semaphore::new(config.max_concurrency)),
            poll: config
                .poll_settings()
                .map_err(|error| SdcError::Config(error.to_string()))?,
            max_page_size: config.max_page_size,
            list_page_budget_bytes: config.list_page_budget_bytes,
            shutdown: CancellationToken::new(),
        })
    }

    /// Bind this client to a process-wide shutdown signal.
    ///
    /// Every request and job poll then aborts when the process begins shutting
    /// down, instead of holding a listener drain open for the remainder of
    /// `poll_deadline_ms`. A client built without one carries a token that is
    /// never cancelled.
    #[must_use]
    pub fn with_shutdown(mut self, shutdown: CancellationToken) -> Self {
        self.shutdown = shutdown;
        self
    }

    /// Build a non-TLS client wired to a caller-chosen `base_url`, for tests
    /// that stand up a mock HTTP server rather than calling a real tenant.
    ///
    /// Gated behind `test-support` (on unconditionally for this crate's own
    /// `#[cfg(test)]`) so the non-TLS, unchecked-credential path this takes
    /// can never reach a production binary.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_test_parts(
        base_url: &str,
        credential: String,
        max_response_bytes: usize,
        max_page_size: u32,
    ) -> Self {
        let config = SdcConfig {
            version: 1,
            tenant: "test".to_owned(),
            expected_tenant_id: "tenant-test".to_owned(),
            credential_env: "TEST_SDC_TOKEN".to_owned(),
            auth_scheme: crate::AuthScheme::ApiKey,
            endpoint: "https://api.sdcloud.juniperclouds.net/".to_owned(),
            connect_timeout_ms: 1_000,
            request_timeout_ms: 2_000,
            max_response_bytes,
            max_concurrency: 2,
            max_page_size,
            list_page_budget_bytes: 131_072,
            poll_initial_ms: 1,
            poll_max_ms: 2,
            poll_deadline_ms: 50,
            changeset_state_file: None,
            approval_ttl_secs: 60,
            egress_proxy: None,
        };
        let mut client = Self::from_parts(
            &config,
            OutboundSecret::new_unchecked(credential),
            reqwest::Client::new(),
        )
        .expect("test client");
        client.base_url = Url::parse(base_url).expect("test base url");
        client
    }

    /// Maximum page size allowed by this tenant configuration.
    #[must_use]
    pub const fn max_page_size(&self) -> u32 {
        self.max_page_size
    }

    /// Byte budget for one page of a budget-paginated list result.
    #[must_use]
    pub const fn list_page_budget_bytes(&self) -> usize {
        self.list_page_budget_bytes
    }

    /// Fetch the credential tenant scope.
    pub async fn tenant_scope(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<TenantScope, SdcError> {
        self.get(&["api", "v2", "tenant", "tenant-id"], &[], cancellation)
            .await
    }

    /// Verify that a credential resolves to the configured tenant ID.
    pub async fn verify_tenant(
        &self,
        expected_tenant_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<TenantScope, SdcError> {
        let scope = self.tenant_scope(cancellation).await?;
        if scope.tenant_id != expected_tenant_id {
            return Err(SdcError::TenantMismatch);
        }
        Ok(scope)
    }

    /// List managed devices with bounded pagination.
    pub async fn list_devices(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(&["api", "v1", "devices"], page, cancellation)
            .await
    }

    /// Create a new firewall policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the body is not a bounded JSON object, or when
    /// the SDC request fails.
    pub async fn create_firewall_policy(
        &self,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_object_body(body)?;
        self.send_write(
            Method::POST,
            &["api", "v1", "policies", "firewall"],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Replace an existing firewall policy by UUID.
    ///
    /// # Errors
    ///
    /// Returns an error when the UUID or body is invalid, or when the SDC
    /// request fails.
    pub async fn update_firewall_policy(
        &self,
        uuid: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("uuid", uuid)?;
        validate_object_body(body)?;
        self.send_write(
            Method::PUT,
            &["api", "v1", "policies", "firewall", uuid],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Delete an existing firewall policy by UUID.
    ///
    /// # Errors
    ///
    /// Returns an error when the UUID is invalid or when the SDC request
    /// fails.
    pub async fn delete_firewall_policy(
        &self,
        uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("uuid", uuid)?;
        self.send_write(
            Method::DELETE,
            &["api", "v1", "policies", "firewall", uuid],
            None,
            cancellation,
        )
        .await
    }

    /// Fetch the operational state of a firewall policy by UUID.
    ///
    /// Returns policy deployment state and optionally per-device states when
    /// `include_assigned_devices` is true.
    pub async fn get_firewall_policy_state(
        &self,
        policy_uuid: &str,
        include_assigned_devices: bool,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_uuid", policy_uuid)?;
        let query = if include_assigned_devices {
            vec![("include_assigned_devices", "true")]
        } else {
            vec![]
        };
        self.get(
            &["api", "v1", "policies", "firewall", policy_uuid, "state"],
            &query,
            cancellation,
        )
        .await
    }

    /// List NAT pools with bounded pagination.
    pub async fn list_nat_pools(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(&["api", "v1", "nat_pools"], page, cancellation)
            .await
    }

    /// List device groups with bounded pagination and an optional projection.
    ///
    /// A group embeds its membership, so `size` alone does not bound the
    /// response: one large group can exceed `max_response_bytes` and refuse
    /// the read. Pass `fields` to project the response down to group metadata
    /// and use [`Self::get_device_group`] when membership is actually wanted.
    ///
    /// The field names are the API's, not this crate's, and no default
    /// projection is applied: guessing them would silently drop data. The lab
    /// tenant has no groups, so none has been observed to hard-code.
    pub async fn list_device_groups(
        &self,
        page: ListRequest,
        fields: &[String],
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list_projected(&["api", "v1", "device_groups"], page, fields, cancellation)
            .await
    }

    /// Fetch one device group by UUID, including its membership.
    pub async fn get_device_group(
        &self,
        group_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("group_uuid", group_uuid)?;
        self.get(
            &["api", "v1", "device_groups", group_uuid],
            &[],
            cancellation,
        )
        .await
    }

    /// Fetch one NAT pool by ID.
    ///
    /// NAT resources use a numeric-string `id`, not the UUID the firewall side
    /// uses — see docs/sdc-api/README.md.
    pub async fn get_nat_pool(
        &self,
        pool_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("pool_id", pool_id)?;
        self.get(&["api", "v1", "nat_pools", pool_id], &[], cancellation)
            .await
    }

    /// Fetch one managed device by UUID.
    pub async fn get_device(
        &self,
        device_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        self.get(&["api", "v1", "devices", device_uuid], &[], cancellation)
            .await
    }

    /// List configuration versions for one device.
    ///
    /// Returns the standard `{"items": [...], "count": N}` envelope with archived
    /// configuration metadata. The endpoint declares no pagination parameters, so
    /// the response is bounded only by `max_response_bytes`. A device with a long
    /// archive may exceed that limit and fail the read.
    pub async fn list_config_versions(
        &self,
        device_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        self.get(
            &["api", "v1", "devices", device_uuid, "config", "versions"],
            &[],
            cancellation,
        )
        .await
    }

    /// List one section of a device's configuration as SDC models it.
    ///
    /// `interface_name` narrows `Subinterfaces` to one parent interface and is
    /// refused for any other section rather than silently ignored. The API
    /// expects underscores in place of forward slashes in the interface name
    /// path segment (per `GetDeviceInterfaceSubinterfaces` in the spec).
    pub async fn list_device_config(
        &self,
        device_uuid: &str,
        section: DeviceConfigSection,
        interface_name: Option<&str>,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        let Some(interface_name) = interface_name else {
            return self
                .list(
                    &[
                        "api",
                        "v1",
                        "devices",
                        device_uuid,
                        "config",
                        section.segment(),
                    ],
                    page,
                    cancellation,
                )
                .await;
        };
        if section != DeviceConfigSection::Subinterfaces {
            return Err(SdcError::InvalidInput(
                "interface_name is only valid with section=subinterfaces",
            ));
        }
        validate_atom("interface_name", interface_name)?;
        let interface_segment = interface_name.replace('/', "_");
        self.list(
            &[
                "api",
                "v1",
                "devices",
                device_uuid,
                "config",
                "interfaces",
                &interface_segment,
                "subinterfaces",
            ],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch the configuration revision status for one device.
    pub async fn get_device_config_revision(
        &self,
        device_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        self.get(
            &[
                "api",
                "v1",
                "devices",
                device_uuid,
                "config",
                "latest_version",
            ],
            &[],
            cancellation,
        )
        .await
    }

    /// List device software image definitions with bounded pagination.
    pub async fn list_image_definitions(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(
            &["api", "v1", "device_image_definitions"],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch the status of one image stage or deploy job.
    pub async fn get_image_job_status(
        &self,
        job: ImageJob,
        job_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("job_id", job_id)?;
        self.get(
            &[
                "api",
                "v1",
                "device_image_definitions",
                job.segment(),
                job_id,
            ],
            &[],
            cancellation,
        )
        .await
    }

    /// Fetch the status of one MNHA cluster sync job.
    pub async fn get_mnha_sync_status(
        &self,
        mnha_sync_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("mnha_sync_id", mnha_sync_id)?;
        self.get(
            &["api", "v1", "mnha_clusters", "sync", mnha_sync_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Fetch the RMA state of one device.
    ///
    /// The sibling `rma/reactivation_config` endpoint is deliberately not
    /// wrapped: it returns a full bootstrap configuration.
    pub async fn get_rma_state(
        &self,
        device_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_id", device_id)?;
        self.get(
            &["api", "v1", "devices", device_id, "rma", "state"],
            &[],
            cancellation,
        )
        .await
    }

    /// Fetch the status of one RMA reactivation job.
    pub async fn get_rma_reactivation_status(
        &self,
        reactivation_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("reactivation_id", reactivation_id)?;
        self.get(
            &["api", "v1", "devices", "rma", "reactivate", reactivation_id],
            &[],
            cancellation,
        )
        .await
    }

    /// List firewall policies with bounded pagination.
    pub async fn list_firewall_policies(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(&["api", "v1", "policies", "firewall"], page, cancellation)
            .await
    }

    /// Fetch one firewall policy by UUID.
    pub async fn get_firewall_policy(
        &self,
        policy_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_uuid", policy_uuid)?;
        self.get(
            &["api", "v1", "policies", "firewall", policy_uuid],
            &[],
            cancellation,
        )
        .await
    }

    /// List NAT policies with bounded pagination.
    pub async fn list_nat_policies(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(&["api", "v1", "policies", "nat"], page, cancellation)
            .await
    }

    /// Fetch one NAT policy by ID.
    pub async fn get_nat_policy(
        &self,
        id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("id", id)?;
        self.get(&["api", "v1", "policies", "nat", id], &[], cancellation)
            .await
    }

    /// List firewall policy rules with bounded pagination.
    ///
    /// `scope` must be `"global"` or `"zone"`.
    pub async fn list_firewall_rules(
        &self,
        policy_uuid: &str,
        scope: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_uuid", policy_uuid)?;
        validate_atom("scope", scope)?;
        self.list(
            &[
                "api",
                "v1",
                "policies",
                "firewall",
                policy_uuid,
                scope,
                "rules",
            ],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch one firewall policy rule by UUID.
    ///
    /// `scope` must be `"global"` or `"zone"`.
    pub async fn get_firewall_rule(
        &self,
        policy_uuid: &str,
        scope: &str,
        rule_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_uuid", policy_uuid)?;
        validate_atom("scope", scope)?;
        validate_atom("rule_uuid", rule_uuid)?;
        self.get(
            &[
                "api",
                "v1",
                "policies",
                "firewall",
                policy_uuid,
                scope,
                "rules",
                rule_uuid,
            ],
            &[],
            cancellation,
        )
        .await
    }

    /// List firewall policy rule groups with bounded pagination.
    ///
    /// `scope` must be `"global"` or `"zone"`.
    pub async fn list_firewall_rule_groups(
        &self,
        policy_uuid: &str,
        scope: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_uuid", policy_uuid)?;
        validate_atom("scope", scope)?;
        self.list(
            &[
                "api",
                "v1",
                "policies",
                "firewall",
                policy_uuid,
                scope,
                "rule_groups",
            ],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch firewall policy rule hierarchy.
    ///
    /// `scope` must be `"global"` or `"zone"`.
    ///
    /// Note: The spec misspells this path segment as `heirarchy`.
    pub async fn get_firewall_hierarchy(
        &self,
        policy_uuid: &str,
        scope: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_uuid", policy_uuid)?;
        validate_atom("scope", scope)?;
        self.get(
            &[
                "api",
                "v1",
                "policies",
                "firewall",
                policy_uuid,
                scope,
                "heirarchy",
            ],
            &[],
            cancellation,
        )
        .await
    }

    /// List NAT policy rules with bounded pagination.
    pub async fn list_nat_rules(
        &self,
        policy_id: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        self.list(
            &["api", "v1", "policies", "nat", policy_id, "rules"],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch one NAT policy rule by ID.
    pub async fn get_nat_rule(
        &self,
        policy_id: &str,
        rule_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_atom("rule_id", rule_id)?;
        self.get(
            &["api", "v1", "policies", "nat", policy_id, "rules", rule_id],
            &[],
            cancellation,
        )
        .await
    }

    /// List NAT policy rule groups with bounded pagination.
    pub async fn list_nat_rule_groups(
        &self,
        policy_id: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        self.list(
            &["api", "v1", "policies", "nat", policy_id, "rule_groups"],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch one NAT policy rule group by ID.
    pub async fn get_nat_rule_group(
        &self,
        policy_id: &str,
        group_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_atom("group_id", group_id)?;
        self.get(
            &[
                "api",
                "v1",
                "policies",
                "nat",
                policy_id,
                "rule_groups",
                group_id,
            ],
            &[],
            cancellation,
        )
        .await
    }

    /// Fetch NAT policy rule hierarchy.
    ///
    /// Note: Unlike firewall policies, NAT uses the correctly-spelled `hierarchy`.
    pub async fn get_nat_hierarchy(
        &self,
        policy_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        self.get(
            &["api", "v1", "policies", "nat", policy_id, "hierarchy"],
            &[],
            cancellation,
        )
        .await
    }

    /// List one allowlisted generic resource family.
    ///
    /// `size` bounds how many objects come back, not how large each one is,
    /// and profile families embed rule and pattern lists. Pass `fields` to
    /// apply the API's server-side projection; pass an empty slice to omit the
    /// parameter entirely. No default projection is invented — field names
    /// belong to the API, and guessing them silently drops data.
    pub async fn list_resource(
        &self,
        kind: ResourceKind,
        page: ListRequest,
        fields: &[String],
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list_projected(kind.collection_segments(), page, fields, cancellation)
            .await
    }

    /// Fetch one allowlisted generic resource by UUID.
    pub async fn get_resource(
        &self,
        kind: ResourceKind,
        uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("uuid", uuid)?;
        let mut segments = kind.collection_segments().to_vec();
        segments.push(uuid);
        self.get(&segments, &[], cancellation).await
    }

    /// List the IPS rules of one IPS profile with bounded pagination.
    pub async fn list_ips_rules(
        &self,
        profile_uuid: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("profile_uuid", profile_uuid)?;
        self.list(
            &["api", "v1", "ips_profiles", profile_uuid, "ips_rules"],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch one IPS rule of one IPS profile.
    pub async fn get_ips_rule(
        &self,
        profile_uuid: &str,
        rule_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("profile_uuid", profile_uuid)?;
        validate_atom("rule_uuid", rule_uuid)?;
        self.get(
            &[
                "api",
                "v1",
                "ips_profiles",
                profile_uuid,
                "ips_rules",
                rule_uuid,
            ],
            &[],
            cancellation,
        )
        .await
    }

    /// List the exempt rules of one IPS profile with bounded pagination.
    pub async fn list_ips_exempt_rules(
        &self,
        profile_uuid: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("profile_uuid", profile_uuid)?;
        self.list(
            &["api", "v1", "ips_profiles", profile_uuid, "exempt_rules"],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch one exempt rule of one IPS profile.
    pub async fn get_ips_exempt_rule(
        &self,
        profile_uuid: &str,
        rule_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("profile_uuid", profile_uuid)?;
        validate_atom("rule_uuid", rule_uuid)?;
        self.get(
            &[
                "api",
                "v1",
                "ips_profiles",
                profile_uuid,
                "exempt_rules",
                rule_uuid,
            ],
            &[],
            cancellation,
        )
        .await
    }

    /// List the rule sets of one enhanced content-filtering profile.
    pub async fn list_ecf_rule_sets(
        &self,
        profile_uuid: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("profile_uuid", profile_uuid)?;
        self.list(
            &[
                "api",
                "v1",
                "enhanced_content_filtering_profiles",
                profile_uuid,
                "rule_sets",
            ],
            page,
            cancellation,
        )
        .await
    }

    /// List the rules of one rule set of one enhanced content-filtering profile.
    pub async fn list_ecf_rules(
        &self,
        profile_uuid: &str,
        rule_set_uuid: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("profile_uuid", profile_uuid)?;
        validate_atom("rule_set_uuid", rule_set_uuid)?;
        self.list(
            &[
                "api",
                "v1",
                "enhanced_content_filtering_profiles",
                profile_uuid,
                "rule_sets",
                rule_set_uuid,
                "rules",
            ],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch the tenant's firewall global settings (a singleton).
    ///
    /// No pagination exists; the response is bounded by `max_response_bytes`
    /// and refused, never truncated, above it.
    pub async fn get_firewall_global_settings(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.get(
            &["api", "v1", "firewall_global_settings"],
            &[],
            cancellation,
        )
        .await
    }

    /// Fetch the tenant's firewall global profile (a singleton).
    pub async fn get_firewall_global_profile(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.get(
            &["api", "v1", "firewall_global_profiles"],
            &[],
            cancellation,
        )
        .await
    }

    /// Fetch the tenant's content-security settings (a singleton).
    pub async fn get_content_security_settings(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.get(
            &["api", "v1", "content_security_settings"],
            &[],
            cancellation,
        )
        .await
    }

    /// List per-device firewall global settings.
    ///
    /// Unlike the rest of `/api/v1/`, this endpoint pages with `offset` and
    /// `limit`. `device_id` narrows to one device when given.
    pub async fn list_device_global_settings(
        &self,
        device_id: Option<&str>,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        let page = ListRequest::new(page.from, page.size, self.max_page_size)?;
        let offset = page.from.to_string();
        let limit = page.size.to_string();
        let mut query = vec![("offset", offset.as_str()), ("limit", limit.as_str())];
        if let Some(device_id) = device_id {
            validate_atom("device_id", device_id)?;
            query.push(("device_id", device_id));
        }
        self.get(
            &["api", "v1", "firewall_device_global_settings"],
            &query,
            cancellation,
        )
        .await
    }

    /// List tenant users with bounded pagination (`ListUsers`, `/api/v2/`).
    ///
    /// CLAUDE.md's IAM decision (see the decision log) reopens exactly
    /// `ListUsers`/`GetUser`/`ListRoles`/`GetRole` for read-only, metadata-only
    /// access; the other five IAM operations (`CreateUser`, `EditUser`,
    /// `DeleteUser`, `ChangePassword`, `SendActivateUserEmail`) stay excluded.
    /// SDC's `ListUsers` response has no `created`/`created_by` field — only
    /// `user_id`, `email`, `name`, `status`, `last_login`, and `role[].role_name`.
    /// It carries no key or secret material at all; there is no API-key
    /// concept anywhere in this surface.
    pub async fn list_users(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list_v2(&["api", "v2", "users"], page, cancellation)
            .await
    }

    /// List tenant roles with bounded pagination (`ListRoles`, `/api/v2/`).
    ///
    /// Each role carries `UUID`, `name`, `capabilities`, and `predefined` —
    /// no timestamp field of any kind, and no key or secret material.
    pub async fn list_roles(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list_v2(&["api", "v2", "roles"], page, cancellation)
            .await
    }

    /// Combined read of [`Self::list_users`] and [`Self::list_roles`] for the
    /// `list_users_and_roles` tool.
    ///
    /// Fails closed: if either call errors, the whole call errors rather than
    /// returning a partial users-only or roles-only result labeled as
    /// complete.
    pub async fn list_users_and_roles(
        &self,
        users_page: ListRequest,
        roles_page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        let users = self.list_users(users_page, cancellation).await?;
        let roles = self.list_roles(roles_page, cancellation).await?;
        Ok(serde_json::json!({ "users": users, "roles": roles }))
    }

    /// Create one object in an allowlisted generic resource family.
    ///
    /// Takes [`WritableResource`], not [`ResourceKind`]: adding a family to the
    /// read catalog must not make it writable.
    ///
    /// # Errors
    ///
    /// Returns an error when the body is not a bounded JSON object, or when
    /// the SDC request fails.
    pub async fn create_resource(
        &self,
        kind: WritableResource,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_object_body(body)?;
        self.send_write(
            Method::POST,
            kind.collection_segments(),
            Some(body),
            cancellation,
        )
        .await
    }

    /// Replace one object in an allowlisted generic resource family.
    ///
    /// Takes [`WritableResource`], not [`ResourceKind`]: adding a family to the
    /// read catalog must not make it writable.
    ///
    /// # Errors
    ///
    /// Returns an error when the UUID or body is invalid, or when the SDC
    /// request fails.
    pub async fn update_resource(
        &self,
        kind: WritableResource,
        uuid: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("uuid", uuid)?;
        validate_object_body(body)?;
        let mut segments = kind.collection_segments().to_vec();
        segments.push(uuid);
        self.send_write(Method::PUT, &segments, Some(body), cancellation)
            .await
    }

    /// Delete one object from an allowlisted generic resource family.
    ///
    /// Takes [`WritableResource`], not [`ResourceKind`]: adding a family to the
    /// read catalog must not make it writable.
    ///
    /// # Errors
    ///
    /// Returns an error when the UUID is invalid or when the SDC request
    /// fails. SDC rejects deleting an object that a policy still references.
    pub async fn delete_resource(
        &self,
        kind: WritableResource,
        uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("uuid", uuid)?;
        let mut segments = kind.collection_segments().to_vec();
        segments.push(uuid);
        self.send_write(Method::DELETE, &segments, None, cancellation)
            .await
    }

    /// List IPsec profiles with bounded pagination.
    ///
    /// This is a `/api/v2/` endpoint, unlike most policy and device operations.
    pub async fn list_ipsec_profiles(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(&["api", "v2", "ipsec-profiles"], page, cancellation)
            .await
    }

    /// Fetch one IPsec profile by name.
    ///
    /// IPsec profiles are addressed by `profile_name`, not UUID or numeric ID.
    /// This is a `/api/v2/` endpoint.
    pub async fn get_ipsec_profile(
        &self,
        profile_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("profile_name", profile_name)?;
        self.get(
            &["api", "v2", "ipsec-profile", profile_name],
            &[],
            cancellation,
        )
        .await
    }

    /// List tunnels with bounded pagination.
    ///
    /// This is a `/api/v2/` endpoint. Tunnels are read-only derived state,
    /// not directly created or deleted.
    pub async fn list_tunnels(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list_v2(&["api", "v2", "tunnels"], page, cancellation)
            .await
    }

    /// Fetch one tunnel by ID.
    ///
    /// This is a `/api/v2/` endpoint.
    pub async fn get_tunnel(
        &self,
        tunnel_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("tunnel_id", tunnel_id)?;
        self.get(&["api", "v2", "tunnel", tunnel_id], &[], cancellation)
            .await
    }

    /// Get tunnel status count.
    ///
    /// This is a `/api/v2/` endpoint.
    pub async fn tunnel_count(&self, cancellation: &CancellationToken) -> Result<Value, SdcError> {
        self.get(
            &["api", "v2", "tunnels", "status", "count"],
            &[],
            cancellation,
        )
        .await
    }

    /// List sites with bounded pagination (`/api/v2/`, `spec.from`/`spec.size`).
    ///
    /// Site objects embed CPE interfaces carrying IKE pre-shared keys. The
    /// client returns them verbatim; the tool boundary redacts.
    pub async fn list_sites(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list_v2(&["api", "v2", "sites"], page, cancellation)
            .await
    }

    /// Fetch one site by name (`/api/v2/site/{site_name}`).
    pub async fn get_site(
        &self,
        site_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("site_name", site_name)?;
        self.get(&["api", "v2", "site", site_name], &[], cancellation)
            .await
    }

    /// List CA certificates across all devices with bounded pagination.
    pub async fn list_ca_certificates(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(
            &["api", "v1", "devices", "ca_certificates"],
            page,
            cancellation,
        )
        .await
    }

    /// List local certificates across all devices with bounded pagination.
    pub async fn list_local_certificates(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(
            &["api", "v1", "devices", "local_certificates"],
            page,
            cancellation,
        )
        .await
    }

    /// List CA certificates for one device with bounded pagination.
    pub async fn list_device_ca_certificates(
        &self,
        device_uuid: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        self.list(
            &["api", "v1", "devices", device_uuid, "ca_certificates"],
            page,
            cancellation,
        )
        .await
    }

    /// List local certificates for one device with bounded pagination.
    pub async fn list_device_local_certificates(
        &self,
        device_uuid: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        self.list(
            &["api", "v1", "devices", device_uuid, "local_certificates"],
            page,
            cancellation,
        )
        .await
    }

    /// List licenses for one device with bounded pagination.
    pub async fn list_licenses(
        &self,
        device_uuid: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        self.list(
            &["api", "v1", "devices", device_uuid, "licenses"],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch one license by device UUID and license UUID.
    pub async fn get_license(
        &self,
        device_uuid: &str,
        license_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        validate_atom("license_uuid", license_uuid)?;
        self.get(
            &[
                "api",
                "v1",
                "devices",
                device_uuid,
                "licenses",
                license_uuid,
            ],
            &[],
            cancellation,
        )
        .await
    }

    /// Install a license on a device and poll until the operation completes.
    ///
    /// # Errors
    ///
    /// Returns an error when the device_uuid or body is invalid, or when the
    /// SDC request or polling fails.
    pub async fn install_license(
        &self,
        device_uuid: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<(String, DeploymentStatus), SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        validate_object_body(body)?;
        let response_value = self
            .send_write(
                Method::POST,
                &["api", "v1", "devices", device_uuid, "install_license"],
                Some(body),
                cancellation,
            )
            .await?;
        let response: JobStatus =
            serde_json::from_value(response_value).map_err(|_| SdcError::Serialization)?;
        let job_id = response
            .deploy_id
            .as_ref()
            .ok_or(SdcError::InvalidInput(
                "install_license response missing job id",
            ))?
            .clone();
        validate_atom("job_id", &job_id)?;
        let status = self
            .poll_job(JobKind::InstallLicense, &job_id, cancellation)
            .await?;
        Ok((job_id, status.status))
    }

    /// Install a CA certificate on a device and poll until the operation completes.
    ///
    /// # Errors
    ///
    /// Returns an error when the device_uuid or body is invalid, or when the
    /// SDC request or polling fails.
    pub async fn install_ca_certificate(
        &self,
        device_uuid: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<(String, DeploymentStatus), SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        validate_object_body(body)?;
        let response_value = self
            .send_write(
                Method::POST,
                &[
                    "api",
                    "v1",
                    "devices",
                    device_uuid,
                    "install_ca_certificate",
                ],
                Some(body),
                cancellation,
            )
            .await?;
        let response: JobStatus =
            serde_json::from_value(response_value).map_err(|_| SdcError::Serialization)?;
        let job_id = response
            .deploy_id
            .as_ref()
            .ok_or(SdcError::InvalidInput(
                "install_ca_certificate response missing job id",
            ))?
            .clone();
        validate_atom("job_id", &job_id)?;
        let status = self
            .poll_job(JobKind::InstallCaCertificate, &job_id, cancellation)
            .await?;
        Ok((job_id, status.status))
    }

    /// Install a local certificate on a device and poll until the operation completes.
    ///
    /// # Errors
    ///
    /// Returns an error when the device_uuid or body is invalid, or when the
    /// SDC request or polling fails.
    pub async fn install_local_certificate(
        &self,
        device_uuid: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<(String, DeploymentStatus), SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        validate_object_body(body)?;
        let response_value = self
            .send_write(
                Method::POST,
                &[
                    "api",
                    "v1",
                    "devices",
                    device_uuid,
                    "install_local_certificate",
                ],
                Some(body),
                cancellation,
            )
            .await?;
        let response: JobStatus =
            serde_json::from_value(response_value).map_err(|_| SdcError::Serialization)?;
        let job_id = response
            .deploy_id
            .as_ref()
            .ok_or(SdcError::InvalidInput(
                "install_local_certificate response missing job id",
            ))?
            .clone();
        validate_atom("job_id", &job_id)?;
        let status = self
            .poll_job(JobKind::InstallLocalCertificate, &job_id, cancellation)
            .await?;
        Ok((job_id, status.status))
    }

    /// Delete a certificate from a device and poll until the operation completes.
    ///
    /// # Errors
    ///
    /// Returns an error when the device_uuid or body is invalid, or when the
    /// SDC request or polling fails.
    pub async fn delete_certificate(
        &self,
        device_uuid: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<(String, DeploymentStatus), SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        validate_object_body(body)?;
        let response_value = self
            .send_write(
                Method::POST,
                &["api", "v1", "devices", device_uuid, "delete_certificate"],
                Some(body),
                cancellation,
            )
            .await?;
        let response: JobStatus =
            serde_json::from_value(response_value).map_err(|_| SdcError::Serialization)?;
        let job_id = response
            .deploy_id
            .as_ref()
            .ok_or(SdcError::InvalidInput(
                "delete_certificate response missing job id",
            ))?
            .clone();
        validate_atom("job_id", &job_id)?;
        let status = self
            .poll_job(JobKind::DeleteCertificate, &job_id, cancellation)
            .await?;
        Ok((job_id, status.status))
    }

    /// Read an install_license job status without polling.
    pub async fn install_license_status(
        &self,
        job_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<JobStatus, SdcError> {
        validate_atom("job_id", job_id)?;
        self.get(
            &["api", "v1", "devices", "install_license", job_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Ask SDC to re-read one or more devices' running configuration.
    ///
    /// **Direction: import.** `BulkSyncDevices` reads the device and updates
    /// SDC's model to match; it does not push SDC's view down. Confirmed
    /// against `vsrx-ci` on the live tenant (snapshot-gated, single device):
    /// the device's commit log was unchanged across the sync. The OpenAPI spec
    /// states no direction, which is why the finding is recorded in
    /// `docs/sdc-api/README.md` §5 and repeated here — this is the one property
    /// of this call that decides whether it is safe.
    ///
    /// Asynchronous: returns a `sync_id`, which this polls to completion.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or malformed UUID list, a rejected
    /// request, or a job that does not finish within the poll deadline.
    pub async fn sync_devices(
        &self,
        device_uuids: &[String],
        cancellation: &CancellationToken,
    ) -> Result<(String, crate::DeviceSyncJob), crate::DeviceSyncFailure> {
        use crate::DeviceSyncFailure;
        if device_uuids.is_empty() {
            return Err(DeviceSyncFailure::BeforeSubmit(SdcError::InvalidInput(
                "device sync requires at least one device UUID",
            )));
        }
        for uuid in device_uuids {
            validate_atom("device_uuid", uuid).map_err(DeviceSyncFailure::BeforeSubmit)?;
        }
        let body = serde_json::json!({ "uuids": device_uuids });
        let response_value = self
            .send_write(
                Method::POST,
                &["api", "v1", "devices", "sync"],
                Some(&body),
                cancellation,
            )
            .await
            .map_err(DeviceSyncFailure::from_submit)?;
        // Past this line the request has been accepted. Everything that can go
        // wrong now must carry the `sync_id`, or an operator is told the outcome
        // is unknown and given no way to look it up.
        let sync_id = response_value
            .get("sync_id")
            .and_then(Value::as_str)
            // A 2xx without a usable id still means SDC took the request.
            .ok_or(DeviceSyncFailure::AfterSubmit {
                sync_id: None,
                source: SdcError::InvalidInput("device sync response missing sync_id"),
            })?
            .to_owned();
        validate_atom("sync_id", &sync_id).map_err(|error| DeviceSyncFailure::AfterSubmit {
            sync_id: None,
            source: error,
        })?;
        // Polled here rather than through `poll_job`: this endpoint answers
        // `SUCCESS`/`FAILURE`, which `DeploymentStatus` does not recognise, so
        // the shared loop would never see a terminal state and every sync would
        // end in `JobDeadline` however well it went.
        //
        // The `sync_id` is returned alongside every error after this point, so a
        // caller that cannot learn the outcome can still name the job to an
        // operator.
        match self.poll_device_sync(&sync_id, cancellation).await {
            Ok(job) => Ok((sync_id, job)),
            // Every failure here is post-acceptance, whatever its kind — a
            // deadline, a cancellation, an unreadable body, a 5xx on the status
            // GET. Listing kinds would mean a new one silently becoming
            // "nothing happened" later.
            Err(source) => Err(DeviceSyncFailure::AfterSubmit {
                sync_id: Some(sync_id),
                source,
            }),
        }
    }

    /// Poll one device inventory sync to a terminal state.
    async fn poll_device_sync(
        &self,
        sync_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<crate::DeviceSyncJob, SdcError> {
        let deadline = Instant::now() + self.poll.deadline;
        let mut interval = self.poll.initial;
        loop {
            let probe = self.sync_devices_status(sync_id, cancellation);
            let job = tokio::select! {
                () = cancellation.cancelled() => return Err(SdcError::Cancelled),
                () = self.shutdown.cancelled() => return Err(SdcError::Cancelled),
                () = time::sleep_until(deadline) => return Err(SdcError::JobDeadline),
                result = probe => result?,
            };
            if job.status.is_terminal() {
                return Ok(job);
            }
            tokio::select! {
                () = cancellation.cancelled() => return Err(SdcError::Cancelled),
                () = self.shutdown.cancelled() => return Err(SdcError::Cancelled),
                () = time::sleep_until(deadline) => return Err(SdcError::JobDeadline),
                () = time::sleep(interval) => {}
            }
            interval = interval.saturating_mul(2).min(self.poll.maximum);
        }
    }

    /// Read a device-sync job status without polling.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed sync id or an unreadable response.
    pub async fn sync_devices_status(
        &self,
        sync_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<crate::DeviceSyncJob, SdcError> {
        validate_atom("sync_id", sync_id)?;
        self.get(
            &["api", "v1", "devices", "sync", sync_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Read an install_ca_certificate job status without polling.
    pub async fn install_ca_certificate_status(
        &self,
        job_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<JobStatus, SdcError> {
        validate_atom("job_id", job_id)?;
        self.get(
            &["api", "v1", "devices", "install_ca_certificate", job_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Read an install_local_certificate job status without polling.
    pub async fn install_local_certificate_status(
        &self,
        job_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<JobStatus, SdcError> {
        validate_atom("job_id", job_id)?;
        self.get(
            &["api", "v1", "devices", "install_local_certificate", job_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Read a delete_certificate job status without polling.
    pub async fn delete_certificate_status(
        &self,
        job_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<JobStatus, SdcError> {
        validate_atom("job_id", job_id)?;
        self.get(
            &["api", "v1", "devices", "delete_certificate", job_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Create a new NAT policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the body is invalid or when the SDC request fails.
    pub async fn create_nat_policy(
        &self,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_object_body(body)?;
        self.send_write(
            Method::POST,
            &["api", "v1", "policies", "nat"],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Update an existing NAT policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy_id or body is invalid, or when the SDC
    /// request fails.
    pub async fn update_nat_policy(
        &self,
        policy_id: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_object_body(body)?;
        self.send_write(
            Method::PUT,
            &["api", "v1", "policies", "nat", policy_id],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Delete a NAT policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy_id is invalid or when the SDC request
    /// fails.
    pub async fn delete_nat_policy(
        &self,
        policy_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        self.send_write(
            Method::DELETE,
            &["api", "v1", "policies", "nat", policy_id],
            None,
            cancellation,
        )
        .await
    }

    /// Create a new NAT rule within a policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy_id or body is invalid, or when the SDC
    /// request fails.
    pub async fn create_nat_rule(
        &self,
        policy_id: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_object_body(body)?;
        self.send_write(
            Method::POST,
            &["api", "v1", "policies", "nat", policy_id, "rules"],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Update an existing NAT rule.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy_id, rule_id, or body is invalid, or
    /// when the SDC request fails.
    pub async fn update_nat_rule(
        &self,
        policy_id: &str,
        rule_id: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_atom("rule_id", rule_id)?;
        validate_object_body(body)?;
        self.send_write(
            Method::PUT,
            &["api", "v1", "policies", "nat", policy_id, "rules", rule_id],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Delete a NAT rule.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy_id or rule_id is invalid, or when the
    /// SDC request fails.
    pub async fn delete_nat_rule(
        &self,
        policy_id: &str,
        rule_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_atom("rule_id", rule_id)?;
        self.send_write(
            Method::DELETE,
            &["api", "v1", "policies", "nat", policy_id, "rules", rule_id],
            None,
            cancellation,
        )
        .await
    }

    /// Create a new NAT rule group within a policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy_id or body is invalid, or when the SDC
    /// request fails.
    pub async fn create_nat_rule_group(
        &self,
        policy_id: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_object_body(body)?;
        self.send_write(
            Method::POST,
            &["api", "v1", "policies", "nat", policy_id, "rule_groups"],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Update an existing NAT rule group.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy_id, group_id, or body is invalid, or
    /// when the SDC request fails.
    pub async fn update_nat_rule_group(
        &self,
        policy_id: &str,
        group_id: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_atom("group_id", group_id)?;
        validate_object_body(body)?;
        self.send_write(
            Method::PUT,
            &[
                "api",
                "v1",
                "policies",
                "nat",
                policy_id,
                "rule_groups",
                group_id,
            ],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Read a preview job without polling.
    pub async fn preview_status(
        &self,
        preview_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<JobStatus, SdcError> {
        validate_atom("preview_id", preview_id)?;
        self.get(
            &["api", "v1", "policies", "preview", preview_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Read a deploy job without polling.
    pub async fn deploy_status(
        &self,
        deploy_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<JobStatus, SdcError> {
        validate_atom("deploy_id", deploy_id)?;
        self.get(
            &["api", "v1", "policies", "deploy", deploy_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Fetch one per-device preview result in XML format.
    pub async fn preview_device_result(
        &self,
        preview_id: &str,
        device_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("preview_id", preview_id)?;
        validate_atom("device_id", device_id)?;
        self.get(
            &[
                "api", "v1", "policies", "preview", preview_id, "devices", device_id,
            ],
            &[("format", "XML")],
            cancellation,
        )
        .await
    }

    /// Fetch one per-device deploy result in CLI format.
    pub async fn deploy_device_result(
        &self,
        deploy_id: &str,
        device_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("deploy_id", deploy_id)?;
        validate_atom("device_id", device_id)?;
        self.get(
            &[
                "api", "v1", "policies", "deploy", deploy_id, "devices", device_id,
            ],
            &[("format", "CLI")],
            cancellation,
        )
        .await
    }

    /// Submit, resolve, and bind a batch policy preview.
    pub async fn prepare_policy_deploy(
        &self,
        policies: Vec<PolicyOperation>,
        cancellation: &CancellationToken,
    ) -> Result<SdcPreparedChange, SdcError> {
        validate_policy_operations(&policies)?;
        let preview_request = PreviewRequest { policies };
        let response: PreviewResponse = self
            .post(
                &["api", "v1", "policies", "preview"],
                &preview_request,
                cancellation,
            )
            .await?;
        validate_atom("preview_id", &response.preview_id)?;
        let status = self
            .poll_job(JobKind::Preview, &response.preview_id, cancellation)
            .await?;
        if !status.status.succeeded() {
            return Err(SdcError::JobFailed {
                status: status.status,
            });
        }

        let mut device_results = Vec::with_capacity(status.device_deployment_status.len());
        for device in &status.device_deployment_status {
            device_results.push(
                self.preview_device_result(&response.preview_id, &device.device_id, cancellation)
                    .await?,
            );
        }

        let targets = prepared_targets(&preview_request)?;
        let deploy_request = DeployRequest::from(&preview_request);
        let preview = serde_json::json!({
            "preview_request": preview_request,
            "status": status,
            "device_results": device_results,
        });
        SdcPreparedChange::new(
            targets,
            serde_json::to_value(deploy_request).map_err(|_| SdcError::Serialization)?,
            preview,
            response.preview_id,
        )
        .map_err(|error| SdcError::PreparedChange(error.to_string()))
    }

    /// Submit an exact prepared deploy request and resolve its documented job.
    pub async fn deploy_prepared(
        &self,
        request: &DeployRequest,
        cancellation: &CancellationToken,
    ) -> Result<(String, JobStatus), SdcError> {
        let response: DeployResponse = self
            .post(&["api", "v1", "policies", "deploy"], request, cancellation)
            .await?;
        validate_atom("deploy_id", &response.deploy_id)?;
        let status = self
            .poll_job(JobKind::Deploy, &response.deploy_id, cancellation)
            .await?;
        Ok((response.deploy_id, status))
    }

    async fn poll_job(
        &self,
        kind: JobKind,
        job_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<JobStatus, SdcError> {
        let deadline = Instant::now() + self.poll.deadline;
        let mut interval = self.poll.initial;
        loop {
            let probe = async {
                match kind {
                    JobKind::Preview => self.preview_status(job_id, cancellation).await,
                    JobKind::Deploy => self.deploy_status(job_id, cancellation).await,
                    JobKind::InstallLicense => {
                        self.install_license_status(job_id, cancellation).await
                    }
                    JobKind::InstallCaCertificate => {
                        self.install_ca_certificate_status(job_id, cancellation)
                            .await
                    }
                    JobKind::InstallLocalCertificate => {
                        self.install_local_certificate_status(job_id, cancellation)
                            .await
                    }
                    JobKind::DeleteCertificate => {
                        self.delete_certificate_status(job_id, cancellation).await
                    }
                }
            };
            let status = tokio::select! {
                () = cancellation.cancelled() => return Err(SdcError::Cancelled),
                () = self.shutdown.cancelled() => return Err(SdcError::Cancelled),
                () = time::sleep_until(deadline) => return Err(SdcError::JobDeadline),
                result = probe => result?,
            };
            if status.status.is_terminal() {
                return Ok(status);
            }
            tokio::select! {
                () = cancellation.cancelled() => return Err(SdcError::Cancelled),
                () = self.shutdown.cancelled() => return Err(SdcError::Cancelled),
                () = time::sleep_until(deadline) => return Err(SdcError::JobDeadline),
                () = time::sleep(interval) => {}
            }
            interval = interval.saturating_mul(2).min(self.poll.maximum);
        }
    }

    async fn list(
        &self,
        segments: &[&str],
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list_projected(segments, page, &[], cancellation).await
    }

    /// `list`, with the API's server-side `fields` projection.
    ///
    /// `size` bounds how many objects come back, not how large each one is. A
    /// collection whose members embed arrays -- device groups embed their
    /// membership -- can therefore exceed `max_response_bytes` even at
    /// `size=1`, which refuses the read rather than truncating it. `fields`
    /// is the API's own remedy (see docs/sdc-api/README.md, "Pagination,
    /// filtering, and result shaping").
    async fn list_projected(
        &self,
        segments: &[&str],
        page: ListRequest,
        fields: &[String],
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        let page = ListRequest::new(page.from, page.size, self.max_page_size)?;
        let mut query = vec![
            ("from", page.from.to_string()),
            ("size", page.size.to_string()),
        ];
        // The spec declares `fields` as `style: form, explode: true` over an
        // array, and its own example is `fields=uuid && fields=name`. One
        // comma-joined value is a different request, and would likely be read
        // as a single unknown field name.
        for field in fields {
            validate_atom("fields", field)?;
            query.push(("fields", field.clone()));
        }
        let borrowed = query
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect::<Vec<_>>();
        self.get(segments, &borrowed, cancellation).await
    }

    /// Bounded list for `/api/v2/` collections, which prefix their page
    /// parameters (`spec.from`, `spec.size`) and accept no `fields`.
    async fn list_v2(
        &self,
        segments: &[&str],
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        let page = ListRequest::new(page.from, page.size, self.max_page_size)?;
        let from = page.from.to_string();
        let size = page.size.to_string();
        self.get(
            segments,
            &[("spec.from", from.as_str()), ("spec.size", size.as_str())],
            cancellation,
        )
        .await
    }

    async fn get<T: DeserializeOwned>(
        &self,
        segments: &[&str],
        query: &[(&str, &str)],
        cancellation: &CancellationToken,
    ) -> Result<T, SdcError> {
        self.send::<(), T>(Method::GET, segments, query, None, cancellation)
            .await
    }

    async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        segments: &[&str],
        body: &B,
        cancellation: &CancellationToken,
    ) -> Result<T, SdcError> {
        self.send(Method::POST, segments, &[], Some(body), cancellation)
            .await
    }

    async fn send<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&B>,
        cancellation: &CancellationToken,
    ) -> Result<T, SdcError> {
        let raw = self
            .send_raw(method, segments, query, body, cancellation)
            .await?;
        serde_json::from_slice(&raw).map_err(|_| SdcError::InvalidJson)
    }

    /// Send one request and return its raw successful response body.
    async fn send_raw<B: Serialize>(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&B>,
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>, SdcError> {
        let (status, body) = self
            .send_parts(method, segments, query, body, cancellation)
            .await?;
        let body = body?;
        if !status.is_success() {
            return Err(classify_api_error(status, &body));
        }
        Ok(body)
    }

    /// Send one request, retrying a `GET` on a rate-limited or overloaded
    /// response, and reporting the response status separately from the body.
    ///
    /// The status is resolved first so a caller can tell a request SDC refused
    /// from one it accepted but whose body could not be read. Reads do not
    /// care about that distinction; writes do, because it decides whether a
    /// mutation landed.
    ///
    /// Retrying is deliberately restricted to `GET`: a write must not
    /// silently resend into an unknown state, so `send_write` always takes
    /// this same method and never observes more than one attempt here.
    async fn send_parts<B: Serialize>(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&B>,
        cancellation: &CancellationToken,
    ) -> Result<(StatusCode, Result<Vec<u8>, SdcError>), SdcError> {
        let mut attempt: u32 = 0;
        loop {
            let outcome = self
                .send_parts_once(method.clone(), segments, query, body, cancellation)
                .await?;
            let retryable = method == Method::GET
                && attempt < MAX_RETRY_ATTEMPTS
                && matches!(
                    outcome.status,
                    StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
                );
            if !retryable {
                return Ok((outcome.status, outcome.body));
            }
            let delay = retry_delay(outcome.retry_after, attempt);
            attempt += 1;
            tokio::select! {
                () = cancellation.cancelled() => return Err(SdcError::Cancelled),
                () = self.shutdown.cancelled() => return Err(SdcError::Cancelled),
                () = time::sleep(delay) => {}
            }
        }
    }

    /// Send exactly one wire attempt.
    async fn send_parts_once<B: Serialize>(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&B>,
        cancellation: &CancellationToken,
    ) -> Result<SendOutcome, SdcError> {
        let mut url = self.base_url.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| SdcError::UrlConstruction)?;
            path.clear();
            for segment in segments {
                if segment.is_empty() || matches!(*segment, "." | "..") {
                    return Err(SdcError::UrlConstruction);
                }
                path.push(segment);
            }
        }
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }

        let mut auth = HeaderValue::from_str(self.credential.expose())
            .map_err(|_| SdcError::InvalidCredentialHeader)?;
        auth.set_sensitive(true);
        let mut request = self
            .http
            .request(method, url)
            .header(self.auth_scheme.header_name(), auth)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }

        let operation = async {
            let _permit = self
                .concurrency
                .acquire()
                .await
                .map_err(|_| SdcError::Cancelled)?;
            let response = request
                .send()
                .await
                .map_err(|error| classify_reqwest(&error))?;
            // Read the status before any body handling. A write needs to know
            // whether SDC accepted the request even when the body is then
            // unreadable, because that decides whether the mutation landed.
            let status = response.status();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok())
                .map(Duration::from_secs);
            let oversized = response
                .content_length()
                .is_some_and(|length| length > self.max_response_bytes as u64);
            let body = async {
                if oversized {
                    return Err(SdcError::ResponseTooLarge {
                        limit: self.max_response_bytes,
                    });
                }
                let mut body = Vec::new();
                let mut stream = response.bytes_stream();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|error| classify_reqwest(&error))?;
                    if body.len().saturating_add(chunk.len()) > self.max_response_bytes {
                        return Err(SdcError::ResponseTooLarge {
                            limit: self.max_response_bytes,
                        });
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(body)
            }
            .await;
            Ok::<_, SdcError>(SendOutcome {
                status,
                retry_after,
                body,
            })
        };

        tokio::select! {
            () = cancellation.cancelled() => Err(SdcError::Cancelled),
            () = self.shutdown.cancelled() => Err(SdcError::Cancelled),
            result = time::timeout(self.request_timeout, operation) => {
                result.map_err(|_| SdcError::Timeout)?
            }
        }
    }

    /// Send one mutating request whose successful response may carry no body.
    ///
    /// An empty or whitespace-only body resolves to `Value::Null` rather than
    /// an `InvalidJson` failure, because SDC answers some deletes that way.
    async fn send_write(
        &self,
        method: Method,
        segments: &[&str],
        body: Option<&Value>,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        let (status, raw) = self
            .send_parts(method, segments, &[], body, cancellation)
            .await?;
        let raw = match raw {
            Ok(bytes) => bytes,
            // SDC accepted the request, so the mutation may have landed even
            // though its response could not be read. Reporting a plain failure
            // here would invite a retry that duplicates a create.
            Err(_) if status.is_success() => return Err(SdcError::MutationOutcomeUnknown),
            Err(error) => return Err(error),
        };
        if !status.is_success() {
            return Err(classify_api_error(status, &raw));
        }
        if raw.iter().all(u8::is_ascii_whitespace) {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&raw).map_err(|_| SdcError::MutationOutcomeUnknown)
    }
}

#[derive(Debug, Clone, Copy)]
enum JobKind {
    Preview,
    Deploy,
    InstallLicense,
    InstallCaCertificate,
    InstallLocalCertificate,
    DeleteCertificate,
}

fn prepared_targets(request: &PreviewRequest) -> Result<Vec<SdcPreparedTarget>, SdcError> {
    let mut targets = Vec::new();
    for operation in &request.policies {
        for target in operation
            .deploy_targets
            .iter()
            .chain(&operation.undeploy_targets)
        {
            let kind = match target.target_type {
                crate::TargetType::Device => "device",
                crate::TargetType::DeviceGroup => "device_group",
            };
            targets.push(
                SdcPreparedTarget::new(kind, &target.target_id)
                    .map_err(|error| SdcError::PreparedChange(error.to_string()))?,
            );
        }
    }
    targets.sort();
    targets.dedup();
    Ok(targets)
}

fn validate_policy_operations(policies: &[PolicyOperation]) -> Result<(), SdcError> {
    if policies.is_empty() || policies.len() > 256 {
        return Err(SdcError::InvalidInput(
            "policies must contain 1-256 entries",
        ));
    }
    for policy in policies {
        validate_atom("policy_id", &policy.policy_id)?;
        if policy.deploy_targets.is_empty() && policy.undeploy_targets.is_empty() {
            return Err(SdcError::InvalidInput(
                "each policy needs at least one deploy or undeploy target",
            ));
        }
    }
    Ok(())
}

/// Hard cap on one object-write request body.
const MAX_WRITE_BODY_BYTES: usize = 1024 * 1024;

/// Reject write bodies that are not a bounded, non-empty JSON object.
///
/// SDC object definitions are small; a scalar, an array, or a megabyte-scale
/// body indicates a caller error rather than a legitimate write.
fn validate_object_body(body: &Value) -> Result<(), SdcError> {
    let Value::Object(fields) = body else {
        return Err(SdcError::InvalidInput(
            "object write body must be a JSON object",
        ));
    };
    if fields.is_empty() {
        return Err(SdcError::InvalidInput(
            "object write body must not be empty",
        ));
    }
    if serde_json::to_vec(body)
        .map_err(|_| SdcError::Serialization)?
        .len()
        > MAX_WRITE_BODY_BYTES
    {
        return Err(SdcError::InvalidInput(
            "object write body exceeds the 1048576-byte limit",
        ));
    }
    if crate::redact::contains_redaction_marker(body) {
        return Err(SdcError::InvalidInput(
            "write body contains a redaction marker; re-read the field value out-of-band",
        ));
    }
    Ok(())
}

fn validate_atom(field: &'static str, value: &str) -> Result<(), SdcError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(SdcError::InvalidIdentifier { field });
    }
    Ok(())
}

fn classify_reqwest(error: &reqwest::Error) -> SdcError {
    if error.is_timeout() {
        SdcError::Timeout
    } else if error.is_body() || error.is_decode() {
        SdcError::BodyTransfer
    } else if error.is_builder() {
        SdcError::UrlConstruction
    } else {
        SdcError::Transport
    }
}

fn classify_api_error(status: StatusCode, body: &[u8]) -> SdcError {
    if status == StatusCode::TOO_MANY_REQUESTS {
        return SdcError::ResourceExhausted;
    }
    let value: Option<Value> = serde_json::from_slice(body).ok();
    let code = value
        .as_ref()
        .and_then(|value| value.get("code"))
        .and_then(Value::as_str)
        .map(bound_text)
        .unwrap_or_else(|| format!("http_{}", status.as_u16()));
    let message = value
        .as_ref()
        .and_then(|value| value.get("message").or_else(|| value.get("error")))
        .and_then(Value::as_str)
        .map(bound_text)
        .unwrap_or_else(|| "SDC API request failed".to_owned());
    SdcError::Api {
        status: status.as_u16(),
        code,
        message,
    }
}

fn bound_text(value: &str) -> String {
    mecmcp_server::bounded_text(value, 512).text
}

/// Stable, credential-free SDC client failure.
#[derive(Debug, thiserror::Error)]
pub enum SdcError {
    /// Configuration validation failed.
    #[error("SDC configuration failed: {0}")]
    Config(String),
    /// Credential was empty or excessive.
    #[error("SDC credential must contain 1-16384 bytes")]
    Credential,
    /// HTTPS client construction failed.
    #[error("SDC HTTPS client construction failed")]
    ClientConstruction,
    /// Request URL construction failed.
    #[error("failed to construct an SDC request URL")]
    UrlConstruction,
    /// Credential could not be represented as a header.
    #[error("SDC credential is not a valid HTTP header value")]
    InvalidCredentialHeader,
    /// Request transmission failed.
    #[error("SDC request transmission failed")]
    Transport,
    /// Response body transfer failed.
    #[error("SDC response body transfer failed")]
    BodyTransfer,
    /// Whole-request deadline elapsed.
    #[error("SDC request timed out")]
    Timeout,
    /// Response exceeded the configured cap.
    #[error("SDC response exceeds the {limit}-byte limit")]
    ResponseTooLarge {
        /// Configured maximum.
        limit: usize,
    },
    /// Successful response was not valid JSON.
    #[error("SDC response is not valid JSON")]
    InvalidJson,
    /// Invalid bounded list request.
    #[error(transparent)]
    List(#[from] ListRequestError),
    /// Invalid budget-paginated list request.
    #[error(transparent)]
    Page(#[from] crate::paging::PageError),
    /// Credential tenant scope differed from operator configuration.
    #[error("credential tenant scope does not match expected_tenant_id")]
    TenantMismatch,
    /// SDC rejected the request.
    #[error("SDC API error {status} ({code}): {message}")]
    Api {
        /// HTTP status.
        status: u16,
        /// Bounded machine-readable code.
        code: String,
        /// Bounded SDC message.
        message: String,
    },
    /// SDC uses 429 for rate limiting and oversized service responses.
    #[error(
        "SDC resource exhausted: request was rate limited or the service response was too large; retry only after operator review"
    )]
    ResourceExhausted,
    /// A caller-controlled identifier was unsafe.
    #[error("{field} must be 1-256 non-whitespace bytes")]
    InvalidIdentifier {
        /// Rejected field.
        field: &'static str,
    },
    /// A structured input violated an SDC contract.
    #[error("{0}")]
    InvalidInput(&'static str),
    /// A prepared-change envelope could not be built or validated.
    #[error("invalid prepared change: {0}")]
    PreparedChange(String),
    /// JSON construction failed without exposing content.
    #[error("failed to serialize SDC request")]
    Serialization,
    /// Job polling or request was cancelled.
    #[error("SDC operation was cancelled")]
    Cancelled,
    /// Job polling reached its configured deadline.
    #[error("SDC job outcome is indeterminate because the polling deadline elapsed")]
    JobDeadline,
    /// SDC returned a documented terminal failure.
    #[error("SDC job ended with {status:?}")]
    JobFailed {
        /// Documented terminal state.
        status: DeploymentStatus,
    },
    /// Shared change-control operation failed.
    #[error("SDC change control failed: {0}")]
    ChangeControl(String),
    /// SDC has no candidate rollback primitive for this transaction.
    #[error("SDC policy deployment rollback is unsupported")]
    RollbackUnsupported,

    /// SDC accepted a mutation but its response could not be read.
    #[error(
        "SDC accepted the write but its response could not be read; the change may have been applied"
    )]
    MutationOutcomeUnknown,

    /// A change-controlled target moved between planning and writing.
    #[error("object changed since it was prepared; re-prepare to see the current state")]
    TargetDrifted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::Query,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::{delete, get, post, put},
    };
    use std::collections::HashMap;

    async fn serve(app: Router) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve test application");
        });
        (
            Url::parse(&format!("http://{address}/")).expect("test URL"),
            task,
        )
    }

    fn client(base_url: Url, max_response_bytes: usize) -> SdcClient {
        let _ = rustls::crypto::ring::default_provider().install_default();
        SdcClient::from_test_parts(
            base_url.as_str(),
            "test-secret".to_owned(),
            max_response_bytes,
            100,
        )
    }

    #[tokio::test]
    async fn list_devices_sends_exact_auth_path_and_nonzero_page() {
        let app = Router::new().route(
            "/api/v1/devices",
            get(
                |headers: HeaderMap, Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(
                        headers
                            .get("x-api-key")
                            .and_then(|value| value.to_str().ok()),
                        Some("test-secret")
                    );
                    assert_eq!(query.get("from").map(String::as_str), Some("10"));
                    assert_eq!(query.get("size").map(String::as_str), Some("20"));
                    Json(serde_json::json!({"items": [], "count": 0}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_devices(
                ListRequest::new(10, 20, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["count"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn path_parameters_remain_one_encoded_segment() {
        // A hostile identifier must be percent-encoded into exactly one path
        // segment. Route it explicitly rather than with a fallback: a fallback
        // answers every path, so it would pass just as happily if the value
        // were split across segments or leaked into the query string.
        let app = Router::new()
            .route(
                "/api/v1/devices/{device_uuid}",
                get(
                    |axum::extract::Path(device_uuid): axum::extract::Path<String>,
                     Query(query): Query<HashMap<String, String>>| async move {
                        Json(serde_json::json!({
                            "device_uuid": device_uuid,
                            "query_keys": query.into_keys().collect::<Vec<_>>(),
                        }))
                    },
                ),
            )
            .fallback(|uri: axum::http::Uri| async move {
                // Reached only if the identifier escaped its single segment.
                Json(serde_json::json!({"escaped_to": uri.to_string()}))
            });
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .get_device("a/b?admin=true#frag", &CancellationToken::new())
            .await
            .expect("encoded path succeeds");
        assert_eq!(
            result["device_uuid"], "a/b?admin=true#frag",
            "identifier did not survive as one encoded segment: {result}"
        );
        assert_eq!(
            result["query_keys"],
            serde_json::json!([]),
            "identifier leaked into the query string: {result}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn status_429_is_never_hidden_as_a_retryable_transport_error() {
        // A persistent 429 must still fail once retries are exhausted, not
        // surface as some other, more optimistic-looking transport error.
        let calls: Arc<std::sync::atomic::AtomicU32> =
            Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counted = Arc::clone(&calls);
        let app = Router::new().route(
            "/api/v1/devices",
            get(move || {
                let counted = Arc::clone(&counted);
                async move {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(reqwest::header::RETRY_AFTER.as_str(), "0")],
                        Json(serde_json::json!({"message": "too many"})),
                    )
                }
            }),
        );
        let (base_url, server) = serve(app).await;
        let error = client(base_url, 4096)
            .list_devices(
                ListRequest::new(0, 20, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect_err("429 must fail");
        assert!(matches!(error, SdcError::ResourceExhausted));
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            MAX_RETRY_ATTEMPTS + 1,
            "GET must retry up to the capped attempt count, then stop"
        );
        server.abort();
    }

    #[tokio::test]
    async fn get_retries_a_429_with_retry_after_and_then_succeeds() {
        // Acceptance criterion: a GET rate-limited with `Retry-After` retries
        // and succeeds within the capped attempt count.
        let calls: Arc<std::sync::atomic::AtomicU32> =
            Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counted = Arc::clone(&calls);
        let app = Router::new().route(
            "/api/v1/devices",
            get(move || {
                let counted = Arc::clone(&counted);
                async move {
                    let attempt = counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if attempt < MAX_RETRY_ATTEMPTS {
                        return (
                            StatusCode::TOO_MANY_REQUESTS,
                            [(reqwest::header::RETRY_AFTER.as_str(), "0")],
                            Json(serde_json::json!({"message": "too many"})),
                        )
                            .into_response();
                    }
                    Json(serde_json::json!({"items": [], "count": 0})).into_response()
                }
            }),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_devices(
                ListRequest::new(0, 20, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("must succeed once the rate limit clears within the cap");
        assert_eq!(result["count"], 0);
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            MAX_RETRY_ATTEMPTS + 1
        );
        server.abort();
    }

    #[tokio::test]
    async fn write_never_retries_on_429() {
        // Acceptance criterion: a write must not silently retry into an
        // unknown state, so it gets exactly one attempt even when rate
        // limited.
        let calls: Arc<std::sync::atomic::AtomicU32> =
            Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counted = Arc::clone(&calls);
        let app = Router::new().route(
            "/api/v1/policies/firewall",
            post(move || {
                let counted = Arc::clone(&counted);
                async move {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(reqwest::header::RETRY_AFTER.as_str(), "0")],
                        Json(serde_json::json!({"message": "too many"})),
                    )
                }
            }),
        );
        let (base_url, server) = serve(app).await;
        let error = client(base_url, 4096)
            .create_firewall_policy(&serde_json::json!({"name": "p"}), &CancellationToken::new())
            .await
            .expect_err("429 must fail");
        assert!(matches!(error, SdcError::ResourceExhausted));
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a write must never be retried automatically"
        );
        server.abort();
    }

    #[tokio::test]
    async fn cancelling_the_request_token_aborts_an_in_flight_call() {
        // The MCP handler feeds each tool the per-request `RequestContext::ct`,
        // so a client `notifications/cancelled` must abandon the SDC call
        // instead of running to the whole-request timeout.
        let app = Router::new().route(
            "/api/v1/devices",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Json(serde_json::json!({"items": []}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let cancellation = CancellationToken::new();
        let trigger = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            trigger.cancel();
        });

        let started = std::time::Instant::now();
        let error = client(base_url, 4096)
            .list_devices(
                ListRequest::new(0, 20, 100).expect("test page"),
                &cancellation,
            )
            .await
            .expect_err("a cancelled request must fail");
        assert!(matches!(error, SdcError::Cancelled));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "cancellation must abandon the call, not wait for the 2s request timeout"
        );
        server.abort();
    }

    #[tokio::test]
    async fn process_shutdown_aborts_work_the_request_token_would_not() {
        // systemd stops the unit with SIGTERM while a request token is still
        // live. Without this the listener drain would block for the remainder
        // of poll_deadline_ms and be SIGKILLed at TimeoutStopSec.
        let app = Router::new().route(
            "/api/v1/devices",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Json(serde_json::json!({"items": []}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let shutdown = CancellationToken::new();
        let trigger = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            trigger.cancel();
        });

        // The per-request token stays uncancelled throughout.
        let request_token = CancellationToken::new();
        let started = std::time::Instant::now();
        let error = client(base_url, 4096)
            .with_shutdown(shutdown)
            .list_devices(
                ListRequest::new(0, 20, 100).expect("test page"),
                &request_token,
            )
            .await
            .expect_err("shutdown must abort the call");
        assert!(matches!(error, SdcError::Cancelled));
        assert!(!request_token.is_cancelled());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "shutdown must abandon the call, not wait for the 2s request timeout"
        );
        server.abort();
    }

    #[tokio::test]
    async fn response_limit_is_enforced_while_streaming() {
        let app = Router::new().route(
            "/api/v1/devices",
            get(|| async { Json(serde_json::json!({"items": ["0123456789"]})) }),
        );
        let (base_url, server) = serve(app).await;
        let error = client(base_url, 8)
            .list_devices(
                ListRequest::new(0, 1, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect_err("body cap must fail");
        assert!(matches!(error, SdcError::ResponseTooLarge { limit: 8 }));
        server.abort();
    }

    #[tokio::test]
    async fn create_resource_posts_the_body_to_the_exact_collection_path() {
        let app = Router::new().route(
            "/api/v1/addresses",
            post(|headers: HeaderMap, Json(body): Json<Value>| async move {
                assert_eq!(
                    headers
                        .get("x-api-key")
                        .and_then(|value| value.to_str().ok()),
                    Some("test-secret")
                );
                assert_eq!(body.get("name").and_then(Value::as_str), Some("lab-net"));
                Json(serde_json::json!({"uuid": "created", "name": "lab-net"}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let created = client(base_url, 65536)
            .create_resource(
                WritableResource::Addresses,
                &serde_json::json!({"name": "lab-net"}),
                &CancellationToken::new(),
            )
            .await
            .expect("create must succeed");
        assert_eq!(created.get("uuid").and_then(Value::as_str), Some("created"));
        server.abort();
    }

    #[tokio::test]
    async fn update_resource_puts_the_body_to_the_exact_item_path() {
        let app = Router::new().route(
            "/api/v1/services/svc-1",
            put(|Json(body): Json<Value>| async move {
                assert_eq!(body.get("name").and_then(Value::as_str), Some("telnet-alt"));
                Json(serde_json::json!({"uuid": "svc-1", "name": "telnet-alt"}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let updated = client(base_url, 65536)
            .update_resource(
                WritableResource::Services,
                "svc-1",
                &serde_json::json!({"name": "telnet-alt"}),
                &CancellationToken::new(),
            )
            .await
            .expect("update must succeed");
        assert_eq!(updated.get("uuid").and_then(Value::as_str), Some("svc-1"));
        server.abort();
    }

    #[tokio::test]
    async fn delete_resource_tolerates_an_empty_success_body() {
        let app = Router::new().route(
            "/api/v1/schedulers/sch-1",
            delete(|| async { StatusCode::NO_CONTENT }),
        );
        let (base_url, server) = serve(app).await;
        let deleted = client(base_url, 65536)
            .delete_resource(
                WritableResource::Schedulers,
                "sch-1",
                &CancellationToken::new(),
            )
            .await
            .expect("an empty delete response must not be an error");
        assert_eq!(deleted, Value::Null);
        server.abort();
    }

    #[tokio::test]
    async fn object_writes_reject_identifiers_that_could_escape_the_collection() {
        let sdc = client(
            Url::parse("https://example.invalid/").expect("test URL"),
            1024,
        );
        // `a/b` is deliberately absent: a slash is percent-encoded into a
        // single path segment rather than refused, which
        // `path_parameters_remain_one_encoded_segment` already pins down.
        for identifier in ["", ".", "..", "with space", "tab\there", "nul\0byte"] {
            let error = sdc
                .update_resource(
                    WritableResource::Addresses,
                    identifier,
                    &serde_json::json!({"name": "x"}),
                    &CancellationToken::new(),
                )
                .await
                .expect_err("invalid identifier must be refused before transport");
            // Two independent guards refuse these: `validate_atom` rejects
            // empty, whitespace, and control bytes, and the path builder
            // separately refuses `.` and `..`. Either is a safe refusal, and
            // neither reaches the network.
            assert!(
                matches!(
                    error,
                    SdcError::InvalidIdentifier { field: "uuid" } | SdcError::UrlConstruction
                ),
                "identifier {identifier:?} produced {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn object_writes_reject_bodies_that_are_not_a_populated_object() {
        let sdc = client(
            Url::parse("https://example.invalid/").expect("test URL"),
            1024,
        );
        for body in [
            serde_json::json!([]),
            serde_json::json!("scalar"),
            serde_json::json!(7),
            serde_json::json!({}),
        ] {
            let error = sdc
                .create_resource(
                    WritableResource::Addresses,
                    &body,
                    &CancellationToken::new(),
                )
                .await
                .expect_err("invalid body must be refused before transport");
            assert!(
                matches!(error, SdcError::InvalidInput(_)),
                "body {body} produced {error:?}"
            );
        }
    }

    /// Percy F2 (MEC-973): a model that echoes back a redacted read must not
    /// be able to write the literal marker over a real field.
    #[tokio::test]
    async fn object_writes_reject_bodies_carrying_the_redaction_marker() {
        let sdc = client(
            Url::parse("https://example.invalid/").expect("test URL"),
            1024,
        );
        let error = sdc
            .create_resource(
                WritableResource::Addresses,
                &serde_json::json!({"name": "a", "description": crate::REDACTED}),
                &CancellationToken::new(),
            )
            .await
            .expect_err("a redaction marker in the request body must be refused");
        assert!(matches!(error, SdcError::InvalidInput(_)), "{error:?}");
    }

    #[tokio::test]
    async fn list_ca_certificates_sends_exact_auth_path_and_page() {
        let app = Router::new().route(
            "/api/v1/devices/ca_certificates",
            get(
                |headers: HeaderMap, Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(
                        headers
                            .get("x-api-key")
                            .and_then(|value| value.to_str().ok()),
                        Some("test-secret")
                    );
                    assert_eq!(query.get("from").map(String::as_str), Some("0"));
                    assert_eq!(query.get("size").map(String::as_str), Some("10"));
                    Json(serde_json::json!({"items": [], "count": 0}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_ca_certificates(
                ListRequest::new(0, 10, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["count"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn list_device_groups_sends_exact_auth_path_and_page() {
        let app = Router::new().route(
            "/api/v1/device_groups",
            get(
                |headers: HeaderMap, Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(
                        headers
                            .get("x-api-key")
                            .and_then(|value| value.to_str().ok()),
                        Some("test-secret")
                    );
                    assert_eq!(query.get("from").map(String::as_str), Some("0"));
                    assert_eq!(query.get("size").map(String::as_str), Some("10"));
                    // An empty tenant returns a bare `{}` — see docs/sdc-api §3.
                    // Observed live on 2026-08-12 against this endpoint.
                    Json(serde_json::json!({}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_device_groups(
                ListRequest::new(0, 10, 100).expect("test page"),
                &[],
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result, serde_json::json!({}));
        server.abort();
    }

    #[tokio::test]
    async fn get_device_group_returns_member_devices() {
        let app = Router::new().route(
            "/api/v1/device_groups/{group_uuid}",
            get(|| async {
                Json(serde_json::json!({
                    "uuid": "group-1",
                    "name": "branches",
                    "devices": [{"uuid": "device-1"}, {"uuid": "device-2"}],
                }))
            }),
        );
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);

        let group = sdc
            .get_device_group("group-1", &CancellationToken::new())
            .await
            .expect("get succeeds");
        assert_eq!(
            group["devices"].as_array().map(Vec::len),
            Some(2),
            "membership is the whole point of this read: it is how an approver \
             sees the blast radius of a deploy aimed at the group"
        );

        server.abort();
    }

    #[tokio::test]
    async fn a_device_group_list_can_project_fields_and_omits_the_param_otherwise() {
        let app = Router::new().route(
            "/api/v1/device_groups",
            get(|uri: axum::http::Uri| async move {
                // Collect every `fields` pair: the spec explodes the array, so
                // a single comma-joined value would be the wrong request.
                let fields: Vec<String> = uri
                    .query()
                    .unwrap_or_default()
                    .split('&')
                    .filter_map(|pair| pair.strip_prefix("fields="))
                    .map(str::to_owned)
                    .collect();
                Json(serde_json::json!({"fields": fields}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);

        let projected = sdc
            .list_device_groups(
                ListRequest::new(0, 10, 100).expect("test page"),
                &["uuid".to_owned(), "name".to_owned()],
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(
            projected["fields"],
            serde_json::json!(["uuid", "name"]),
            "each field must be its own query item per the spec's exploded array"
        );

        // Absent by default: a projection invented here would silently drop
        // fields, and no live group has been observed to derive one from.
        let unprojected = sdc
            .list_device_groups(
                ListRequest::new(0, 10, 100).expect("test page"),
                &[],
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(unprojected["fields"], serde_json::json!([]));
        server.abort();
    }

    /// The generic reader projects with an exploded `fields` array, and omits
    /// the parameter entirely when no projection is asked for.
    ///
    /// The spec declares `fields` as `style: form, explode: true`, so
    /// `fields=uuid&fields=name` is the request and one comma-joined value
    /// would read as a single unknown field name. Omitting it when empty
    /// matters just as much: no default projection is invented for any
    /// family, because field names belong to the API and guessing them
    /// silently drops data.
    #[tokio::test]
    async fn a_resource_list_can_project_fields_and_omits_the_param_otherwise() {
        let app = Router::new().route(
            "/api/v1/ips_profiles",
            get(|uri: axum::http::Uri| async move {
                // Collect every `fields` pair: the spec explodes the array, so
                // a single comma-joined value would be the wrong request.
                let fields: Vec<String> = uri
                    .query()
                    .unwrap_or_default()
                    .split('&')
                    .filter_map(|pair| pair.strip_prefix("fields="))
                    .map(str::to_owned)
                    .collect();
                Json(serde_json::json!({"fields": fields}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);

        let projected = sdc
            .list_resource(
                ResourceKind::IpsProfiles,
                ListRequest::new(0, 10, 200).expect("page"),
                &["uuid".to_owned(), "name".to_owned()],
                &CancellationToken::new(),
            )
            .await
            .expect("projected list succeeds");
        assert_eq!(
            projected["fields"],
            serde_json::json!(["uuid", "name"]),
            "each field must be its own query item per the spec's exploded array"
        );

        // Absent by default: a projection invented here would silently drop
        // fields, and no live resource has been observed to derive one from.
        let unprojected = sdc
            .list_resource(
                ResourceKind::IpsProfiles,
                ListRequest::new(0, 10, 200).expect("page"),
                &[],
                &CancellationToken::new(),
            )
            .await
            .expect("unprojected list succeeds");
        assert_eq!(unprojected["fields"], serde_json::json!([]));
        server.abort();
    }

    /// A new family's list reaches its own collection path.
    ///
    /// The catalog's self-consistency tests prove the table agrees with itself.
    /// This proves the table is what the client actually requests.
    #[tokio::test]
    async fn a_new_family_lists_from_its_own_collection() {
        let app = Router::new().route(
            "/api/v1/rule_options",
            get(|| async { Json(serde_json::json!({"items": []})) }),
        );
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);

        let listed = sdc
            .list_resource(
                ResourceKind::RuleOptions,
                ListRequest::new(0, 10, 200).expect("page"),
                &[],
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");

        assert_eq!(listed["items"], serde_json::json!([]));
        server.abort();
    }

    #[tokio::test]
    async fn a_device_group_uuid_cannot_escape_its_collection() {
        // `validate_atom` permits `/` and `.`, so the guarantee lives in the
        // URL builder: it refuses a literal `.`/`..` segment, and `push`
        // percent-encodes everything else into exactly one segment. Asserted
        // against the path the server actually receives rather than inferred.
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let recorder = recorder.clone();
            async move {
                recorder
                    .lock()
                    .expect("record path")
                    .push(uri.path().to_owned());
                Json(serde_json::json!({}))
            }
        });
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);

        sdc.get_device_group("../devices", &CancellationToken::new())
            .await
            .expect("the request is built, not refused");
        let path = seen.lock().expect("read path")[0].clone();
        assert!(
            path.starts_with("/api/v1/device_groups/"),
            "a traversal attempt must stay inside the collection; got {path}"
        );
        assert!(
            !path.contains("/devices"),
            "the separator must be encoded rather than opening a new segment; got {path}"
        );

        // A literal traversal segment is refused outright.
        assert!(
            sdc.get_device_group("..", &CancellationToken::new())
                .await
                .is_err()
        );
        server.abort();
    }

    #[tokio::test]
    async fn certificate_reads_stay_unprojected_at_the_client_layer() {
        // The allowlist projection belongs at the MCP tool boundary, not here.
        // prepare_license_write and the apply-time drift check both read
        // through this method and digest the result, so projecting it would
        // erase an unknown field from both sides of the comparison and let a
        // drifted write apply as unchanged.
        let app = Router::new().route(
            "/api/v1/devices/ca_certificates",
            get(|| async {
                Json(serde_json::json!({
                    "items": [{"uuid": "u", "field_added_upstream": "visible"}],
                    "count": 1,
                }))
            }),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_ca_certificates(
                ListRequest::new(0, 10, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");

        assert_eq!(
            result["items"][0]["field_added_upstream"], "visible",
            "the client must return upstream fields verbatim so change control \
             can detect drift in them"
        );
        server.abort();
    }

    #[tokio::test]
    async fn list_local_certificates_sends_exact_auth_path_and_page() {
        let app = Router::new().route(
            "/api/v1/devices/local_certificates",
            get(
                |headers: HeaderMap, Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(
                        headers
                            .get("x-api-key")
                            .and_then(|value| value.to_str().ok()),
                        Some("test-secret")
                    );
                    assert_eq!(query.get("from").map(String::as_str), Some("0"));
                    assert_eq!(query.get("size").map(String::as_str), Some("10"));
                    Json(serde_json::json!({"items": [], "count": 0}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_local_certificates(
                ListRequest::new(0, 10, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["count"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn list_device_ca_certificates_sends_device_uuid_in_path() {
        let app = Router::new().route(
            "/api/v1/devices/{device_uuid}/ca_certificates",
            get(
                |axum::extract::Path(device_uuid): axum::extract::Path<String>,
                 Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(device_uuid, "dev-123");
                    assert_eq!(query.get("from").map(String::as_str), Some("0"));
                    assert_eq!(query.get("size").map(String::as_str), Some("5"));
                    Json(serde_json::json!({"items": [], "count": 0}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_device_ca_certificates(
                "dev-123",
                ListRequest::new(0, 5, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["count"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn list_device_local_certificates_sends_device_uuid_in_path() {
        let app = Router::new().route(
            "/api/v1/devices/{device_uuid}/local_certificates",
            get(
                |axum::extract::Path(device_uuid): axum::extract::Path<String>,
                 Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(device_uuid, "dev-456");
                    assert_eq!(query.get("from").map(String::as_str), Some("0"));
                    assert_eq!(query.get("size").map(String::as_str), Some("5"));
                    Json(serde_json::json!({"items": [], "count": 0}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_device_local_certificates(
                "dev-456",
                ListRequest::new(0, 5, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["count"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn a_ten_thousand_version_device_pages_through_the_mcp_layer_without_the_8mib_refusal() {
        // `list_config_versions` has no upstream pagination (SDC's endpoint
        // takes no query parameters), so a large tenant's archive used to
        // come back as one response and be refused outright once it crossed
        // `max_response_bytes`. This drives the real HTTP fetch, bounded to a
        // production-sized `max_response_bytes`, then pages the fetched value
        // the way `list_sdc_config_versions` does.
        let app = Router::new().route(
            "/api/v1/devices/{device_uuid}/config/versions",
            get(|| async move {
                let items: Vec<serde_json::Value> = (0..10_000)
                    .map(|index| {
                        serde_json::json!({
                            "version": index,
                            "created_at": "2026-01-01T00:00:00Z",
                            "author": "operator",
                            "comment": "routine archive entry with enough text to matter",
                        })
                    })
                    .collect();
                Json(serde_json::json!({"items": items, "count": 10_000}))
            }),
        );
        let (base_url, server) = serve(app).await;
        // Production-sized cap: the fetch itself must succeed under it.
        let sdc = client(base_url, 8 * 1024 * 1024);
        let fetched = sdc
            .list_config_versions("dev-archive", &CancellationToken::new())
            .await
            .expect("fetch under max_response_bytes succeeds");

        let mut token: Option<String> = None;
        let mut collected = 0usize;
        let mut pages = 0usize;
        loop {
            let page = crate::paging::page_list(&fetched, "items", None, token.as_deref(), 65_536)
                .expect("page succeeds");
            assert_eq!(page.total_item_count, 10_000);
            collected += page.page_item_count;
            pages += 1;
            assert!(pages < 10_000, "paging did not converge");
            match page.continuation_token {
                Some(next) => token = Some(next),
                None => break,
            }
        }
        assert_eq!(collected, 10_000);
        assert!(pages > 1, "10,000 versions must not fit in one 64 KiB page");
        server.abort();
    }

    #[tokio::test]
    async fn list_config_versions_sends_device_uuid_in_path_without_pagination() {
        let app = Router::new().route(
            "/api/v1/devices/{device_uuid}/config/versions",
            get(
                |axum::extract::Path(device_uuid): axum::extract::Path<String>,
                 Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(device_uuid, "dev-789");
                    // This endpoint has no pagination parameters; adding them later
                    // would be a silent contract change.
                    assert!(
                        query.is_empty(),
                        "config versions endpoint must have no query parameters, found: {query:?}"
                    );
                    Json(serde_json::json!({"items": [], "count": 0}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_config_versions("dev-789", &CancellationToken::new())
            .await
            .expect("list succeeds");
        assert_eq!(result["count"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn a_device_uuid_in_config_versions_cannot_escape_its_collection() {
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let recorder = recorder.clone();
            async move {
                recorder
                    .lock()
                    .expect("record path")
                    .push(uri.path().to_owned());
                Json(serde_json::json!({}))
            }
        });
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);

        sdc.list_config_versions("../../api/v1/devices", &CancellationToken::new())
            .await
            .expect("the request is built, not refused");
        let path = seen.lock().expect("read path")[0].clone();
        assert!(
            !path.contains("/../"),
            "path traversal must be percent-encoded, not literal: {path}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn device_config_sections_map_to_their_config_paths() {
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let recorder = recorder.clone();
            async move {
                recorder.lock().expect("record").push(uri.to_string());
                Json(serde_json::json!({"items": [], "count": 0}))
            }
        });
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);
        let ct = CancellationToken::new();
        let page = || ListRequest::new(0, 3, 100).expect("test page");
        for section in [
            DeviceConfigSection::Interfaces,
            DeviceConfigSection::Subinterfaces,
            DeviceConfigSection::Zones,
            DeviceConfigSection::RoutingInstances,
            DeviceConfigSection::IdpSensors,
        ] {
            sdc.list_device_config("d1", section, None, page(), &ct)
                .await
                .expect("list");
        }
        sdc.list_device_config(
            "d1",
            DeviceConfigSection::Subinterfaces,
            Some("ge-0/0/1"),
            page(),
            &ct,
        )
        .await
        .expect("per-interface list");
        sdc.get_device_config_revision("d1", &ct)
            .await
            .expect("revision");
        let seen = seen.lock().expect("read").clone();
        assert_eq!(
            seen,
            vec![
                "/api/v1/devices/d1/config/interfaces?from=0&size=3",
                "/api/v1/devices/d1/config/subinterfaces?from=0&size=3",
                "/api/v1/devices/d1/config/zones?from=0&size=3",
                "/api/v1/devices/d1/config/routing_instances?from=0&size=3",
                "/api/v1/devices/d1/config/idp_sensors?from=0&size=3",
                "/api/v1/devices/d1/config/interfaces/ge-0_0_1/subinterfaces?from=0&size=3",
                "/api/v1/devices/d1/config/latest_version",
            ]
        );
        server.abort();
    }

    #[tokio::test]
    async fn interface_name_is_refused_outside_the_subinterfaces_section() {
        let sdc = client(Url::parse("http://127.0.0.1:9/").expect("url"), 4096);
        let error = sdc
            .list_device_config(
                "d1",
                DeviceConfigSection::Zones,
                Some("ge-0/0/1"),
                ListRequest::new(0, 3, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect_err("interface_name only narrows subinterfaces");
        assert!(matches!(error, SdcError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn interface_name_dot_dot_is_refused() {
        let sdc = client(Url::parse("http://127.0.0.1:9/").expect("url"), 4096);
        let error = sdc
            .list_device_config(
                "d1",
                DeviceConfigSection::Subinterfaces,
                Some(".."),
                ListRequest::new(0, 3, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect_err("dot-dot segment should be refused");
        assert!(matches!(error, SdcError::UrlConstruction));
    }

    #[tokio::test]
    async fn interface_name_dot_dot_slash_becomes_safe_segment() {
        use std::sync::{Arc, Mutex};
        let captured_path = Arc::new(Mutex::new(String::new()));
        let captured_path_clone = Arc::clone(&captured_path);
        let app = Router::new().route(
            "/api/v1/devices/{device_uuid}/config/interfaces/{interface}/subinterfaces",
            get(
                move |axum::extract::Path((_device_uuid, interface)): axum::extract::Path<(
                    String,
                    String,
                )>| {
                    let mut path = captured_path_clone
                        .lock()
                        .expect("lock should not be poisoned");
                    *path = format!("/config/interfaces/{}/subinterfaces", interface);
                    async move { Json(serde_json::json!({"items": [], "count": 0})) }
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let _ = client(base_url, 4096)
            .list_device_config(
                "d1",
                DeviceConfigSection::Subinterfaces,
                Some("../x"),
                ListRequest::new(0, 3, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await;
        let path = captured_path.lock().expect("lock should not be poisoned");
        assert!(
            path.contains(".._x"),
            "path should contain .._x, got: {}",
            path
        );
        server.abort();
    }

    #[tokio::test]
    async fn list_licenses_sends_device_uuid_in_path() {
        let app = Router::new().route(
            "/api/v1/devices/{device_uuid}/licenses",
            get(
                |axum::extract::Path(device_uuid): axum::extract::Path<String>,
                 Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(device_uuid, "dev-789");
                    assert_eq!(query.get("from").map(String::as_str), Some("0"));
                    assert_eq!(query.get("size").map(String::as_str), Some("10"));
                    Json(serde_json::json!({"items": [], "count": 0}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_licenses(
                "dev-789",
                ListRequest::new(0, 10, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["count"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn get_license_sends_both_uuids_in_path() {
        let app = Router::new().route(
            "/api/v1/devices/{device_uuid}/licenses/{license_uuid}",
            get(
                |axum::extract::Path((device_uuid, license_uuid)): axum::extract::Path<(
                    String,
                    String,
                )>| async move {
                    assert_eq!(device_uuid, "dev-abc");
                    assert_eq!(license_uuid, "lic-xyz");
                    Json(serde_json::json!({
                        "uuid": "lic-xyz",
                        "name": "test-license",
                        "state": "valid"
                    }))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .get_license("dev-abc", "lic-xyz", &CancellationToken::new())
            .await
            .expect("get succeeds");
        assert_eq!(result["uuid"], "lic-xyz");
        assert_eq!(result["name"], "test-license");
        server.abort();
    }

    #[tokio::test]
    async fn license_and_certificate_methods_validate_identifiers() {
        let sdc = client(
            Url::parse("https://example.invalid/").expect("test URL"),
            1024,
        );
        // Empty device_uuid is refused
        let error = sdc
            .list_device_ca_certificates(
                "",
                ListRequest::new(0, 10, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect_err("empty device_uuid must be refused");
        assert!(matches!(
            error,
            SdcError::InvalidIdentifier {
                field: "device_uuid"
            }
        ));

        // Control character in license_uuid is refused
        let error = sdc
            .get_license("dev-1", "lic\n123", &CancellationToken::new())
            .await
            .expect_err("license_uuid with control char must be refused");
        assert!(matches!(
            error,
            SdcError::InvalidIdentifier {
                field: "license_uuid"
            }
        ));
    }

    #[tokio::test]
    async fn preview_device_result_requests_xml_format() {
        let app = Router::new().route(
            "/api/v1/policies/preview/{preview_id}/devices/{device_id}",
            get(
                |axum::extract::Path((preview_id, device_id)): axum::extract::Path<(
                    String,
                    String,
                )>,
                 Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(preview_id, "preview-123");
                    assert_eq!(device_id, "device-456");
                    assert_eq!(
                        query.get("format").map(String::as_str),
                        Some("XML"),
                        "preview_device_result must request XML format, not CLI"
                    );
                    Json(serde_json::json!({
                        "config_diff": "<configuration></configuration>"
                    }))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let _result = client(base_url, 4096)
            .preview_device_result("preview-123", "device-456", &CancellationToken::new())
            .await
            .expect("preview_device_result succeeds");
        server.abort();
    }

    #[tokio::test]
    async fn v2_tunnel_list_sends_spec_prefixed_page_parameters() {
        // ListTunnels declares `spec.from`/`spec.size`. Plain `from`/`size`
        // are ignored upstream, leaving the list bounded only by bytes.
        let app = Router::new().route(
            "/api/v2/tunnels",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                assert_eq!(query.get("spec.from").map(String::as_str), Some("5"));
                assert_eq!(query.get("spec.size").map(String::as_str), Some("7"));
                assert!(
                    !query.contains_key("from"),
                    "unprefixed from sent: {query:?}"
                );
                assert!(
                    !query.contains_key("size"),
                    "unprefixed size sent: {query:?}"
                );
                Json(serde_json::json!({"tunnels": [], "total": 0}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_tunnels(
                ListRequest::new(5, 7, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["total"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn list_sites_uses_the_v2_page_parameters() {
        let app = Router::new().route(
            "/api/v2/sites",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                assert_eq!(query.get("spec.from").map(String::as_str), Some("0"));
                assert_eq!(query.get("spec.size").map(String::as_str), Some("3"));
                Json(serde_json::json!({"sites": [], "total": 0}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_sites(
                ListRequest::new(0, 3, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["total"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn list_users_and_roles_uses_the_v2_page_parameters_for_each_collection() {
        // ListUsers and ListRoles both take `spec.from`/`spec.size`, and each
        // collection paginates independently: a tenant with many users but
        // few roles must not be forced to over-fetch roles to match.
        let app = Router::new()
            .route(
                "/api/v2/users",
                get(|Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(query.get("spec.from").map(String::as_str), Some("5"));
                    assert_eq!(query.get("spec.size").map(String::as_str), Some("7"));
                    Json(serde_json::json!({
                        "users": [{
                            "user_id": "u1",
                            "email": "soc@example.com",
                            "name": "SOC Reader",
                            "status": "active",
                            "last_login": "2026-09-01T00:00:00Z",
                            "role": [{"role_name": "viewer"}],
                        }],
                        "user_count": "1",
                    }))
                }),
            )
            .route(
                "/api/v2/roles",
                get(|Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(query.get("spec.from").map(String::as_str), Some("0"));
                    assert_eq!(query.get("spec.size").map(String::as_str), Some("2"));
                    Json(serde_json::json!({
                        "roles": [{
                            "UUID": "r1",
                            "name": "viewer",
                            "capabilities": ["read"],
                            "predefined": true,
                        }],
                        "role_count": "1",
                    }))
                }),
            );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_users_and_roles(
                ListRequest::new(5, 7, 100).expect("test page"),
                ListRequest::new(0, 2, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("combined list succeeds");
        assert_eq!(result["users"]["users"][0]["name"], "SOC Reader");
        assert_eq!(result["users"]["users"][0]["user_id"], "u1");
        assert_eq!(result["roles"]["roles"][0]["name"], "viewer");
        assert!(result["users"]["users"][0].get("api_key").is_none());
        assert!(result["users"]["users"][0].get("password").is_none());
        server.abort();
    }

    #[tokio::test]
    async fn list_users_and_roles_fails_closed_when_either_call_errors() {
        // A roles-side failure must not surface as a users-only "clean" list;
        // the whole call errors rather than returning partial data unlabeled.
        let app = Router::new()
            .route(
                "/api/v2/users",
                get(|| async move { Json(serde_json::json!({"users": [], "user_count": "0"})) }),
            )
            .route(
                "/api/v2/roles",
                get(|| async move { (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response() }),
            );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_users_and_roles(
                ListRequest::new(0, 5, 100).expect("test page"),
                ListRequest::new(0, 5, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            result.is_err(),
            "a roles-side error must fail the whole call"
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_large_tenants_users_and_roles_page_independently_through_the_mcp_layer() {
        // `list_users_and_roles` combines two independently-sized SDC
        // collections into one `{"users": ..., "roles": ...}` envelope. A
        // tenant with many more users than roles must not force the roles
        // sub-list to share a continuation cursor with users, and the byte
        // budget each sub-list pages against must be independent: this
        // drives the real fetch, then pages each sub-list the way
        // `list_users_and_roles` does in the server, with a budget tight
        // enough that each sub-list needs more than one page on its own.
        let app = Router::new()
            .route(
                "/api/v2/users",
                get(|| async move {
                    let users: Vec<serde_json::Value> = (0..500)
                        .map(|index| {
                            serde_json::json!({
                                "user_id": format!("u{index}"),
                                "email": format!("user{index}@example.com"),
                                "name": format!("User {index} with a reasonably long display name"),
                                "status": "active",
                                "last_login": "2026-09-01T00:00:00Z",
                                "role": [{"role_name": "viewer"}],
                            })
                        })
                        .collect();
                    Json(serde_json::json!({"users": users, "user_count": "500"}))
                }),
            )
            .route(
                "/api/v2/roles",
                get(|| async move {
                    let roles: Vec<serde_json::Value> = (0..40)
                        .map(|index| {
                            serde_json::json!({
                                "UUID": format!("r{index}"),
                                "name": format!("role-{index}"),
                                "capabilities": ["read", "write", "approve"],
                                "predefined": false,
                            })
                        })
                        .collect();
                    Json(serde_json::json!({"roles": roles, "role_count": "40"}))
                }),
            );
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 8 * 1024 * 1024);
        // `client()` configures `max_page_size` 100; the test endpoint ignores
        // the requested size and returns the full 500/40 tenant regardless,
        // simulating an SDC response larger than what was asked for.
        let fetched = sdc
            .list_users_and_roles(
                ListRequest::new(0, 100, 100).expect("test page"),
                ListRequest::new(0, 40, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("combined fetch succeeds");
        let projected = crate::project_users_and_roles(fetched).expect("projection succeeds");
        let users_envelope = projected["users"].clone();
        let roles_envelope = projected["roles"].clone();

        let mut users_token: Option<String> = None;
        let mut users_seen = 0usize;
        let mut users_pages = 0usize;
        loop {
            let page = crate::paging::page_list(
                &users_envelope,
                "users",
                None,
                users_token.as_deref(),
                4_096,
            )
            .expect("users page succeeds");
            assert_eq!(page.total_item_count, 500);
            users_seen += page.page_item_count;
            users_pages += 1;
            assert!(users_pages < 500, "users paging did not converge");
            match page.continuation_token {
                Some(next) => users_token = Some(next),
                None => break,
            }
        }
        assert_eq!(users_seen, 500);
        assert!(users_pages > 1, "500 users must not fit in one 4 KiB page");

        let mut roles_token: Option<String> = None;
        let mut roles_seen = 0usize;
        let mut roles_pages = 0usize;
        loop {
            let page = crate::paging::page_list(
                &roles_envelope,
                "roles",
                None,
                roles_token.as_deref(),
                4_096,
            )
            .expect("roles page succeeds");
            assert_eq!(page.total_item_count, 40);
            roles_seen += page.page_item_count;
            roles_pages += 1;
            assert!(roles_pages < 40, "roles paging did not converge");
            match page.continuation_token {
                Some(next) => roles_token = Some(next),
                None => break,
            }
        }
        assert_eq!(roles_seen, 40);
        server.abort();
    }

    #[tokio::test]
    async fn get_site_addresses_the_site_by_one_encoded_name_segment() {
        let app = Router::new().route(
            "/api/v2/site/{site_name}",
            get(
                |axum::extract::Path(site_name): axum::extract::Path<String>| async move {
                    Json(serde_json::json!({"site": {"site_name": site_name}}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .get_site("branch/../1", &CancellationToken::new())
            .await
            .expect("get succeeds");
        assert_eq!(result["site"]["site_name"], "branch/../1");
        server.abort();
    }

    #[tokio::test]
    async fn ips_rule_reads_use_the_ips_rules_and_exempt_rules_segments() {
        let app = Router::new()
            .route(
                "/api/v1/ips_profiles/{profile}/ips_rules",
                get(|Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(query.get("size").map(String::as_str), Some("2"));
                    Json(serde_json::json!({"items": [], "count": 0, "kind": "ips"}))
                }),
            )
            .route(
                "/api/v1/ips_profiles/{profile}/ips_rules/{rule}",
                get(|axum::extract::Path((p, r)): axum::extract::Path<(String, String)>| async move {
                    Json(serde_json::json!({"profile": p, "rule": r}))
                }),
            )
            .route(
                "/api/v1/ips_profiles/{profile}/exempt_rules",
                get(|| async { Json(serde_json::json!({"items": [], "count": 0, "kind": "exempt"})) }),
            )
            .route(
                "/api/v1/ips_profiles/{profile}/exempt_rules/{rule}",
                get(|axum::extract::Path((p, r)): axum::extract::Path<(String, String)>| async move {
                    Json(serde_json::json!({"profile": p, "exempt": r}))
                }),
            );
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);
        let ct = CancellationToken::new();
        let page = || ListRequest::new(0, 2, 100).expect("test page");
        assert_eq!(
            sdc.list_ips_rules("p1", page(), &ct).await.expect("list")["kind"],
            "ips"
        );
        assert_eq!(
            sdc.get_ips_rule("p1", "r1", &ct).await.expect("get")["rule"],
            "r1"
        );
        assert_eq!(
            sdc.list_ips_exempt_rules("p1", page(), &ct)
                .await
                .expect("list")["kind"],
            "exempt"
        );
        assert_eq!(
            sdc.get_ips_exempt_rule("p1", "e1", &ct).await.expect("get")["exempt"],
            "e1"
        );
        server.abort();
    }

    #[tokio::test]
    async fn ips_rule_reads_refuse_empty_identifiers() {
        let sdc = client(Url::parse("http://127.0.0.1:9/").expect("url"), 4096);
        let ct = CancellationToken::new();
        assert!(matches!(
            sdc.get_ips_rule("", "r1", &ct).await,
            Err(SdcError::InvalidIdentifier {
                field: "profile_uuid"
            })
        ));
        assert!(matches!(
            sdc.get_ips_exempt_rule("p1", "", &ct).await,
            Err(SdcError::InvalidIdentifier { field: "rule_uuid" })
        ));
    }

    #[tokio::test]
    async fn ecf_reads_nest_rule_sets_under_the_profile_and_rules_under_the_set() {
        let app = Router::new()
            .route(
                "/api/v1/enhanced_content_filtering_profiles/{p}/rule_sets",
                get(
                    |axum::extract::Path(p): axum::extract::Path<String>| async move {
                        Json(serde_json::json!({"items": [], "count": 0, "profile": p}))
                    },
                ),
            )
            .route(
                "/api/v1/enhanced_content_filtering_profiles/{p}/rule_sets/{s}/rules",
                get(
                    |axum::extract::Path((p, s)): axum::extract::Path<(String, String)>,
                     Query(query): Query<HashMap<String, String>>| async move {
                        assert_eq!(query.get("size").map(String::as_str), Some("4"));
                        Json(serde_json::json!({"items": [], "count": 0, "profile": p, "set": s}))
                    },
                ),
            );
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);
        let ct = CancellationToken::new();
        let page = || ListRequest::new(0, 4, 100).expect("test page");
        assert_eq!(
            sdc.list_ecf_rule_sets("p1", page(), &ct)
                .await
                .expect("sets")["profile"],
            "p1"
        );
        let rules = sdc
            .list_ecf_rules("p1", "s1", page(), &ct)
            .await
            .expect("rules");
        assert_eq!(
            (rules["profile"].as_str(), rules["set"].as_str()),
            (Some("p1"), Some("s1"))
        );
        server.abort();
    }

    #[tokio::test]
    async fn singleton_reads_send_no_query_and_refuse_an_oversized_body() {
        let app = Router::new()
            .route(
                "/api/v1/firewall_global_settings",
                get(|Query(query): Query<HashMap<String, String>>| async move {
                    assert!(query.is_empty(), "singleton sent a query: {query:?}");
                    Json(serde_json::json!({"ok": "settings"}))
                }),
            )
            .route(
                "/api/v1/firewall_global_profiles",
                get(|| async { Json(serde_json::json!({"ok": "profile"})) }),
            )
            .route(
                "/api/v1/content_security_settings",
                get(|| async { Json(serde_json::json!({"padding": "x".repeat(512)})) }),
            );
        let (base_url, server) = serve(app).await;
        let ct = CancellationToken::new();
        let roomy = client(base_url.clone(), 4096);
        assert_eq!(
            roomy
                .get_firewall_global_settings(&ct)
                .await
                .expect("settings")["ok"],
            "settings"
        );
        assert_eq!(
            roomy
                .get_firewall_global_profile(&ct)
                .await
                .expect("profile")["ok"],
            "profile"
        );
        let tight = client(base_url, 64);
        assert!(matches!(
            tight.get_content_security_settings(&ct).await,
            Err(SdcError::ResponseTooLarge { limit: 64 })
        ));
        server.abort();
    }

    #[tokio::test]
    async fn device_global_settings_page_with_offset_and_limit() {
        let app = Router::new().route(
            "/api/v1/firewall_device_global_settings",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                assert_eq!(query.get("offset").map(String::as_str), Some("2"));
                assert_eq!(query.get("limit").map(String::as_str), Some("5"));
                assert_eq!(query.get("device_id").map(String::as_str), Some("d1"));
                assert!(
                    !query.contains_key("size"),
                    "from/size vocabulary leaked: {query:?}"
                );
                Json(serde_json::json!({"items": [], "count": 0}))
            }),
        );
        let (base_url, server) = serve(app).await;
        client(base_url, 4096)
            .list_device_global_settings(
                Some("d1"),
                ListRequest::new(2, 5, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        server.abort();
    }

    #[tokio::test]
    async fn image_reads_use_the_definition_list_and_job_status_paths() {
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let recorder = recorder.clone();
            async move {
                recorder.lock().expect("record").push(uri.to_string());
                Json(serde_json::json!({}))
            }
        });
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);
        let ct = CancellationToken::new();
        sdc.list_image_definitions(ListRequest::new(0, 2, 100).expect("page"), &ct)
            .await
            .expect("list");
        sdc.get_image_job_status(ImageJob::Stage, "s1", &ct)
            .await
            .expect("stage");
        sdc.get_image_job_status(ImageJob::Deploy, "d1", &ct)
            .await
            .expect("deploy");
        assert_eq!(
            seen.lock().expect("read").clone(),
            vec![
                "/api/v1/device_image_definitions?from=0&size=2",
                "/api/v1/device_image_definitions/stage_image/s1",
                "/api/v1/device_image_definitions/deploy_image/d1",
            ]
        );
        server.abort();
    }

    #[tokio::test]
    async fn mnha_and_rma_status_reads_use_their_spec_paths() {
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let recorder = recorder.clone();
            async move {
                recorder.lock().expect("record").push(uri.to_string());
                Json(serde_json::json!({}))
            }
        });
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);
        let ct = CancellationToken::new();
        sdc.get_mnha_sync_status("m1", &ct).await.expect("mnha");
        sdc.get_rma_state("dev1", &ct).await.expect("rma state");
        sdc.get_rma_reactivation_status("r1", &ct)
            .await
            .expect("reactivation");
        assert_eq!(
            seen.lock().expect("read").clone(),
            vec![
                "/api/v1/mnha_clusters/sync/m1",
                "/api/v1/devices/dev1/rma/state",
                "/api/v1/devices/rma/reactivate/r1",
            ]
        );
        server.abort();
    }
}
