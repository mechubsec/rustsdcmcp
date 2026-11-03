//! Operator configuration for one Security Director Cloud tenant.

use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;

const DEFAULT_ENDPOINT: &str = "https://api.sdcloud.juniperclouds.net/";

/// SDC authentication header selected by the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthScheme {
    /// The `x-api-key` header.
    ApiKey,
    /// The opaque `x-oauth2-token` header.
    Oauth2Token,
}

impl AuthScheme {
    /// Exact header name documented by SDC.
    #[must_use]
    pub const fn header_name(self) -> &'static str {
        match self {
            Self::ApiKey => "x-api-key",
            Self::Oauth2Token => "x-oauth2-token",
        }
    }
}

/// Product-owned job polling settings.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PollSettings {
    pub(crate) initial: Duration,
    pub(crate) maximum: Duration,
    pub(crate) deadline: Duration,
}

/// Configuration for one SDC tenant.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdcConfig {
    /// Configuration schema version.
    pub version: u32,
    /// Stable local tenant alias used by MCP scopes.
    pub tenant: String,
    /// Tenant identifier that the startup scope probe must return.
    pub expected_tenant_id: String,
    /// Name of the environment variable containing the SDC credential.
    ///
    /// The secret value itself never enters configuration. Generalized secret
    /// sources are tracked in `mecmcp` issue #90.
    pub credential_env: String,
    /// SDC authentication mechanism.
    pub auth_scheme: AuthScheme,
    /// SDC HTTPS API base URL.
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    /// TCP/TLS connection timeout in milliseconds.
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Whole-request timeout in milliseconds.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Maximum accepted response body.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    /// Maximum simultaneous outbound requests.
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: usize,
    /// Maximum page size accepted by list tools.
    #[serde(default = "default_max_page_size")]
    pub max_page_size: u32,
    /// Byte budget for one page of a budget-paginated list result -- a list
    /// SDC itself has no `from`/`size` parameters for, such as
    /// `list_sdc_config_versions`. Independent of `max_response_bytes`,
    /// which bounds the raw SDC response before it is paged.
    #[serde(default = "default_list_page_budget_bytes")]
    pub list_page_budget_bytes: usize,
    /// Initial job-poll interval in milliseconds.
    #[serde(default = "default_poll_initial_ms")]
    pub poll_initial_ms: u64,
    /// Maximum job-poll interval in milliseconds.
    #[serde(default = "default_poll_max_ms")]
    pub poll_max_ms: u64,
    /// Whole job-poll deadline in milliseconds.
    #[serde(default = "default_poll_deadline_ms")]
    pub poll_deadline_ms: u64,
    /// Optional absolute durable change-set state file.
    ///
    /// When omitted, change state is in-memory and does not survive restart.
    #[serde(default)]
    pub changeset_state_file: Option<PathBuf>,
    /// Two-person approval lifetime in seconds.
    #[serde(default = "default_approval_ttl_secs")]
    pub approval_ttl_secs: u64,
    /// Optional explicit HTTP(S) egress proxy for all outbound SDC traffic.
    ///
    /// Unset by default: the client never autodiscovers a proxy from
    /// environment variables. When set, every request goes through this one
    /// proxy; the fixed SDC endpoint is unaffected, so this cannot be used to
    /// redirect requests to an unintended host.
    #[serde(default)]
    pub egress_proxy: Option<String>,
}

/// Hand-written so `egress_proxy` prints only its origin: the URL's userinfo
/// may carry proxy credentials.
impl std::fmt::Debug for SdcConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive, so a new field cannot be added without deciding how it prints.
        let Self {
            version,
            tenant,
            expected_tenant_id,
            credential_env,
            auth_scheme,
            endpoint,
            connect_timeout_ms,
            request_timeout_ms,
            max_response_bytes,
            max_concurrency,
            max_page_size,
            list_page_budget_bytes,
            poll_initial_ms,
            poll_max_ms,
            poll_deadline_ms,
            changeset_state_file,
            approval_ttl_secs,
            egress_proxy,
        } = self;
        let egress_proxy_origin = egress_proxy.as_deref().map(|raw| {
            Url::parse(raw).map_or_else(
                |_| "<unparsable>".to_owned(),
                |url| url.origin().ascii_serialization(),
            )
        });
        formatter
            .debug_struct("SdcConfig")
            .field("version", version)
            .field("tenant", tenant)
            .field("expected_tenant_id", expected_tenant_id)
            .field("credential_env", credential_env)
            .field("auth_scheme", auth_scheme)
            .field("endpoint", endpoint)
            .field("connect_timeout_ms", connect_timeout_ms)
            .field("request_timeout_ms", request_timeout_ms)
            .field("max_response_bytes", max_response_bytes)
            .field("max_concurrency", max_concurrency)
            .field("max_page_size", max_page_size)
            .field("list_page_budget_bytes", list_page_budget_bytes)
            .field("poll_initial_ms", poll_initial_ms)
            .field("poll_max_ms", poll_max_ms)
            .field("poll_deadline_ms", poll_deadline_ms)
            .field("changeset_state_file", changeset_state_file)
            .field("approval_ttl_secs", approval_ttl_secs)
            .field("egress_proxy", &egress_proxy_origin)
            .finish()
    }
}

impl SdcConfig {
    /// Parse and validate a JSON configuration file.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration error for I/O, JSON, or unsafe values.
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        let bytes = std::fs::read(path).map_err(ConfigError::Read)?;
        let config: Self = serde_json::from_slice(&bytes).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate identifiers, resource bounds, polling, and the HTTPS endpoint.
    ///
    /// # Errors
    ///
    /// Refuses unknown versions, empty values, unsafe endpoints, and zero or
    /// internally inconsistent limits.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::Invalid("version must be 1"));
        }
        validate_identifier("tenant", &self.tenant)?;
        validate_identifier("expected_tenant_id", &self.expected_tenant_id)?;
        validate_env_name(&self.credential_env)?;
        validate_endpoint(&self.endpoint)?;
        if self.connect_timeout_ms == 0
            || self.request_timeout_ms == 0
            || self.max_response_bytes == 0
            || !(1..=1024).contains(&self.max_concurrency)
            || self.max_page_size == 0
            || self.list_page_budget_bytes == 0
            || self.approval_ttl_secs == 0
        {
            return Err(ConfigError::Invalid(
                "HTTP timeouts and bounds must be nonzero and max_concurrency at most 1024",
            ));
        }
        if self
            .changeset_state_file
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(ConfigError::Invalid(
                "changeset_state_file must be an absolute path",
            ));
        }
        self.poll_settings()?;
        self.egress_proxy_url()?;
        Ok(())
    }

    /// Validated API base URL.
    pub(crate) fn base_url(&self) -> Result<Url, ConfigError> {
        validate_endpoint(&self.endpoint)
    }

    /// Validated egress proxy URL, if the operator configured one.
    pub(crate) fn egress_proxy_url(&self) -> Result<Option<Url>, ConfigError> {
        let Some(raw) = self.egress_proxy.as_deref() else {
            return Ok(None);
        };
        let url =
            Url::parse(raw).map_err(|_| ConfigError::Invalid("egress_proxy is not a valid URL"))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none_or(str::is_empty) {
            return Err(ConfigError::Invalid(
                "egress_proxy must be an http(s) URL with a host",
            ));
        }
        Ok(Some(url))
    }

    /// Validated product-owned job polling settings.
    pub(crate) fn poll_settings(&self) -> Result<PollSettings, ConfigError> {
        let settings = PollSettings {
            initial: Duration::from_millis(self.poll_initial_ms),
            maximum: Duration::from_millis(self.poll_max_ms),
            deadline: Duration::from_millis(self.poll_deadline_ms),
        };
        if settings.initial.is_zero()
            || settings.maximum.is_zero()
            || settings.deadline.is_zero()
            || settings.initial > settings.maximum
            || settings.maximum > settings.deadline
        {
            return Err(ConfigError::Invalid(
                "poll intervals require nonzero initial <= maximum <= deadline",
            ));
        }
        Ok(settings)
    }
}

fn validate_endpoint(raw: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(raw).map_err(|_| ConfigError::Invalid("endpoint is not a valid URL"))?;
    if url.scheme() != "https"
        || url.host_str() != Some("api.sdcloud.juniperclouds.net")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ConfigError::Invalid(
            "endpoint must be an HTTPS base URL without credentials, path, query, fragment, or port",
        ));
    }
    Ok(url)
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ConfigError::Invalid(match field {
            "tenant" => "tenant must be 1-256 non-whitespace bytes",
            _ => "expected_tenant_id must be 1-256 non-whitespace bytes",
        }));
    }
    Ok(())
}

fn validate_env_name(value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(ConfigError::Invalid(
            "credential_env must be 1-128 ASCII alphanumeric/underscore bytes",
        ));
    }
    Ok(())
}

fn default_endpoint() -> String {
    DEFAULT_ENDPOINT.to_owned()
}
const fn default_connect_timeout_ms() -> u64 {
    10_000
}
const fn default_request_timeout_ms() -> u64 {
    30_000
}
const fn default_max_response_bytes() -> usize {
    8 * 1024 * 1024
}
const fn default_max_concurrency() -> usize {
    16
}
const fn default_max_page_size() -> u32 {
    200
}
const fn default_list_page_budget_bytes() -> usize {
    131_072
}
const fn default_poll_initial_ms() -> u64 {
    250
}
const fn default_poll_max_ms() -> u64 {
    3_000
}
const fn default_poll_deadline_ms() -> u64 {
    120_000
}
const fn default_approval_ttl_secs() -> u64 {
    3_600
}

/// SDC configuration failure.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Configuration file read failed.
    #[error("failed to read SDC configuration: {0}")]
    Read(std::io::Error),
    /// Configuration JSON was invalid.
    #[error("failed to parse SDC configuration: {0}")]
    Parse(serde_json::Error),
    /// A field failed validation.
    #[error("invalid SDC configuration: {0}")]
    Invalid(&'static str),
}
