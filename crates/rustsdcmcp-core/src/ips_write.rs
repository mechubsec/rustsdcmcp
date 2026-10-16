//! Change-controlled writes to SDC IPS content: signatures, profiles, IPS rules
//! and exempt rules.
//!
//! IPS writes have no SDC-side preview endpoint, so the plan artifact is built
//! locally: it records the exact request together with the target's observed
//! state beforehand. Apply refuses if that state has since moved, which is the
//! IPS analogue of binding a deploy to its preview.
//!
//! An IPS write changes SDC's model only. It does not deploy: reaching a device
//! still takes `prepare_sdc_policy_deploy`, approval and `apply_sdc_change_set`.
//!
//! Guards specific to IPS:
//!
//! - **Custom signatures only.** A signature update or delete is refused unless
//!   the observed signature is positively identified as custom, see
//!   [`is_custom_signature`].
//! - **Referenced profiles are not deleted.** A profile delete is refused while
//!   any firewall rule's `advanced_security.ips_profile` points at it.
//!
//! The plan digest covers the exact request body, never a redacted rendering.
//! Signature `pattern_sets[].expression` values are free text that the generic
//! redactor would corrupt, so tool output carries them verbatim (see
//! `redact::redact_secrets`) together with a per-expression digest from
//! [`expression_digests`] that makes any mismatch detectable.

use crate::{SdcClient, SdcError, prepared::canonical_digest};
use async_trait::async_trait;
use mecmcp_audit::Attribution;
use mecmcp_changeset::{
    CommitOptions, CommitOutcome, DeviceTransaction, RollbackOutcome, RollbackRef, UnlockOutcome,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio_util::sync::CancellationToken;

/// Hard cap on one serialized IPS-write envelope.
const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;

/// Which IPS object family one write targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IpsFamily {
    /// A custom IPS signature (`/api/v1/ips_signatures`).
    Signature,
    /// An IPS profile (`/api/v1/ips_profiles`).
    Profile,
    /// An IPS rule inside a profile (`.../ips_profiles/{profile_uuid}/ips_rules`).
    Rule,
    /// An exempt rule inside a profile (`.../ips_profiles/{profile_uuid}/exempt_rules`).
    ExemptRule,
}

impl IpsFamily {
    /// Whether this family lives under a profile and so needs `profile_uuid`.
    #[must_use]
    pub const fn is_profile_scoped(self) -> bool {
        matches!(self, Self::Rule | Self::ExemptRule)
    }

    /// Stable name recorded in audit and change-control state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::Profile => "profile",
            Self::Rule => "rule",
            Self::ExemptRule => "exempt_rule",
        }
    }
}

/// Which mutation one IPS write performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IpsWriteAction {
    /// Create a new object in the family.
    Create,
    /// Replace an existing object by UUID.
    Update,
    /// Delete an existing object by UUID.
    Delete,
}

impl IpsWriteAction {
    /// Stable discriminator recorded in audit and change-control state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "ips_create",
            Self::Update => "ips_update",
            Self::Delete => "ips_delete",
        }
    }
}

/// Whether an observed signature is positively identified as custom.
///
/// The vendored OpenAPI export has no `custom` or `predefined` field. Its
/// `signature_type` enum (`anomaly`, `signature`, `chain`, `static`,
/// `dynamic`) describes the detection kind, which custom and predefined
/// signatures share. The only documented difference is provenance: `import_id`
/// is "applicable only for predefined signatures imported from signature
/// bundles, not for custom signatures or groups", and `activation_date` is
/// set when a bundle activates a signature.
///
/// So a signature counts as custom only when it is a JSON object, carries a
/// known `signature_type`, and has an absent or empty `import_id` and
/// `activation_date`. Anything else, including a value of an unexpected type,
/// is treated as not custom. The check fails closed: a predefined signature
/// that a tenant renders without those fields would be a false positive, which
/// is why the live-tenant validation in the issue must confirm the field.
#[must_use]
pub fn is_custom_signature(observed: &Value) -> bool {
    let Some(fields) = observed.as_object() else {
        return false;
    };
    let known_type = matches!(
        fields.get("signature_type").and_then(Value::as_str),
        Some("anomaly" | "signature" | "chain" | "static" | "dynamic")
    );
    let blank = |key: &str| match fields.get(key) {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty(),
        Some(_) => false,
    };
    known_type && blank("import_id") && blank("activation_date")
}

/// Digest of one signature pattern expression, for approver cross-checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpressionDigest {
    /// Where the expression sits, for example `request.pattern_sets[0].expression`.
    pub location: String,
    /// Canonical SHA-256 digest of the exact expression string.
    pub digest: String,
}

/// Digest every `pattern_sets[].expression` in the request and observed state.
///
/// Tool output carries the expressions verbatim, so this is a second line of
/// defence: an approver (or a downstream renderer that mangles text) can
/// compare the digest with one computed from what they actually read.
#[must_use]
pub fn expression_digests(request: &Value, before: &Value) -> Vec<ExpressionDigest> {
    let mut digests = Vec::new();
    for (label, body) in [("before", before), ("request", request)] {
        let Some(sets) = body.get("pattern_sets").and_then(Value::as_array) else {
            continue;
        };
        for (index, set) in sets.iter().enumerate() {
            let Some(expression) = set.get("expression").and_then(Value::as_str) else {
                continue;
            };
            if let Ok(digest) = canonical_digest(&Value::String(expression.to_owned())) {
                digests.push(ExpressionDigest {
                    location: format!("{label}.pattern_sets[{index}].expression"),
                    digest,
                });
            }
        }
    }
    digests
}

/// Strictly validate an identifier that becomes a URL path segment.
///
/// Stricter than the client's own check: only the characters of SDC's UUID
/// format other than `/` are allowed, so a separator, query, fragment, escape
/// or relative-path segment can never ride in an identifier.
///
/// # Errors
///
/// Returns [`SdcError::InvalidIdentifier`] for an empty, oversized or
/// out-of-alphabet value.
pub(crate) fn validate_ips_identifier(field: &'static str, value: &str) -> Result<(), SdcError> {
    let allowed =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'+' | b'=');
    if value.is_empty() || value.len() > 256 || !value.bytes().all(allowed) {
        return Err(SdcError::InvalidIdentifier { field });
    }
    Ok(())
}

/// Exact IPS write bound into a change-set action.
///
/// Product-owned while its vendor-neutral extraction is tracked in mecmcp#90.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdcPreparedIpsWrite {
    operation: String,
    family: IpsFamily,
    action: IpsWriteAction,
    uuid: Option<String>,
    profile_uuid: Option<String>,
    request: Value,
    before: Value,
    plan_digest: String,
}

impl SdcPreparedIpsWrite {
    /// Build a canonical, digest-bound IPS write.
    ///
    /// `before` is the target's observed state for update and delete, and
    /// `Value::Null` for create.
    ///
    /// # Errors
    ///
    /// Refuses shapes that do not match the action or family, unsafe
    /// identifiers, an update or delete of a signature that is not custom, and
    /// oversized envelopes.
    pub fn new(
        family: IpsFamily,
        action: IpsWriteAction,
        uuid: Option<String>,
        profile_uuid: Option<String>,
        request: Value,
        before: Value,
    ) -> Result<Self, SdcError> {
        let plan = plan_artifact(
            family,
            action,
            uuid.as_deref(),
            profile_uuid.as_deref(),
            &request,
            &before,
        );
        let prepared = Self {
            operation: "ips_write".to_owned(),
            family,
            action,
            uuid,
            profile_uuid,
            request,
            before,
            plan_digest: canonical_digest(&plan)
                .map_err(|error| SdcError::PreparedChange(error.to_string()))?,
        };
        prepared.validate()?;
        Ok(prepared)
    }

    /// Product operation discriminator.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Which object family this write targets.
    #[must_use]
    pub const fn family(&self) -> IpsFamily {
        self.family
    }

    /// Which mutation this write performs.
    #[must_use]
    pub const fn action(&self) -> IpsWriteAction {
        self.action
    }

    /// Target object UUID, absent for create.
    #[must_use]
    pub fn uuid(&self) -> Option<&str> {
        self.uuid.as_deref()
    }

    /// Owning profile UUID, present only for rule and exempt-rule writes.
    #[must_use]
    pub fn profile_uuid(&self) -> Option<&str> {
        self.profile_uuid.as_deref()
    }

    /// Exact request body, `Null` for delete.
    #[must_use]
    pub const fn request(&self) -> &Value {
        &self.request
    }

    /// Object state observed at prepare time, `Null` for create.
    #[must_use]
    pub const fn before(&self) -> &Value {
        &self.before
    }

    /// Canonical SHA-256 digest binding this plan.
    #[must_use]
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    /// Human-readable plan showing what this write would change.
    #[must_use]
    pub fn plan(&self) -> Value {
        plan_artifact(
            self.family,
            self.action,
            self.uuid.as_deref(),
            self.profile_uuid.as_deref(),
            &self.request,
            &self.before,
        )
    }

    /// Per-expression digests for the signature patterns in this write.
    #[must_use]
    pub fn expression_digests(&self) -> Vec<ExpressionDigest> {
        expression_digests(&self.request, &self.before)
    }

    /// Revalidate shape, guards, bounds, and digest integrity.
    ///
    /// # Errors
    ///
    /// Returns a stable error if persisted content was malformed or tampered.
    pub fn validate(&self) -> Result<(), SdcError> {
        if self.operation != "ips_write" {
            return Err(SdcError::PreparedChange(
                "prepared operation must be ips_write".to_owned(),
            ));
        }
        let has_uuid = self.uuid.is_some();
        // Match the client's body rule so an unexecutable plan cannot be
        // approved: discovering an empty body only at commit would burn a
        // change set.
        let request_is_populated_object = self
            .request
            .as_object()
            .is_some_and(|fields| !fields.is_empty());
        let before_is_object = self.before.is_object();
        let shape_ok = match self.action {
            IpsWriteAction::Create => {
                !has_uuid && request_is_populated_object && self.before.is_null()
            }
            IpsWriteAction::Update => has_uuid && request_is_populated_object && before_is_object,
            IpsWriteAction::Delete => has_uuid && self.request.is_null() && before_is_object,
        };
        if !shape_ok {
            return Err(SdcError::PreparedChange(format!(
                "prepared {} does not match its required shape",
                self.action.as_str()
            )));
        }
        if self.family.is_profile_scoped() != self.profile_uuid.is_some() {
            return Err(SdcError::PreparedChange(format!(
                "profile_uuid is required for rule and exempt_rule and rejected for others; got {} {}",
                self.family.as_str(),
                if self.profile_uuid.is_some() {
                    "with a profile_uuid"
                } else {
                    "without one"
                }
            )));
        }
        if let Some(uuid) = self.uuid.as_deref() {
            validate_ips_identifier("uuid", uuid)
                .map_err(|error| SdcError::PreparedChange(error.to_string()))?;
        }
        if let Some(profile_uuid) = self.profile_uuid.as_deref() {
            validate_ips_identifier("profile_uuid", profile_uuid)
                .map_err(|error| SdcError::PreparedChange(error.to_string()))?;
        }
        if crate::redact::contains_redaction_marker(&self.request) {
            return Err(SdcError::PreparedChange(
                "write body contains a redaction marker; re-read the field value out-of-band"
                    .to_owned(),
            ));
        }
        if self.family == IpsFamily::Signature {
            self.validate_signature_guards()?;
        }
        let plan = self.plan();
        if canonical_digest(&plan).map_err(|error| SdcError::PreparedChange(error.to_string()))?
            != self.plan_digest
        {
            return Err(SdcError::PreparedChange(
                "prepared IPS write does not match its digest".to_owned(),
            ));
        }
        if serde_json::to_vec(self)
            .map_err(|_| SdcError::Serialization)?
            .len()
            > MAX_ENVELOPE_BYTES
        {
            return Err(SdcError::PreparedChange(
                "prepared IPS write exceeds the 2097152-byte limit".to_owned(),
            ));
        }
        Ok(())
    }

    /// Custom-only guard for signatures.
    fn validate_signature_guards(&self) -> Result<(), SdcError> {
        if self
            .request
            .as_object()
            .is_some_and(|fields| fields.contains_key("import_id"))
        {
            return Err(SdcError::IpsGuard(
                "import_id is read-only and marks a predefined signature; it cannot be written"
                    .to_owned(),
            ));
        }
        if !matches!(self.action, IpsWriteAction::Update | IpsWriteAction::Delete) {
            return Ok(());
        }
        if !is_custom_signature(&self.before) {
            return Err(SdcError::IpsGuard(
                "only custom IPS signatures can be updated or deleted; this signature is \
                 predefined or could not be positively identified as custom"
                    .to_owned(),
            ));
        }
        if let (Some(observed), Some(target)) = (
            self.before.get("uuid").and_then(Value::as_str),
            self.uuid.as_deref(),
        ) && observed != target
        {
            return Err(SdcError::PreparedChange(
                "observed signature does not match the target UUID".to_owned(),
            ));
        }
        Ok(())
    }
}

fn plan_artifact(
    family: IpsFamily,
    action: IpsWriteAction,
    uuid: Option<&str>,
    profile_uuid: Option<&str>,
    request: &Value,
    before: &Value,
) -> Value {
    json!({
        "family": family,
        "action": action,
        "uuid": uuid,
        "profile_uuid": profile_uuid,
        "before": before,
        "after": request,
    })
}

/// Outcome of revalidating an IPS write immediately before commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsValidationReport {
    /// Whether the envelope is intact and the target has not drifted.
    pub valid: bool,
    /// Which family was validated.
    pub family: IpsFamily,
    /// Which mutation was validated.
    pub action: IpsWriteAction,
    /// Whether the live object still matched its prepared `before` state.
    pub target_unchanged: bool,
}

/// SDC implementation of the shared transaction contract for IPS writes.
#[derive(Clone)]
pub struct SdcIpsTransaction {
    client: SdcClient,
    expected_plan_digest: String,
    cancellation: CancellationToken,
    refused_before_write: Arc<AtomicBool>,
}

impl SdcIpsTransaction {
    /// Bind a transaction to one exact plan digest.
    #[must_use]
    pub fn new(
        client: SdcClient,
        expected_plan_digest: impl Into<String>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            client,
            expected_plan_digest: expected_plan_digest.into(),
            cancellation,
            refused_before_write: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Whether commit refused before issuing any request to SDC.
    ///
    /// The coordinator flattens a transaction error into a string, so this is
    /// how the caller distinguishes "nothing was written, safe to discard" from
    /// "the write may have landed".
    #[must_use]
    pub fn refused_before_write(&self) -> bool {
        self.refused_before_write.load(Ordering::SeqCst)
    }

    /// Re-read the target and report whether it still matches its plan.
    ///
    /// Create has no prior object, so it is vacuously unchanged.
    async fn target_unchanged(&self, staged: &SdcPreparedIpsWrite) -> Result<bool, SdcError> {
        let (IpsWriteAction::Update | IpsWriteAction::Delete, Some(uuid)) =
            (staged.action(), staged.uuid())
        else {
            return Ok(true);
        };
        let current = self
            .client
            .get_ips_object(
                staged.family(),
                staged.profile_uuid(),
                uuid,
                &self.cancellation,
            )
            .await?;
        let digest = |value: &Value| {
            canonical_digest(value).map_err(|error| SdcError::PreparedChange(error.to_string()))
        };
        Ok(digest(&current)? == digest(staged.before())?)
    }

    /// Refuse a profile delete while any firewall rule still references it.
    ///
    /// Re-run at apply time because a rule can be attached to the profile
    /// between prepare and apply, and that is not a change to the profile
    /// object, so the drift check cannot see it.
    async fn ensure_unreferenced(&self, staged: &SdcPreparedIpsWrite) -> Result<(), SdcError> {
        let (IpsFamily::Profile, IpsWriteAction::Delete, Some(uuid)) =
            (staged.family(), staged.action(), staged.uuid())
        else {
            return Ok(());
        };
        let references = self
            .client
            .find_ips_profile_references(uuid, &self.cancellation)
            .await?;
        if references.is_empty() {
            return Ok(());
        }
        Err(profile_in_use(&references))
    }
}

/// Build the refusal for a profile that firewall rules still reference.
pub(crate) fn profile_in_use(rule_uuids: &[String]) -> SdcError {
    SdcError::IpsGuard(format!(
        "IPS profile is still referenced by firewall rules {}; detach it from those rules first",
        rule_uuids.join(", ")
    ))
}

#[async_trait]
impl DeviceTransaction for SdcIpsTransaction {
    type Action = SdcPreparedIpsWrite;
    type Staged = SdcPreparedIpsWrite;
    type Diff = Value;
    type Validation = IpsValidationReport;
    type Error = SdcError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        Ok(self.expected_plan_digest.clone())
    }

    /// Sole validation point for the envelope, mirroring `SdcObjectTransaction`.
    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let [prepared] = actions else {
            return Err(SdcError::InvalidInput(
                "an SDC IPS write requires exactly one prepared change",
            ));
        };
        prepared.validate()?;
        if prepared.operation() != "ips_write"
            || prepared.plan_digest() != self.expected_plan_digest
        {
            return Err(SdcError::PreparedChange(
                "prepared action does not match the approved plan digest".to_owned(),
            ));
        }
        Ok(prepared.clone())
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        // Validated in `stage`.
        Ok(staged.plan())
    }

    /// Refuse the write if the target moved since it was prepared.
    ///
    /// An IPS write has no SDC preview to bind, so this drift check is what
    /// makes the approved digest meaningful at apply time.
    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        let target_unchanged = self.target_unchanged(staged).await?;
        if !target_unchanged {
            return Err(SdcError::TargetDrifted);
        }
        self.ensure_unreferenced(staged).await?;
        Ok(IpsValidationReport {
            valid: true,
            family: staged.family(),
            action: staged.action(),
            target_unchanged,
        })
    }

    async fn commit(
        &self,
        staged: &Self::Staged,
        _attribution: &Attribution,
        options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        // Every exit path until the request is issued is a pre-write refusal:
        // nothing has been sent, so the caller may safely discard the operation
        // instead of leaving a non-terminal record that blocks the tenant.
        self.refused_before_write.store(true, Ordering::SeqCst);
        if options.confirm_timeout.is_some() {
            return Err(SdcError::InvalidInput(
                "SDC does not support confirmed IPS writes",
            ));
        }
        // Re-check drift immediately before writing: the coordinator releases
        // and reacquires its guard between validate and commit, and that guard
        // cannot exclude a writer working directly against SDC. SDC exposes no
        // conditional write, so this narrows the window rather than closing it.
        if !self.target_unchanged(staged).await? {
            return Err(SdcError::TargetDrifted);
        }
        self.ensure_unreferenced(staged).await?;
        self.refused_before_write.store(false, Ordering::SeqCst);
        let family = staged.family();
        let profile_uuid = staged.profile_uuid();
        let result = match (staged.action(), staged.uuid()) {
            (IpsWriteAction::Create, _) => {
                self.client
                    .create_ips_object(family, profile_uuid, staged.request(), &self.cancellation)
                    .await
            }
            (IpsWriteAction::Update, Some(uuid)) => {
                self.client
                    .update_ips_object(
                        family,
                        profile_uuid,
                        uuid,
                        staged.request(),
                        &self.cancellation,
                    )
                    .await
            }
            (IpsWriteAction::Delete, Some(uuid)) => {
                self.client
                    .delete_ips_object(family, profile_uuid, uuid, &self.cancellation)
                    .await
            }
            (IpsWriteAction::Update | IpsWriteAction::Delete, None) => {
                return Err(SdcError::PreparedChange(
                    "prepared IPS write is missing its target UUID".to_owned(),
                ));
            }
        };
        match result {
            Ok(_) => Ok(CommitOutcome::Reconciled {
                succeeded: true,
                job_id: None,
                details: Some(format!(
                    "SDC {} completed; this changed SDC's model only and deployed nothing",
                    staged.action().as_str()
                )),
            }),
            Err(SdcError::Cancelled | SdcError::Timeout | SdcError::MutationOutcomeUnknown) => {
                Ok(CommitOutcome::Indeterminate {
                    reason: "SDC IPS write was submitted but its outcome was not observed"
                        .to_owned(),
                })
            }
            Err(error) => {
                // A definitive validation rejection means nothing landed.
                if error.is_definitive_rejection() {
                    self.refused_before_write.store(true, Ordering::SeqCst);
                }
                Err(error)
            }
        }
    }

    /// Release a planned-but-uncommitted IPS write. SDC has no candidate store,
    /// so there is nothing remote to revert.
    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        match to {
            RollbackRef::CandidateRevert => Ok(RollbackOutcome {
                succeeded: true,
                details: Some(
                    "no remote candidate exists; SDC IPS writes are not staged".to_owned(),
                ),
            }),
            RollbackRef::Archive(_) | RollbackRef::Custom(_) => Err(SdcError::RollbackUnsupported),
        }
    }

    async fn unlock(&self) -> Result<UnlockOutcome, Self::Error> {
        Ok(UnlockOutcome::Released)
    }

    async fn confirm_commit(
        &self,
        _operation_id: &str,
        _attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error> {
        Err(SdcError::InvalidInput(
            "SDC does not support confirmed IPS writes",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::get};
    use url::Url;

    fn custom_signature(uuid: &str) -> Value {
        json!({"uuid": uuid, "name": "custom-sig", "signature_type": "signature"})
    }

    fn signature_update(before: Value) -> Result<SdcPreparedIpsWrite, SdcError> {
        SdcPreparedIpsWrite::new(
            IpsFamily::Signature,
            IpsWriteAction::Update,
            Some("sig-1".to_owned()),
            None,
            json!({"name": "custom-sig", "signature_type": "signature"}),
            before,
        )
    }

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

    fn client(base_url: &Url) -> SdcClient {
        let _ = rustls::crypto::ring::default_provider().install_default();
        SdcClient::from_test_parts(base_url.as_str(), "test-secret".to_owned(), 256 * 1024, 100)
    }

    #[test]
    fn the_digest_covers_family_action_uuid_profile_and_body() {
        let base = SdcPreparedIpsWrite::new(
            IpsFamily::Rule,
            IpsWriteAction::Update,
            Some("r1".to_owned()),
            Some("p1".to_owned()),
            json!({"name": "rule"}),
            json!({"uuid": "r1", "name": "old"}),
        )
        .expect("base");
        let digest = base.plan_digest().to_owned();
        let build = |family, action, uuid: &str, profile: &str, body: Value, before: Value| {
            SdcPreparedIpsWrite::new(
                family,
                action,
                Some(uuid.to_owned()),
                Some(profile.to_owned()),
                body,
                before,
            )
            .map(|prepared| prepared.plan_digest().to_owned())
        };
        let before = json!({"uuid": "r1", "name": "old"});
        let body = json!({"name": "rule"});
        assert_eq!(
            build(
                IpsFamily::Rule,
                IpsWriteAction::Update,
                "r1",
                "p1",
                body.clone(),
                before.clone()
            )
            .expect("same"),
            digest
        );
        // Family: exempt rules live under the same profile with the same shape.
        assert_ne!(
            build(
                IpsFamily::ExemptRule,
                IpsWriteAction::Update,
                "r1",
                "p1",
                body.clone(),
                before.clone()
            )
            .expect("family"),
            digest
        );
        assert_ne!(
            build(
                IpsFamily::Rule,
                IpsWriteAction::Update,
                "r2",
                "p1",
                body.clone(),
                before.clone()
            )
            .expect("uuid"),
            digest
        );
        assert_ne!(
            build(
                IpsFamily::Rule,
                IpsWriteAction::Update,
                "r1",
                "p2",
                body.clone(),
                before.clone()
            )
            .expect("profile"),
            digest
        );
        assert_ne!(
            build(
                IpsFamily::Rule,
                IpsWriteAction::Update,
                "r1",
                "p1",
                json!({"name": "other"}),
                before.clone()
            )
            .expect("body"),
            digest
        );
        // Action: a delete of the same target is a different plan.
        let delete = SdcPreparedIpsWrite::new(
            IpsFamily::Rule,
            IpsWriteAction::Delete,
            Some("r1".to_owned()),
            Some("p1".to_owned()),
            Value::Null,
            before,
        )
        .expect("delete");
        assert_ne!(delete.plan_digest(), digest);
    }

    #[test]
    fn the_digest_covers_the_exact_body_not_a_redacted_rendering() {
        let build = |body: Value| {
            SdcPreparedIpsWrite::new(
                IpsFamily::Signature,
                IpsWriteAction::Create,
                None,
                None,
                body,
                Value::Null,
            )
            .expect("prepared")
            .plan_digest()
            .to_owned()
        };
        let one = build(json!({"name": "s", "pattern_sets": [{"expression": "password=hunter2"}]}));
        let two = build(json!({"name": "s", "pattern_sets": [{"expression": "password=hunter3"}]}));
        assert_ne!(
            one, two,
            "two different expressions must never share a digest"
        );
    }

    #[test]
    fn action_and_shape_must_agree() {
        let body = json!({"name": "x"});
        let existing = json!({"uuid": "u1", "name": "x"});
        let make = |family,
                    action,
                    uuid: Option<&str>,
                    profile: Option<&str>,
                    request: Value,
                    before: Value| {
            SdcPreparedIpsWrite::new(
                family,
                action,
                uuid.map(str::to_owned),
                profile.map(str::to_owned),
                request,
                before,
            )
        };
        // Create must not carry a UUID, update/delete must.
        assert!(
            make(
                IpsFamily::Profile,
                IpsWriteAction::Create,
                Some("u1"),
                None,
                body.clone(),
                Value::Null
            )
            .is_err()
        );
        assert!(
            make(
                IpsFamily::Profile,
                IpsWriteAction::Update,
                None,
                None,
                body.clone(),
                existing.clone()
            )
            .is_err()
        );
        assert!(
            make(
                IpsFamily::Profile,
                IpsWriteAction::Delete,
                None,
                None,
                Value::Null,
                existing.clone()
            )
            .is_err()
        );
        // Delete carries no body; create/update carry one.
        assert!(
            make(
                IpsFamily::Profile,
                IpsWriteAction::Delete,
                Some("u1"),
                None,
                body.clone(),
                existing.clone()
            )
            .is_err()
        );
        assert!(
            make(
                IpsFamily::Profile,
                IpsWriteAction::Create,
                None,
                None,
                Value::Null,
                Value::Null
            )
            .is_err()
        );
        assert!(
            make(
                IpsFamily::Profile,
                IpsWriteAction::Update,
                Some("u1"),
                None,
                json!({}),
                existing.clone()
            )
            .is_err()
        );
        // Create has no prior state; update needs it.
        assert!(
            make(
                IpsFamily::Profile,
                IpsWriteAction::Create,
                None,
                None,
                body.clone(),
                existing.clone()
            )
            .is_err()
        );
        assert!(
            make(
                IpsFamily::Profile,
                IpsWriteAction::Update,
                Some("u1"),
                None,
                body.clone(),
                Value::Null
            )
            .is_err()
        );
        // profile_uuid: required for rule/exempt_rule, rejected for the rest.
        assert!(
            make(
                IpsFamily::Rule,
                IpsWriteAction::Create,
                None,
                None,
                body.clone(),
                Value::Null
            )
            .is_err()
        );
        assert!(
            make(
                IpsFamily::ExemptRule,
                IpsWriteAction::Create,
                None,
                None,
                body.clone(),
                Value::Null
            )
            .is_err()
        );
        assert!(
            make(
                IpsFamily::Signature,
                IpsWriteAction::Create,
                None,
                Some("p1"),
                body.clone(),
                Value::Null
            )
            .is_err()
        );
        assert!(
            make(
                IpsFamily::Profile,
                IpsWriteAction::Create,
                None,
                Some("p1"),
                body.clone(),
                Value::Null
            )
            .is_err()
        );
        // The well-formed counterparts are accepted.
        assert!(
            make(
                IpsFamily::Rule,
                IpsWriteAction::Create,
                None,
                Some("p1"),
                body.clone(),
                Value::Null
            )
            .is_ok()
        );
        assert!(
            make(
                IpsFamily::Profile,
                IpsWriteAction::Delete,
                Some("u1"),
                None,
                Value::Null,
                existing
            )
            .is_ok()
        );
    }

    #[test]
    fn identifiers_cannot_smuggle_path_segments() {
        for hostile in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "../x",
            "a?b=1",
            "a#b",
            "a%2Fb",
            "a b",
            "a\tb",
            "a\0b",
            "caf\u{e9}",
            &"x".repeat(257),
        ] {
            let as_uuid = SdcPreparedIpsWrite::new(
                IpsFamily::Profile,
                IpsWriteAction::Delete,
                Some(hostile.to_owned()),
                None,
                Value::Null,
                json!({"uuid": hostile}),
            );
            assert!(as_uuid.is_err(), "uuid {hostile:?} must be refused");
            let as_profile = SdcPreparedIpsWrite::new(
                IpsFamily::Rule,
                IpsWriteAction::Create,
                None,
                Some(hostile.to_owned()),
                json!({"name": "r"}),
                Value::Null,
            );
            assert!(
                as_profile.is_err(),
                "profile_uuid {hostile:?} must be refused"
            );
        }
        assert!(
            SdcPreparedIpsWrite::new(
                IpsFamily::Rule,
                IpsWriteAction::Create,
                None,
                Some("0a1b2c3d-4e5f:6+7=8_9".to_owned()),
                json!({"name": "r"}),
                Value::Null,
            )
            .is_ok()
        );
    }

    #[test]
    fn a_tampered_envelope_fails_validation() {
        let prepared = SdcPreparedIpsWrite::new(
            IpsFamily::Rule,
            IpsWriteAction::Create,
            None,
            Some("p1".to_owned()),
            json!({"name": "r"}),
            Value::Null,
        )
        .expect("prepared");
        for (pointer, replacement) in [
            ("/request/name", json!("swapped")),
            ("/profile_uuid", json!("p2")),
            ("/family", json!("exempt_rule")),
            ("/action", json!("update")),
            ("/plan_digest", json!("sha256:00")),
        ] {
            let mut raw = serde_json::to_value(&prepared).expect("serializes");
            if let Some(slot) = raw.pointer_mut(pointer) {
                *slot = replacement;
            }
            let tampered: SdcPreparedIpsWrite =
                serde_json::from_value(raw).expect("tampered envelope still deserializes");
            assert!(tampered.validate().is_err(), "{pointer} tamper must fail");
        }
    }

    #[test]
    fn only_a_positively_identified_custom_signature_is_mutable() {
        assert!(is_custom_signature(&custom_signature("s")));
        let mut with_blank = custom_signature("s");
        with_blank["import_id"] = json!("");
        assert!(is_custom_signature(&with_blank));
        // Predefined: imported from a bundle.
        let mut imported = custom_signature("s");
        imported["import_id"] = json!("HTTP:XSS:1234");
        assert!(!is_custom_signature(&imported));
        let mut activated = custom_signature("s");
        activated["activation_date"] = json!("2026-01-01T00:00:00Z");
        assert!(!is_custom_signature(&activated));
        // Fail closed: unknown, missing, or oddly typed discriminators.
        assert!(!is_custom_signature(&json!({"uuid": "s", "name": "n"})));
        assert!(!is_custom_signature(
            &json!({"signature_type": "predefined"})
        ));
        assert!(!is_custom_signature(
            &json!({"signature_type": "signature", "import_id": 7})
        ));
        assert!(!is_custom_signature(&Value::Null));
        assert!(!is_custom_signature(&json!("signature")));
    }

    #[test]
    fn update_and_delete_of_a_predefined_signature_are_refused() {
        let mut imported = custom_signature("sig-1");
        imported["import_id"] = json!("HTTP:XSS:1234");
        let error = signature_update(imported.clone()).expect_err("predefined update");
        assert!(matches!(error, SdcError::IpsGuard(_)), "{error:?}");
        let error = SdcPreparedIpsWrite::new(
            IpsFamily::Signature,
            IpsWriteAction::Delete,
            Some("sig-1".to_owned()),
            None,
            Value::Null,
            imported,
        )
        .expect_err("predefined delete");
        assert!(matches!(error, SdcError::IpsGuard(_)), "{error:?}");
        assert!(signature_update(custom_signature("sig-1")).is_ok());
        // Create cannot assert predefined provenance either.
        let error = SdcPreparedIpsWrite::new(
            IpsFamily::Signature,
            IpsWriteAction::Create,
            None,
            None,
            json!({"name": "n", "import_id": "HTTP:XSS:1"}),
            Value::Null,
        )
        .expect_err("import_id on create");
        assert!(matches!(error, SdcError::IpsGuard(_)), "{error:?}");
    }

    #[test]
    fn a_redaction_marker_in_the_body_is_refused() {
        let error = SdcPreparedIpsWrite::new(
            IpsFamily::Profile,
            IpsWriteAction::Create,
            None,
            None,
            json!({"name": "p", "description": crate::REDACTED}),
            Value::Null,
        );
        assert!(error.is_err());
    }

    #[test]
    fn expression_digests_identify_each_expression() {
        let request = json!({"pattern_sets": [
            {"expression": "a.*b"},
            {"service": "HTTP"},
            {"expression": "$6$ not a hash"},
        ]});
        let digests = expression_digests(&request, &Value::Null);
        assert_eq!(digests.len(), 2);
        assert_eq!(digests[0].location, "request.pattern_sets[0].expression");
        assert_eq!(digests[1].location, "request.pattern_sets[2].expression");
        assert_ne!(digests[0].digest, digests[1].digest);
        assert_eq!(
            digests[0].digest,
            canonical_digest(&Value::String("a.*b".to_owned())).expect("digest")
        );
    }

    #[tokio::test]
    async fn stage_rejects_a_tampered_envelope_and_a_digest_mismatch() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = SdcClient::from_test_parts(
            "https://example.invalid/",
            "test-secret".to_owned(),
            64 * 1024,
            100,
        );
        let prepared = signature_update(custom_signature("sig-1")).expect("prepared");
        let transaction = SdcIpsTransaction::new(
            client.clone(),
            prepared.plan_digest().to_owned(),
            CancellationToken::new(),
        );
        transaction
            .stage(std::slice::from_ref(&prepared))
            .await
            .expect("an intact envelope stages");

        let mut raw = serde_json::to_value(&prepared).expect("serializes");
        raw["request"]["name"] = json!("swapped after approval");
        let tampered: SdcPreparedIpsWrite = serde_json::from_value(raw).expect("deserializes");
        transaction
            .stage(std::slice::from_ref(&tampered))
            .await
            .expect_err("a mutated request must not reach commit");

        let other_digest = SdcIpsTransaction::new(client, "sha256:other", CancellationToken::new());
        other_digest
            .stage(std::slice::from_ref(&prepared))
            .await
            .expect_err("a digest the approver did not see must not stage");
    }

    #[tokio::test]
    async fn a_target_that_drifted_since_prepare_is_refused_and_discardable() {
        let app = Router::new().route(
            "/api/v1/ips_profiles/p1/ips_rules/r1",
            get(|| async { Json(json!({"uuid": "r1", "name": "changed-by-someone-else"})) }),
        );
        let (base_url, server) = serve(app).await;
        let prepared = SdcPreparedIpsWrite::new(
            IpsFamily::Rule,
            IpsWriteAction::Update,
            Some("r1".to_owned()),
            Some("p1".to_owned()),
            json!({"name": "new"}),
            json!({"uuid": "r1", "name": "as-prepared"}),
        )
        .expect("prepared");
        let transaction = SdcIpsTransaction::new(
            client(&base_url),
            prepared.plan_digest().to_owned(),
            CancellationToken::new(),
        );
        let staged = transaction
            .stage(std::slice::from_ref(&prepared))
            .await
            .expect("stages");
        let error = transaction
            .validate(&staged)
            .await
            .expect_err("a drifted target must refuse");
        assert!(matches!(error, SdcError::TargetDrifted), "{error:?}");
        let error = transaction
            .commit(&staged, &Attribution::stdio(), &CommitOptions::default())
            .await
            .expect_err("a drifted target must not be written");
        assert!(matches!(error, SdcError::TargetDrifted), "{error:?}");
        assert!(transaction.refused_before_write());
        server.abort();
    }

    #[tokio::test]
    async fn an_unchanged_target_validates_and_commits_to_the_exact_path() {
        let app = Router::new().route(
            "/api/v1/ips_profiles/p1/exempt_rules/e1",
            get(|| async { Json(json!({"uuid": "e1", "name": "as-prepared"})) }).put(
                |Json(body): Json<Value>| async move {
                    assert_eq!(body, json!({"name": "new"}));
                    Json(json!({"uuid": "e1"}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let prepared = SdcPreparedIpsWrite::new(
            IpsFamily::ExemptRule,
            IpsWriteAction::Update,
            Some("e1".to_owned()),
            Some("p1".to_owned()),
            json!({"name": "new"}),
            json!({"uuid": "e1", "name": "as-prepared"}),
        )
        .expect("prepared");
        let transaction = SdcIpsTransaction::new(
            client(&base_url),
            prepared.plan_digest().to_owned(),
            CancellationToken::new(),
        );
        let staged = transaction
            .stage(std::slice::from_ref(&prepared))
            .await
            .expect("stages");
        let report = transaction.validate(&staged).await.expect("validates");
        assert!(report.valid && report.target_unchanged);
        let outcome = transaction
            .commit(&staged, &Attribution::stdio(), &CommitOptions::default())
            .await
            .expect("commits");
        assert!(matches!(
            outcome,
            CommitOutcome::Reconciled {
                succeeded: true,
                ..
            }
        ));
        server.abort();
    }

    #[tokio::test]
    async fn a_referenced_profile_delete_is_refused_with_the_referencing_rules() {
        let app = Router::new()
            .route(
                "/api/v1/ips_profiles/p1",
                get(|| async { Json(json!({"uuid": "p1", "name": "prof"})) }),
            )
            .route(
                "/api/v1/policies/firewall",
                get(|| async { Json(json!({"items": [{"uuid": "pol1"}], "count": 1})) }),
            )
            .route(
                "/api/v1/policies/firewall/pol1/global/rules",
                get(|| async { Json(json!({"items": [], "count": 0})) }),
            )
            .route(
                "/api/v1/policies/firewall/pol1/zone/rules",
                get(|| async {
                    Json(json!({"items": [
                        {"uuid": "fw-a", "advanced_security": {"ips_profile": {"uuid": "p1"}}},
                        {"uuid": "fw-b", "advanced_security": {"ips_profile": {"uuid": "other"}}},
                        {"uuid": "fw-c"},
                    ], "count": 3}))
                }),
            );
        let (base_url, server) = serve(app).await;
        let prepared = SdcPreparedIpsWrite::new(
            IpsFamily::Profile,
            IpsWriteAction::Delete,
            Some("p1".to_owned()),
            None,
            Value::Null,
            json!({"uuid": "p1", "name": "prof"}),
        )
        .expect("prepared");
        let transaction = SdcIpsTransaction::new(
            client(&base_url),
            prepared.plan_digest().to_owned(),
            CancellationToken::new(),
        );
        let staged = transaction
            .stage(std::slice::from_ref(&prepared))
            .await
            .expect("stages");
        let error = transaction
            .validate(&staged)
            .await
            .expect_err("a referenced profile must not validate");
        let message = error.to_string();
        assert!(matches!(error, SdcError::IpsGuard(_)), "{message}");
        assert!(message.contains("fw-a"), "{message}");
        assert!(
            !message.contains("fw-b") && !message.contains("fw-c"),
            "{message}"
        );
        let error = transaction
            .commit(&staged, &Attribution::stdio(), &CommitOptions::default())
            .await
            .expect_err("a referenced profile must not be deleted");
        assert!(matches!(error, SdcError::IpsGuard(_)), "{error:?}");
        assert!(transaction.refused_before_write());
        server.abort();
    }
}
