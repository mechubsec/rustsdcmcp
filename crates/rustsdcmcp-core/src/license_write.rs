//! Change-controlled writes to SDC license and certificate management.
//!
//! License and certificate installs and deletions follow the async job pattern
//! already established for preview/deploy and device sync. The POST returns an
//! id, then a GET status poll resolves the outcome. Like firewall writes,
//! there is no SDC-side preview, so the plan artifact is built locally and
//! records the exact request together with observed state beforehand. Apply
//! refuses if that state has since moved.

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

/// Hard cap on one serialized license/certificate write envelope.
const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;

/// Which mutation one license/certificate write performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LicenseWriteOperation {
    /// Install a license on a device.
    InstallLicense,
    /// Install a CA certificate on a device.
    InstallCaCertificate,
    /// Install a local (identity) certificate on a device.
    InstallLocalCertificate,
    /// Delete a certificate from a device.
    DeleteCertificate,
}

impl LicenseWriteOperation {
    /// Stable discriminator recorded in audit and change-control state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstallLicense => "license_install",
            Self::InstallCaCertificate => "ca_certificate_install",
            Self::InstallLocalCertificate => "local_certificate_install",
            Self::DeleteCertificate => "certificate_delete",
        }
    }
}

/// Exact license/certificate write bound into a change-set action.
///
/// Product-owned while its vendor-neutral extraction is tracked in mecmcp#90.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdcPreparedLicenseWrite {
    operation: String,
    action: LicenseWriteOperation,
    device_uuid: String,
    request: Value,
    before: Value,
    plan_digest: String,
}

impl SdcPreparedLicenseWrite {
    /// Build a canonical, digest-bound license/certificate write.
    ///
    /// `before` is the device's observed license or certificate state for
    /// validation, and `Value::Null` when no prior state check is needed.
    ///
    /// # Errors
    ///
    /// Refuses shapes that do not match the action, and oversized envelopes.
    pub fn new(
        action: LicenseWriteOperation,
        device_uuid: String,
        request: Value,
        before: Value,
    ) -> Result<Self, SdcError> {
        let plan = plan_artifact(action, &device_uuid, &request, &before);
        let prepared = Self {
            operation: "license_write".to_owned(),
            action,
            device_uuid,
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

    /// Which mutation this write performs.
    #[must_use]
    pub const fn action(&self) -> LicenseWriteOperation {
        self.action
    }

    /// Target device UUID.
    #[must_use]
    pub fn device_uuid(&self) -> &str {
        &self.device_uuid
    }

    /// Exact request body.
    #[must_use]
    pub const fn request(&self) -> &Value {
        &self.request
    }

    /// Device state observed at prepare time, `Null` when not applicable.
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
        plan_artifact(self.action, &self.device_uuid, &self.request, &self.before)
    }

    /// This prepared write as the caller should see it: `before` projected.
    ///
    /// See `project_before` for why the projection lives here and not in
    /// `Serialize` — the persisted and digested envelope must stay raw.
    ///
    /// # Errors
    ///
    /// Returns an error if the captured state cannot be projected.
    pub fn caller_view(&self) -> Result<Value, SdcError> {
        let mut value = serde_json::to_value(self).map_err(|_| SdcError::Serialization)?;
        let projected = projected_or_withheld(self.action, &self.before);
        if let Some(object) = value.as_object_mut() {
            object.insert("before".to_owned(), projected);
        }
        Ok(value)
    }

    /// Revalidate shape, bounds, and digest integrity.
    ///
    /// # Errors
    ///
    /// Returns a stable error if persisted content was malformed or tampered.
    pub fn validate(&self) -> Result<(), SdcError> {
        if self.operation != "license_write" {
            return Err(SdcError::PreparedChange(
                "prepared operation must be license_write".to_owned(),
            ));
        }
        if self.device_uuid.is_empty()
            || self.device_uuid.len() > 256
            || self
                .device_uuid
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(SdcError::PreparedChange(
                "prepared device UUID must be 1-256 non-whitespace bytes".to_owned(),
            ));
        }
        // All operations require a populated object body
        let request_is_populated_object = self
            .request
            .as_object()
            .is_some_and(|fields| !fields.is_empty());
        if !request_is_populated_object {
            return Err(SdcError::PreparedChange(format!(
                "prepared {} requires a populated request body",
                self.action.as_str()
            )));
        }
        if crate::redact::contains_redaction_marker(&self.request) {
            return Err(SdcError::InvalidInput(
                "write body contains a redaction marker; re-read the field value out-of-band",
            ));
        }
        let plan = plan_artifact(self.action, &self.device_uuid, &self.request, &self.before);
        if canonical_digest(&plan).map_err(|error| SdcError::PreparedChange(error.to_string()))?
            != self.plan_digest
        {
            return Err(SdcError::PreparedChange(
                "prepared license write does not match its digest".to_owned(),
            ));
        }
        if serde_json::to_vec(self)
            .map_err(|_| SdcError::Serialization)?
            .len()
            > MAX_ENVELOPE_BYTES
        {
            return Err(SdcError::PreparedChange(
                "prepared license write exceeds the 2097152-byte limit".to_owned(),
            ));
        }
        Ok(())
    }
}

/// `project_before`, with failure expressed as withheld state rather than as a
/// failed call.
///
/// The projection runs on the way out, after the change set has been persisted
/// or the write committed. Propagating an error there would fail the tool
/// *after* the side effect: the caller would never learn the change-set id of a
/// record that now blocks their later plans, or would read a committed write as
/// failed. Neither is worth a projection error, and neither is safer than
/// returning the result with its before-state withheld.
///
/// Withholding is also the fail-closed direction: a state that cannot be
/// projected is exactly the state that must not be passed through raw.
fn projected_or_withheld(action: LicenseWriteOperation, before: &Value) -> Value {
    project_before(action, before).unwrap_or_else(|error| {
        json!({
            "withheld": "before-state could not be projected onto the read-path allowlist",
            "reason": error.to_string(),
        })
    })
}

/// Project a captured before-state onto the same allowlists the read tools use.
///
/// The write path captures before-state by calling the very endpoints the read
/// tools serve, so returning it verbatim would hand callers fields the read
/// tools drop — a field upstream adds reaches MCP callers through the write
/// tools and nowhere else (#55).
///
/// This is applied **only** on the way to a caller. The digested and persisted
/// `before` stays raw: projecting it would erase an unknown field from both
/// sides of the drift comparison, so a write whose target drifted in exactly
/// that field would apply as unchanged.
///
/// # Errors
///
/// Returns an error when the captured state is not the shape its endpoint
/// returns — projection fails closed rather than passing content through.
pub(crate) fn project_before(
    action: LicenseWriteOperation,
    before: &Value,
) -> Result<Value, SdcError> {
    use LicenseWriteOperation::{
        DeleteCertificate, InstallCaCertificate, InstallLicense, InstallLocalCertificate,
    };

    if before.is_null() {
        // No prior state was applicable; there is nothing to disclose.
        return Ok(Value::Null);
    }

    match action {
        InstallLicense => crate::projection::project_licenses(before.clone()),
        InstallCaCertificate => crate::projection::project_ca_certificates(before.clone()),
        InstallLocalCertificate => crate::projection::project_local_certificates(before.clone()),
        // A delete may target either kind, so prepare captures both halves under
        // fixed keys. Both are projected; a missing half is left as it was found
        // rather than invented.
        DeleteCertificate => {
            let object = before.as_object().ok_or_else(|| {
                SdcError::PreparedChange(
                    "certificate delete before-state must be an object".to_owned(),
                )
            })?;
            let ca = match object.get("ca_certificates") {
                Some(value) => crate::projection::project_ca_certificates(value.clone())?,
                None => Value::Null,
            };
            let local = match object.get("local_certificates") {
                Some(value) => crate::projection::project_local_certificates(value.clone())?,
                None => Value::Null,
            };
            Ok(json!({ "ca_certificates": ca, "local_certificates": local }))
        }
    }
}

fn plan_artifact(
    action: LicenseWriteOperation,
    device_uuid: &str,
    request: &Value,
    before: &Value,
) -> Value {
    json!({
        "action": action,
        "device_uuid": device_uuid,
        "before": before,
        "after": request,
    })
}

/// Outcome of revalidating a license/certificate write immediately before commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseValidationReport {
    /// Whether the envelope is intact and the target has not drifted.
    pub valid: bool,
    /// Which mutation was validated.
    pub action: LicenseWriteOperation,
    /// Whether the live state still matched its prepared `before` state.
    pub target_unchanged: bool,
}

/// SDC implementation of the shared transaction contract for license/certificate writes.
#[derive(Clone)]
pub struct SdcLicenseTransaction {
    client: SdcClient,
    expected_plan_digest: String,
    cancellation: CancellationToken,
    refused_before_write: Arc<AtomicBool>,
}

impl SdcLicenseTransaction {
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
    /// Fetches the current license or certificate state on the device and
    /// compares it to the state observed at prepare time. This prevents
    /// deleting a replaced certificate or installing into a mutated state.
    async fn target_unchanged(&self, staged: &SdcPreparedLicenseWrite) -> Result<bool, SdcError> {
        use LicenseWriteOperation::*;
        let current = match staged.action() {
            InstallLicense => {
                self.client
                    .list_licenses(
                        &staged.device_uuid,
                        crate::ListRequest::new(0, 100, 100)?,
                        &self.cancellation,
                    )
                    .await?
            }
            InstallCaCertificate => {
                self.client
                    .list_device_ca_certificates(
                        &staged.device_uuid,
                        crate::ListRequest::new(0, 100, 100)?,
                        &self.cancellation,
                    )
                    .await?
            }
            InstallLocalCertificate => {
                self.client
                    .list_device_local_certificates(
                        &staged.device_uuid,
                        crate::ListRequest::new(0, 100, 100)?,
                        &self.cancellation,
                    )
                    .await?
            }
            DeleteCertificate => {
                let ca_certs = self
                    .client
                    .list_device_ca_certificates(
                        &staged.device_uuid,
                        crate::ListRequest::new(0, 100, 100)?,
                        &self.cancellation,
                    )
                    .await?;
                let local_certs = self
                    .client
                    .list_device_local_certificates(
                        &staged.device_uuid,
                        crate::ListRequest::new(0, 100, 100)?,
                        &self.cancellation,
                    )
                    .await?;
                serde_json::json!({
                    "ca_certificates": ca_certs,
                    "local_certificates": local_certs,
                })
            }
        };
        let digest = |value: &Value| {
            canonical_digest(value).map_err(|error| SdcError::PreparedChange(error.to_string()))
        };
        Ok(digest(&current)? == digest(staged.before())?)
    }
}

#[async_trait]
impl DeviceTransaction for SdcLicenseTransaction {
    type Action = SdcPreparedLicenseWrite;
    type Staged = SdcPreparedLicenseWrite;
    type Diff = Value;
    type Validation = LicenseValidationReport;
    type Error = SdcError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        Ok(self.expected_plan_digest.clone())
    }

    /// Sole validation point for the envelope, mirroring other transaction types.
    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let [prepared] = actions else {
            return Err(SdcError::InvalidInput(
                "an SDC license write requires exactly one prepared change",
            ));
        };
        prepared.validate()?;
        if prepared.operation() != "license_write"
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

    /// Refuse the write if the target state moved since it was prepared.
    ///
    /// Like firewall writes, license/certificate writes have no SDC preview to
    /// bind, so this drift check is what makes the approved digest meaningful
    /// at apply time.
    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        let target_unchanged = self.target_unchanged(staged).await?;
        if !target_unchanged {
            return Err(SdcError::TargetDrifted);
        }
        Ok(LicenseValidationReport {
            valid: true,
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
        // Every exit path from here until the request is issued is a pre-write
        // refusal: nothing has been sent, so the caller may safely discard the
        // operation instead of leaving a non-terminal record that blocks the
        // tenant. This covers the fallible recheck read below -- a target
        // mutated by someone else, or a transient failure -- not just an
        // explicit drift refusal.
        self.refused_before_write.store(true, Ordering::SeqCst);
        if options.confirm_timeout.is_some() {
            return Err(SdcError::InvalidInput(
                "SDC does not support confirmed license/certificate writes",
            ));
        }
        // Re-check drift immediately before writing. `validate` already checked,
        // but the coordinator releases and reacquires its guard in between, and
        // that guard cannot exclude a writer working directly against SDC.
        // Without this, a stale install or delete could mutate state that was
        // never in the approved plan.
        //
        // A refusal here is recorded as the non-terminal `Failed` state, so the
        // flag lets `apply_license_write` discard it: nothing was sent, which
        // makes that discard truthful.
        //
        // This narrows the window rather than closing it. SDC exposes no
        // conditional write, so a change landing between this read and the
        // request below is still possible.
        if !self.target_unchanged(staged).await? {
            return Err(SdcError::TargetDrifted);
        }
        // The mutation is about to go out. Past this point its outcome is no
        // longer knowably clean, so the operation must not be auto-discarded.
        self.refused_before_write.store(false, Ordering::SeqCst);
        let (job_id, status) = match staged.action() {
            LicenseWriteOperation::InstallLicense => {
                self.client
                    .install_license(&staged.device_uuid, staged.request(), &self.cancellation)
                    .await
            }
            LicenseWriteOperation::InstallCaCertificate => {
                self.client
                    .install_ca_certificate(
                        &staged.device_uuid,
                        staged.request(),
                        &self.cancellation,
                    )
                    .await
            }
            LicenseWriteOperation::InstallLocalCertificate => {
                self.client
                    .install_local_certificate(
                        &staged.device_uuid,
                        staged.request(),
                        &self.cancellation,
                    )
                    .await
            }
            LicenseWriteOperation::DeleteCertificate => {
                self.client
                    .delete_certificate(&staged.device_uuid, staged.request(), &self.cancellation)
                    .await
            }
        }?;
        Ok(CommitOutcome::Reconciled {
            succeeded: status.succeeded(),
            job_id: Some(job_id),
            details: Some(format!(
                "SDC {} completed with status {:?}",
                staged.action().as_str(),
                status
            )),
        })
    }

    /// Release a planned-but-uncommitted license/certificate write.
    ///
    /// SDC has no candidate store, so there is nothing remote to revert. The
    /// coordinator only reaches `rollback` from `Staged`, `Validated`, or
    /// `Failed` — it refuses to discard from `Committing`, `Committed`, and
    /// `Indeterminate` — so every state that gets here is pre-commit and
    /// nothing was written. Reporting success is therefore accurate, and it is
    /// what lets a refused write reach the terminal `Discarded` state instead
    /// of stranding the principal on a non-terminal `Failed` record.
    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        match to {
            RollbackRef::CandidateRevert => Ok(RollbackOutcome {
                succeeded: true,
                details: Some(
                    "no remote candidate exists; SDC license/certificate writes are not staged"
                        .to_owned(),
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
            "SDC does not support confirmed license/certificate writes",
        ))
    }
}

/// Result of planning a license/certificate write.
#[derive(Debug, Clone, Serialize)]
pub struct LicensePrepareResult {
    /// Shared two-person change-set record.
    pub change_set: mecmcp_changeset::ChangeSetOutput,
    /// Exact license/certificate write bound by the plan digest.
    pub prepared_change: SdcPreparedLicenseWrite,
}

impl LicensePrepareResult {
    /// This result as the caller should see it: the prepared change's
    /// before-state projected onto the read-path allowlists (#55).
    ///
    /// # Errors
    ///
    /// Returns an error if the captured state cannot be projected.
    pub fn caller_view(&self) -> Result<Value, SdcError> {
        Ok(json!({
            "change_set": self.change_set,
            "prepared_change": self.prepared_change.caller_view()?,
        }))
    }
}

/// Result of applying one approved SDC license/certificate write.
#[derive(Debug, Clone, Serialize)]
pub struct LicenseApplyResult {
    /// Shared operation identifier.
    pub operation_id: String,
    /// Before/after plan used as the management-plane diff.
    pub plan: Value,
    /// Drift and envelope validation result.
    pub validation: LicenseValidationReport,
    /// Known, detached, or indeterminate commit disposition.
    pub outcome: CommitOutcome,
}

impl LicenseApplyResult {
    /// This result as the caller should see it: the plan's before-state
    /// projected onto the read-path allowlists (#55).
    ///
    /// `action` is the operation the plan describes, which selects the
    /// allowlist. It is read from the plan itself so the caller cannot pick a
    /// projection that discloses more than the write's own kind allows.
    ///
    /// # Errors
    ///
    /// Returns an error if the plan is malformed or cannot be projected.
    pub fn caller_view(&self) -> Result<Value, SdcError> {
        let action: Option<LicenseWriteOperation> = self
            .plan
            .get("action")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok());

        let mut value = serde_json::to_value(self).map_err(|_| SdcError::Serialization)?;
        let before = self.plan.get("before").cloned().unwrap_or(Value::Null);
        // The write has already committed by the time this runs. A plan that
        // does not name its action is unprojectable, so its before-state is
        // withheld — the outcome of the write is still reported.
        let projected = match action {
            Some(action) => projected_or_withheld(action, &before),
            None => json!({
                "withheld": "before-state could not be projected onto the read-path allowlist",
                "reason": "plan does not name a license write action",
            }),
        };
        if let Some(plan) = value.get_mut("plan").and_then(Value::as_object_mut) {
            plan.insert("before".to_owned(), projected);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SdcClient;
    use axum::{Json, Router, routing::get};
    use mecmcp_audit::Attribution;
    use serde_json::json;
    use tokio_util::sync::CancellationToken;
    use url::Url;

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

    fn license_fixture(before: Value) -> SdcPreparedLicenseWrite {
        SdcPreparedLicenseWrite::new(
            LicenseWriteOperation::InstallLicense,
            "device-123".to_owned(),
            json!({"license_key": "TEST-KEY-123"}),
            before,
        )
        .expect("prepared license write")
    }

    /// A certificate delete captures both certificate kinds, so both halves
    /// need projecting — a composite that projects one is a leak with extra
    /// steps (#55).
    #[test]
    fn a_certificate_delete_projects_both_halves_of_its_before_state() {
        let before = json!({
            "ca_certificates": {
                "items": [{"uuid": "ca-1", "name": "root", "upstream_addition": "leak"}],
                "count": 1
            },
            "local_certificates": {
                "items": [{"uuid": "local-1", "name": "id", "upstream_addition": "leak"}],
                "count": 1
            }
        });

        let projected = project_before(LicenseWriteOperation::DeleteCertificate, &before)
            .expect("project composite");

        let rendered = serde_json::to_string(&projected).expect("serialize");
        assert!(!rendered.contains("upstream_addition"), "{rendered}");
        assert!(
            rendered.contains("ca-1") && rendered.contains("local-1"),
            "{rendered}"
        );
    }

    /// The projection runs after the change set is persisted and after the
    /// write commits. A shape it cannot project must not turn a completed
    /// operation into a failed call — the caller would lose the change-set id
    /// of a record that now blocks their later plans, or read a committed write
    /// as failed. The state is withheld instead, which is also the fail-closed
    /// direction.
    #[test]
    fn an_unprojectable_before_state_is_withheld_not_fatal() {
        // `items` as an object is valid JSON and not a collection response.
        let prepared = license_fixture(json!({"items": {"lic-1": "unexpected"}, "count": 1}));

        let view = prepared
            .caller_view()
            .expect("an unprojectable before-state must not fail the call");

        assert_eq!(
            view["before"]["withheld"],
            "before-state could not be projected onto the read-path allowlist",
            "{view}"
        );
        assert!(
            !serde_json::to_string(&view)
                .expect("serialize")
                .contains("unexpected"),
            "withholding must not leak the state it could not project: {view}"
        );
        assert!(
            !view["plan_digest"].as_str().unwrap_or_default().is_empty(),
            "the rest of the result must still reach the caller: {view}"
        );
    }

    /// The apply result hands back the plan, which embeds the same captured
    /// state as prepare (#55).
    #[test]
    fn an_apply_result_projects_the_plan_before_state() {
        let prepared = license_fixture(json!({
            "items": [{"uuid": "lic-1", "name": "initial", "upstream_addition": "leak"}],
            "count": 1
        }));
        let result = LicenseApplyResult {
            operation_id: "op-1".to_owned(),
            plan: prepared.plan(),
            validation: LicenseValidationReport {
                valid: true,
                action: LicenseWriteOperation::InstallLicense,
                target_unchanged: true,
            },
            outcome: CommitOutcome::Reconciled {
                succeeded: true,
                job_id: None,
                details: None,
            },
        };

        let rendered =
            serde_json::to_string(&result.caller_view().expect("caller view")).expect("serialize");
        assert!(!rendered.contains("upstream_addition"), "{rendered}");
        assert!(rendered.contains("lic-1"), "{rendered}");
    }

    /// The projection must not reach the digest. If it did, a target that
    /// drifted in an unallowlisted field would compare equal and the write
    /// would apply against state nobody approved.
    #[test]
    fn drift_in_an_unallowlisted_field_still_changes_the_plan_digest() {
        let at_prepare = license_fixture(json!({
            "items": [{"uuid": "lic-1", "upstream_addition": "before"}],
            "count": 1
        }));
        let at_apply = license_fixture(json!({
            "items": [{"uuid": "lic-1", "upstream_addition": "after"}],
            "count": 1
        }));

        assert_ne!(
            at_prepare.plan_digest(),
            at_apply.plan_digest(),
            "a field outside the allowlist must still be part of what the digest binds"
        );
    }

    #[tokio::test]
    async fn license_write_refuses_a_target_that_drifted_since_prepare() {
        // A license write has no SDC preview to bind, so this drift check is
        // what makes the approved digest meaningful at apply time.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let app = Router::new().route(
            "/api/v1/devices/device-123/licenses",
            get(|| async {
                Json(json!({
                    "items": [{"uuid": "lic-new", "name": "changed-by-someone-else"}],
                    "count": 1
                }))
            }),
        );
        let (base_url, server) = serve(app).await;
        let client =
            SdcClient::from_test_parts(base_url.as_str(), "test-secret".to_owned(), 64 * 1024, 100);
        let prepared = license_fixture(json!({
            "items": [{"uuid": "lic-old", "name": "as-prepared"}],
            "count": 1
        }));
        let transaction = SdcLicenseTransaction::new(
            client,
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
        assert!(
            matches!(&error, SdcError::TargetDrifted),
            "unexpected error: {error:?}"
        );
        assert!(
            !transaction.refused_before_write(),
            "a validation refusal is not a commit-boundary refusal"
        );

        // The same drift must also stop the write itself, since the coordinator
        // drops and reacquires its guard between validate and commit.
        let error = transaction
            .commit(
                &staged,
                &Attribution::stdio(),
                &mecmcp_changeset::CommitOptions::default(),
            )
            .await
            .expect_err("a drifted target must not be written");
        assert!(
            matches!(&error, SdcError::TargetDrifted),
            "unexpected error: {error:?}"
        );
        assert!(
            transaction.refused_before_write(),
            "a commit-boundary refusal must be discardable"
        );
        server.abort();
    }

    #[tokio::test]
    async fn license_write_validates_when_the_target_is_unchanged() {
        // Guards against the drift check above passing vacuously.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let before_state = json!({
            "items": [{"uuid": "lic-1", "name": "existing"}],
            "count": 1
        });
        let app = Router::new().route(
            "/api/v1/devices/device-123/licenses",
            get(move || {
                let state = before_state.clone();
                async move { Json(state) }
            }),
        );
        let (base_url, server) = serve(app).await;
        let client =
            SdcClient::from_test_parts(base_url.as_str(), "test-secret".to_owned(), 64 * 1024, 100);
        let prepared = license_fixture(json!({
            "items": [{"uuid": "lic-1", "name": "existing"}],
            "count": 1
        }));
        let transaction = SdcLicenseTransaction::new(
            client,
            prepared.plan_digest().to_owned(),
            CancellationToken::new(),
        );
        let staged = transaction
            .stage(std::slice::from_ref(&prepared))
            .await
            .expect("stages");
        let report = transaction
            .validate(&staged)
            .await
            .expect("an unchanged target validates");
        assert!(report.valid && report.target_unchanged);
        server.abort();
    }

    /// Percy F2 (MEC-973): a model that echoes back a redacted read must not
    /// be able to write the literal marker over a real field.
    #[test]
    fn a_request_body_carrying_the_redaction_marker_is_refused() {
        let error = SdcPreparedLicenseWrite::new(
            LicenseWriteOperation::InstallLicense,
            "device-123".to_owned(),
            json!({"license_key": crate::REDACTED}),
            Value::Null,
        )
        .expect_err("a redaction marker in the request body must be refused");
        assert!(matches!(error, SdcError::InvalidInput(_)), "{error:?}");
    }
}
