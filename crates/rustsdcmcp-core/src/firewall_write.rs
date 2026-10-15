//! Change-controlled writes to SDC firewall policies.
//!
//! Firewall policy writes have no SDC-side preview endpoint for the policy
//! lifecycle itself (create/update/delete), so the plan artifact is built
//! locally: it records the exact request together with the policy's observed
//! state beforehand. Apply refuses if that state has since moved, which is
//! the firewall-write analogue of binding a deploy to its preview.

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

/// Hard cap on one serialized firewall-write envelope.
const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;

/// Which mutation one firewall policy write performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FirewallWriteOperation {
    /// Create a new firewall policy.
    CreatePolicy,
    /// Replace an existing firewall policy by UUID.
    UpdatePolicy,
    /// Delete an existing firewall policy by UUID.
    DeletePolicy,
}

impl FirewallWriteOperation {
    /// Stable discriminator recorded in audit and change-control state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreatePolicy => "firewall_policy_create",
            Self::UpdatePolicy => "firewall_policy_update",
            Self::DeletePolicy => "firewall_policy_delete",
        }
    }
}

/// Exact firewall policy write bound into a change-set action.
///
/// Product-owned while its vendor-neutral extraction is tracked in mecmcp#90.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdcPreparedFirewallWrite {
    operation: String,
    action: FirewallWriteOperation,
    uuid: Option<String>,
    request: Value,
    before: Value,
    plan_digest: String,
}

impl SdcPreparedFirewallWrite {
    /// Build a canonical, digest-bound firewall policy write.
    ///
    /// `before` is the policy's observed state for update and delete, and
    /// `Value::Null` for create.
    ///
    /// # Errors
    ///
    /// Refuses shapes that do not match the action, and oversized envelopes.
    pub fn new(
        action: FirewallWriteOperation,
        uuid: Option<String>,
        request: Value,
        before: Value,
    ) -> Result<Self, SdcError> {
        let plan = plan_artifact(action, uuid.as_deref(), &request, &before);
        let prepared = Self {
            operation: "firewall_write".to_owned(),
            action,
            uuid,
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
    pub const fn action(&self) -> FirewallWriteOperation {
        self.action
    }

    /// Target policy UUID, absent for create.
    #[must_use]
    pub fn uuid(&self) -> Option<&str> {
        self.uuid.as_deref()
    }

    /// Exact request body, `Null` for delete.
    #[must_use]
    pub const fn request(&self) -> &Value {
        &self.request
    }

    /// Policy state observed at prepare time, `Null` for create.
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
            self.action,
            self.uuid.as_deref(),
            &self.request,
            &self.before,
        )
    }

    /// Revalidate shape, bounds, and digest integrity.
    ///
    /// # Errors
    ///
    /// Returns a stable error if persisted content was malformed or tampered.
    pub fn validate(&self) -> Result<(), SdcError> {
        if self.operation != "firewall_write" {
            return Err(SdcError::PreparedChange(
                "prepared operation must be firewall_write".to_owned(),
            ));
        }
        let has_uuid = self.uuid.is_some();
        // Match the client's own body rule here so an unexecutable plan cannot
        // be approved: create and update reject an empty object, and
        // discovering that only at commit would burn a change set.
        let request_is_populated_object = self
            .request
            .as_object()
            .is_some_and(|fields| !fields.is_empty());
        let before_is_object = self.before.is_object();
        let shape_ok = match self.action {
            FirewallWriteOperation::CreatePolicy => {
                !has_uuid && request_is_populated_object && self.before.is_null()
            }
            FirewallWriteOperation::UpdatePolicy => {
                has_uuid && request_is_populated_object && before_is_object
            }
            FirewallWriteOperation::DeletePolicy => {
                has_uuid && self.request.is_null() && before_is_object
            }
        };
        if !shape_ok {
            return Err(SdcError::PreparedChange(format!(
                "prepared {} does not match its required shape",
                self.action.as_str()
            )));
        }
        // SDC requires `order` on policy create and counts from 1; discovering
        // that as a 400 at apply would burn the change set.
        if self.action == FirewallWriteOperation::CreatePolicy
            && !self
                .request
                .get("order")
                .and_then(Value::as_i64)
                .is_some_and(|order| order >= 1)
        {
            return Err(SdcError::InvalidInput(
                "firewall policy create requires an integer `order` of 1 or more",
            ));
        }
        if crate::redact::contains_redaction_marker(&self.request) {
            return Err(SdcError::InvalidInput(
                "write body contains a redaction marker; re-read the field value out-of-band",
            ));
        }
        if let Some(uuid) = self.uuid.as_deref()
            && (uuid.is_empty()
                || uuid.len() > 256
                || uuid
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()))
        {
            return Err(SdcError::PreparedChange(
                "prepared policy UUID must be 1-256 non-whitespace bytes".to_owned(),
            ));
        }
        let plan = plan_artifact(
            self.action,
            self.uuid.as_deref(),
            &self.request,
            &self.before,
        );
        if canonical_digest(&plan).map_err(|error| SdcError::PreparedChange(error.to_string()))?
            != self.plan_digest
        {
            return Err(SdcError::PreparedChange(
                "prepared firewall write does not match its digest".to_owned(),
            ));
        }
        if serde_json::to_vec(self)
            .map_err(|_| SdcError::Serialization)?
            .len()
            > MAX_ENVELOPE_BYTES
        {
            return Err(SdcError::PreparedChange(
                "prepared firewall write exceeds the 2097152-byte limit".to_owned(),
            ));
        }
        Ok(())
    }
}

fn plan_artifact(
    action: FirewallWriteOperation,
    uuid: Option<&str>,
    request: &Value,
    before: &Value,
) -> Value {
    json!({
        "action": action,
        "uuid": uuid,
        "before": before,
        "after": request,
    })
}

/// Outcome of revalidating a firewall policy write immediately before commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallValidationReport {
    /// Whether the envelope is intact and the target has not drifted.
    pub valid: bool,
    /// Which mutation was validated.
    pub action: FirewallWriteOperation,
    /// Whether the live policy still matched its prepared `before` state.
    pub target_unchanged: bool,
}

/// SDC implementation of the shared transaction contract for firewall policy writes.
#[derive(Clone)]
pub struct SdcFirewallTransaction {
    client: SdcClient,
    expected_plan_digest: String,
    cancellation: CancellationToken,
    refused_before_write: Arc<AtomicBool>,
}

impl SdcFirewallTransaction {
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
    /// Create has no prior policy, so it is vacuously unchanged.
    async fn target_unchanged(&self, staged: &SdcPreparedFirewallWrite) -> Result<bool, SdcError> {
        let (
            FirewallWriteOperation::UpdatePolicy | FirewallWriteOperation::DeletePolicy,
            Some(uuid),
        ) = (staged.action(), staged.uuid())
        else {
            return Ok(true);
        };
        let current = self
            .client
            .get_firewall_policy(uuid, &self.cancellation)
            .await?;
        let digest = |value: &Value| {
            canonical_digest(value).map_err(|error| SdcError::PreparedChange(error.to_string()))
        };
        Ok(digest(&current)? == digest(staged.before())?)
    }
}

#[async_trait]
impl DeviceTransaction for SdcFirewallTransaction {
    type Action = SdcPreparedFirewallWrite;
    type Staged = SdcPreparedFirewallWrite;
    type Diff = Value;
    type Validation = FirewallValidationReport;
    type Error = SdcError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        Ok(self.expected_plan_digest.clone())
    }

    /// Sole validation point for the envelope, mirroring `SdcObjectTransaction`.
    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let [prepared] = actions else {
            return Err(SdcError::InvalidInput(
                "an SDC firewall write requires exactly one prepared change",
            ));
        };
        prepared.validate()?;
        if prepared.operation() != "firewall_write"
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

    /// Refuse the write if the target policy moved since it was prepared.
    ///
    /// A firewall policy write has no SDC preview to bind, so this drift check
    /// is what makes the approved digest meaningful at apply time.
    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        let target_unchanged = self.target_unchanged(staged).await?;
        if !target_unchanged {
            return Err(SdcError::TargetDrifted);
        }
        Ok(FirewallValidationReport {
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
        // deleted by someone else, or a transient failure -- not just an
        // explicit drift refusal.
        self.refused_before_write.store(true, Ordering::SeqCst);
        if options.confirm_timeout.is_some() {
            return Err(SdcError::InvalidInput(
                "SDC does not support confirmed firewall writes",
            ));
        }
        // Re-check drift immediately before writing. `validate` already checked,
        // but the coordinator releases and reacquires its guard in between, and
        // that guard cannot exclude a writer working directly against SDC.
        // Without this, a stale PUT or DELETE could overwrite state that was
        // never in the approved plan.
        //
        // A refusal here is recorded as the non-terminal `Failed` state, so the
        // flag lets `apply_firewall_write` discard it: nothing was sent, which
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
        let result = match (staged.action(), staged.uuid()) {
            (FirewallWriteOperation::CreatePolicy, _) => {
                self.client
                    .create_firewall_policy(staged.request(), &self.cancellation)
                    .await
            }
            (FirewallWriteOperation::UpdatePolicy, Some(uuid)) => {
                self.client
                    .update_firewall_policy(uuid, staged.request(), &self.cancellation)
                    .await
            }
            (FirewallWriteOperation::DeletePolicy, Some(uuid)) => {
                self.client
                    .delete_firewall_policy(uuid, &self.cancellation)
                    .await
            }
            (FirewallWriteOperation::UpdatePolicy | FirewallWriteOperation::DeletePolicy, None) => {
                return Err(SdcError::PreparedChange(
                    "prepared firewall write is missing its target UUID".to_owned(),
                ));
            }
        };
        match result {
            Ok(_) => Ok(CommitOutcome::Reconciled {
                succeeded: true,
                job_id: None,
                details: Some(format!("SDC {} completed", staged.action().as_str())),
            }),
            // The mutation may have landed. `MutationOutcomeUnknown` is raised
            // by `send_write` only when SDC answered with a success status
            // whose body could not be read, so a known API failure -- including
            // the pinned 429 handling -- is never demoted to indeterminate.
            Err(SdcError::Cancelled | SdcError::Timeout | SdcError::MutationOutcomeUnknown) => {
                Ok(CommitOutcome::Indeterminate {
                    reason: "SDC firewall write was submitted but its outcome was not observed"
                        .to_owned(),
                })
            }
            Err(error) => {
                // A definitive validation rejection means nothing landed, so the
                // operation is safe to discard instead of wedging later applies.
                if error.is_definitive_rejection() {
                    self.refused_before_write.store(true, Ordering::SeqCst);
                }
                Err(error)
            }
        }
    }

    /// Release a planned-but-uncommitted firewall policy write.
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
                    "no remote candidate exists; SDC firewall writes are not staged".to_owned(),
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
            "SDC does not support confirmed firewall writes",
        ))
    }
}

/// Result of planning a firewall policy write.
#[derive(Debug, Clone, Serialize)]
pub struct FirewallPrepareResult {
    /// Shared two-person change-set record.
    pub change_set: mecmcp_changeset::ChangeSetOutput,
    /// Exact policy write bound by the plan digest.
    pub prepared_change: SdcPreparedFirewallWrite,
}

/// Result of applying one approved SDC firewall policy write.
#[derive(Debug, Clone, Serialize)]
pub struct FirewallApplyResult {
    /// Shared operation identifier.
    pub operation_id: String,
    /// Before/after plan used as the management-plane diff.
    pub plan: Value,
    /// Drift and envelope validation result.
    pub validation: FirewallValidationReport,
    /// Known, detached, or indeterminate commit disposition.
    pub outcome: CommitOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Percy F2 (MEC-973): a model that echoes back a redacted read must not
    /// be able to write the literal marker over a real field.
    #[test]
    fn a_request_body_carrying_the_redaction_marker_is_refused() {
        let error = SdcPreparedFirewallWrite::new(
            FirewallWriteOperation::CreatePolicy,
            None,
            json!({"name": crate::REDACTED, "order": 1}),
            Value::Null,
        )
        .expect_err("a redaction marker in the request body must be refused");
        assert!(matches!(error, SdcError::InvalidInput(_)), "{error:?}");
    }

    #[test]
    fn policy_create_requires_a_positive_order() {
        let build = |request: Value| {
            SdcPreparedFirewallWrite::new(
                FirewallWriteOperation::CreatePolicy,
                None,
                request,
                Value::Null,
            )
        };
        for bad in [
            json!({"name": "p"}),
            json!({"name": "p", "order": 0}),
            json!({"name": "p", "order": -3}),
            json!({"name": "p", "order": "1"}),
            json!({"name": "p", "order": 1.5}),
        ] {
            let error = build(bad.clone()).expect_err("an invalid order must be refused");
            assert!(
                matches!(error, SdcError::InvalidInput(_)),
                "{bad}: {error:?}"
            );
        }
        build(json!({"name": "p", "order": 1})).expect("a positive order is accepted");
    }

    #[test]
    fn only_validation_rejections_are_definitive() {
        let api = |status| SdcError::Api {
            status,
            code: "c".to_owned(),
            message: "m".to_owned(),
        };
        assert!(api(400).is_definitive_rejection());
        assert!(api(422).is_definitive_rejection());
        for status in [401, 403, 429, 500, 502, 503] {
            assert!(!api(status).is_definitive_rejection(), "{status}");
        }
        assert!(!SdcError::Timeout.is_definitive_rejection());
        assert!(!SdcError::MutationOutcomeUnknown.is_definitive_rejection());
    }
}
