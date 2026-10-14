//! Change-controlled writes to SDC NAT policies, rules, and rule groups.
//!
//! NAT writes have no SDC-side preview endpoint, so the plan artifact is
//! built locally: it records the exact request together with the object's
//! observed state beforehand. Apply refuses if that state has since moved,
//! which is the NAT-write analogue of binding a deploy to its preview.

use crate::{NatWriteOperation, SdcClient, SdcError, prepared::canonical_digest};
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

/// Hard cap on one serialized NAT-write envelope.
const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;

/// Exact NAT write bound into a change-set action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdcPreparedNatWrite {
    operation: String,
    action: NatWriteOperation,
    policy_id: Option<String>,
    rule_id: Option<String>,
    group_id: Option<String>,
    request: Value,
    before: Value,
    plan_digest: String,
}

impl SdcPreparedNatWrite {
    /// Build a canonical, digest-bound NAT write.
    ///
    /// `before` is the object's observed state for update and delete, and
    /// `Value::Null` for create.
    ///
    /// # Errors
    ///
    /// Refuses shapes that do not match the action, and oversized envelopes.
    pub fn new(
        action: NatWriteOperation,
        policy_id: Option<String>,
        rule_id: Option<String>,
        group_id: Option<String>,
        request: Value,
        before: Value,
    ) -> Result<Self, SdcError> {
        let plan = plan_artifact(
            action,
            policy_id.as_deref(),
            rule_id.as_deref(),
            group_id.as_deref(),
            &request,
            &before,
        );
        let prepared = Self {
            operation: "nat_write".to_owned(),
            action,
            policy_id,
            rule_id,
            group_id,
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
    pub const fn action(&self) -> NatWriteOperation {
        self.action
    }

    /// Target policy ID.
    #[must_use]
    pub fn policy_id(&self) -> Option<&str> {
        self.policy_id.as_deref()
    }

    /// Target rule ID, for rule operations.
    #[must_use]
    pub fn rule_id(&self) -> Option<&str> {
        self.rule_id.as_deref()
    }

    /// Target rule group ID, for group operations.
    #[must_use]
    pub fn group_id(&self) -> Option<&str> {
        self.group_id.as_deref()
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
            self.action,
            self.policy_id.as_deref(),
            self.rule_id.as_deref(),
            self.group_id.as_deref(),
            &self.request,
            &self.before,
        )
    }

    /// Revalidate shape, bounds, and digest integrity.
    ///
    /// # Errors
    ///
    /// Refuses mismatched digests and oversized envelopes.
    pub fn validate(&self) -> Result<(), SdcError> {
        let plan = plan_artifact(
            self.action,
            self.policy_id.as_deref(),
            self.rule_id.as_deref(),
            self.group_id.as_deref(),
            &self.request,
            &self.before,
        );
        if canonical_digest(&plan).map_err(|error| SdcError::PreparedChange(error.to_string()))?
            != self.plan_digest
        {
            return Err(SdcError::PreparedChange(
                "prepared NAT write does not match its digest".to_owned(),
            ));
        }
        if crate::redact::contains_redaction_marker(&self.request) {
            return Err(SdcError::InvalidInput(
                "write body contains a redaction marker; re-read the field value out-of-band",
            ));
        }
        if serde_json::to_vec(self)
            .map_err(|_| SdcError::Serialization)?
            .len()
            > MAX_ENVELOPE_BYTES
        {
            return Err(SdcError::PreparedChange(
                "prepared NAT write exceeds the 2097152-byte limit".to_owned(),
            ));
        }
        Ok(())
    }
}

fn plan_artifact(
    action: NatWriteOperation,
    policy_id: Option<&str>,
    rule_id: Option<&str>,
    group_id: Option<&str>,
    request: &Value,
    before: &Value,
) -> Value {
    json!({
        "action": action,
        "policy_id": policy_id,
        "rule_id": rule_id,
        "group_id": group_id,
        "before": before,
        "after": request,
    })
}

/// Outcome of revalidating a NAT write immediately before commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatValidationReport {
    /// Whether the envelope is intact and the target has not drifted.
    pub valid: bool,
    /// Which mutation was validated.
    pub action: NatWriteOperation,
    /// Whether the live object still matched its prepared `before` state.
    pub target_unchanged: bool,
}

/// SDC implementation of the shared transaction contract for NAT writes.
#[derive(Clone)]
pub struct SdcNatTransaction {
    client: SdcClient,
    expected_plan_digest: String,
    cancellation: CancellationToken,
    refused_before_write: Arc<AtomicBool>,
}

impl SdcNatTransaction {
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
    async fn target_unchanged(&self, staged: &SdcPreparedNatWrite) -> Result<bool, SdcError> {
        use NatWriteOperation::*;

        let before_digest = |value: &Value| {
            canonical_digest(value).map_err(|error| SdcError::PreparedChange(error.to_string()))
        };

        match staged.action() {
            CreatePolicy | CreateRule | CreateRuleGroup => Ok(true),
            UpdatePolicy | DeletePolicy => {
                let Some(policy_id) = staged.policy_id() else {
                    return Err(SdcError::InvalidInput(
                        "policy_id required for policy operations",
                    ));
                };
                let current = self
                    .client
                    .get_nat_policy(policy_id, &self.cancellation)
                    .await?;
                Ok(before_digest(&current)? == before_digest(staged.before())?)
            }
            UpdateRule | DeleteRule => {
                let Some(policy_id) = staged.policy_id() else {
                    return Err(SdcError::InvalidInput(
                        "policy_id required for rule operations",
                    ));
                };
                let Some(rule_id) = staged.rule_id() else {
                    return Err(SdcError::InvalidInput(
                        "rule_id required for rule operations",
                    ));
                };
                let current = self
                    .client
                    .get_nat_rule(policy_id, rule_id, &self.cancellation)
                    .await?;
                Ok(before_digest(&current)? == before_digest(staged.before())?)
            }
            UpdateRuleGroup => {
                let Some(policy_id) = staged.policy_id() else {
                    return Err(SdcError::InvalidInput(
                        "policy_id required for rule group operations",
                    ));
                };
                let Some(group_id) = staged.group_id() else {
                    return Err(SdcError::InvalidInput(
                        "group_id required for rule group operations",
                    ));
                };
                let current = self
                    .client
                    .get_nat_rule_group(policy_id, group_id, &self.cancellation)
                    .await?;
                Ok(before_digest(&current)? == before_digest(staged.before())?)
            }
        }
    }
}

#[async_trait]
impl DeviceTransaction for SdcNatTransaction {
    type Action = SdcPreparedNatWrite;
    type Staged = SdcPreparedNatWrite;
    type Diff = Value;
    type Validation = NatValidationReport;
    type Error = SdcError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        Ok(self.expected_plan_digest.clone())
    }

    /// Sole validation point for the envelope, mirroring `SdcTransaction`.
    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let [prepared] = actions else {
            return Err(SdcError::InvalidInput(
                "an SDC NAT write requires exactly one prepared change",
            ));
        };
        prepared.validate()?;
        if prepared.operation() != "nat_write"
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

    /// Refuse the write if the target object moved since it was prepared.
    ///
    /// A NAT write has no SDC preview to bind, so this drift check is what
    /// makes the approved digest meaningful at apply time.
    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        let target_unchanged = self.target_unchanged(staged).await?;
        if !target_unchanged {
            return Err(SdcError::TargetDrifted);
        }
        Ok(NatValidationReport {
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
        use NatWriteOperation::*;

        // Every exit path until the request is issued is a pre-write refusal
        self.refused_before_write.store(true, Ordering::SeqCst);

        if options.confirm_timeout.is_some() {
            return Err(SdcError::InvalidInput(
                "SDC does not support confirmed NAT writes",
            ));
        }

        // Re-check drift immediately before writing
        if !self.target_unchanged(staged).await? {
            return Err(SdcError::TargetDrifted);
        }

        // The mutation is about to go out
        self.refused_before_write.store(false, Ordering::SeqCst);

        let result = match staged.action() {
            CreatePolicy => {
                self.client
                    .create_nat_policy(staged.request(), &self.cancellation)
                    .await
            }
            UpdatePolicy => {
                let Some(policy_id) = staged.policy_id() else {
                    return Err(SdcError::PreparedChange(
                        "prepared NAT write is missing its policy_id".to_owned(),
                    ));
                };
                self.client
                    .update_nat_policy(policy_id, staged.request(), &self.cancellation)
                    .await
            }
            DeletePolicy => {
                let Some(policy_id) = staged.policy_id() else {
                    return Err(SdcError::PreparedChange(
                        "prepared NAT write is missing its policy_id".to_owned(),
                    ));
                };
                self.client
                    .delete_nat_policy(policy_id, &self.cancellation)
                    .await
            }
            CreateRule => {
                let Some(policy_id) = staged.policy_id() else {
                    return Err(SdcError::PreparedChange(
                        "prepared NAT write is missing its policy_id".to_owned(),
                    ));
                };
                self.client
                    .create_nat_rule(policy_id, staged.request(), &self.cancellation)
                    .await
            }
            UpdateRule => {
                let Some(policy_id) = staged.policy_id() else {
                    return Err(SdcError::PreparedChange(
                        "prepared NAT write is missing its policy_id".to_owned(),
                    ));
                };
                let Some(rule_id) = staged.rule_id() else {
                    return Err(SdcError::PreparedChange(
                        "prepared NAT write is missing its rule_id".to_owned(),
                    ));
                };
                self.client
                    .update_nat_rule(policy_id, rule_id, staged.request(), &self.cancellation)
                    .await
            }
            DeleteRule => {
                let Some(policy_id) = staged.policy_id() else {
                    return Err(SdcError::PreparedChange(
                        "prepared NAT write is missing its policy_id".to_owned(),
                    ));
                };
                let Some(rule_id) = staged.rule_id() else {
                    return Err(SdcError::PreparedChange(
                        "prepared NAT write is missing its rule_id".to_owned(),
                    ));
                };
                self.client
                    .delete_nat_rule(policy_id, rule_id, &self.cancellation)
                    .await
            }
            CreateRuleGroup => {
                let Some(policy_id) = staged.policy_id() else {
                    return Err(SdcError::PreparedChange(
                        "prepared NAT write is missing its policy_id".to_owned(),
                    ));
                };
                self.client
                    .create_nat_rule_group(policy_id, staged.request(), &self.cancellation)
                    .await
            }
            UpdateRuleGroup => {
                let Some(policy_id) = staged.policy_id() else {
                    return Err(SdcError::PreparedChange(
                        "prepared NAT write is missing its policy_id".to_owned(),
                    ));
                };
                let Some(group_id) = staged.group_id() else {
                    return Err(SdcError::PreparedChange(
                        "prepared NAT write is missing its group_id".to_owned(),
                    ));
                };
                self.client
                    .update_nat_rule_group(
                        policy_id,
                        group_id,
                        staged.request(),
                        &self.cancellation,
                    )
                    .await
            }
        };

        match result {
            Ok(_) => Ok(CommitOutcome::Reconciled {
                succeeded: true,
                job_id: None,
                details: Some(format!(
                    "SDC {} completed",
                    match staged.action() {
                        CreatePolicy => "create_nat_policy",
                        UpdatePolicy => "update_nat_policy",
                        DeletePolicy => "delete_nat_policy",
                        CreateRule => "create_nat_rule",
                        UpdateRule => "update_nat_rule",
                        DeleteRule => "delete_nat_rule",
                        CreateRuleGroup => "create_nat_rule_group",
                        UpdateRuleGroup => "update_nat_rule_group",
                    }
                )),
            }),
            Err(SdcError::Cancelled | SdcError::Timeout | SdcError::MutationOutcomeUnknown) => {
                Ok(CommitOutcome::Indeterminate {
                    reason: "SDC NAT write was submitted but its outcome was not observed"
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

    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        match to {
            RollbackRef::CandidateRevert => Ok(RollbackOutcome {
                succeeded: true,
                details: Some(
                    "no remote candidate exists; SDC NAT writes are not staged".to_owned(),
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
            "SDC does not support confirmed NAT writes",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NatWriteOperation;

    /// Percy F2 (MEC-973): a model that echoes back a redacted read must not
    /// be able to write the literal marker over a real field.
    #[test]
    fn a_request_body_carrying_the_redaction_marker_is_refused() {
        let error = SdcPreparedNatWrite::new(
            NatWriteOperation::CreatePolicy,
            None,
            None,
            None,
            json!({"name": crate::REDACTED}),
            Value::Null,
        )
        .expect_err("a redaction marker in the request body must be refused");
        assert!(matches!(error, SdcError::InvalidInput(_)), "{error:?}");
    }
}
