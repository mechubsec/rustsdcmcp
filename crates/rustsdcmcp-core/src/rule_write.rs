//! Change-controlled writes to SDC firewall policy rules.
//!
//! Rule writes have no SDC-side preview endpoint, so the plan artifact is
//! built locally: it records the exact request, the rule's location (policy,
//! scope, optional rule group, rule) and the rule's observed state beforehand.
//! Apply refuses if that state has since moved.

use crate::{SdcClient, SdcError, prepared::canonical_digest};
use async_trait::async_trait;
use mecmcp_audit::Attribution;
use mecmcp_changeset::{
    ChangeSetOutput, CommitOptions, CommitOutcome, DeviceTransaction, RollbackOutcome, RollbackRef,
    UnlockOutcome,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio_util::sync::CancellationToken;

/// Hard cap on one serialized rule-write envelope.
const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;

/// Which mutation one firewall rule write performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FirewallRuleWriteOperation {
    /// Create a rule.
    Create,
    /// Replace an existing rule.
    Update,
    /// Delete an existing rule.
    Delete,
}

impl FirewallRuleWriteOperation {
    /// Stable discriminator recorded in audit and change-control state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "firewall_rule_create",
            Self::Update => "firewall_rule_update",
            Self::Delete => "firewall_rule_delete",
        }
    }
}

/// Policy scope a rule lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FirewallRuleScope {
    /// Zone-based rules.
    Zone,
    /// Global rules.
    Global,
}

impl FirewallRuleScope {
    /// Path segment used by the SDC API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Zone => "zone",
            Self::Global => "global",
        }
    }
}

/// Exact firewall rule write bound into a change-set action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdcPreparedFirewallRuleWrite {
    operation: String,
    action: FirewallRuleWriteOperation,
    policy_uuid: String,
    scope: FirewallRuleScope,
    group_uuid: Option<String>,
    rule_uuid: Option<String>,
    request: Value,
    before: Value,
    plan_digest: String,
}

/// Where a rule write lands: the policy, scope, optional group and rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRuleLocation {
    /// Firewall policy UUID.
    pub policy_uuid: String,
    /// Policy scope.
    pub scope: FirewallRuleScope,
    /// Rule group UUID, when the rule lives in (or is created in) a group.
    pub group_uuid: Option<String>,
    /// Rule UUID. Absent for create, required for update and delete.
    pub rule_uuid: Option<String>,
}

impl SdcPreparedFirewallRuleWrite {
    /// Build a canonical, digest-bound rule write.
    ///
    /// `before` is the rule's observed state for update and delete, and
    /// `Value::Null` for create.
    ///
    /// # Errors
    ///
    /// Refuses shapes that do not match the action, and oversized envelopes.
    pub fn new(
        action: FirewallRuleWriteOperation,
        location: FirewallRuleLocation,
        request: Value,
        before: Value,
    ) -> Result<Self, SdcError> {
        let FirewallRuleLocation {
            policy_uuid,
            scope,
            group_uuid,
            rule_uuid,
        } = location;
        let plan = plan_artifact(
            action,
            &policy_uuid,
            scope,
            group_uuid.as_deref(),
            rule_uuid.as_deref(),
            &request,
            &before,
        );
        let prepared = Self {
            operation: "firewall_rule_write".to_owned(),
            action,
            policy_uuid,
            scope,
            group_uuid,
            rule_uuid,
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
    pub const fn action(&self) -> FirewallRuleWriteOperation {
        self.action
    }

    /// Target policy UUID.
    #[must_use]
    pub fn policy_uuid(&self) -> &str {
        &self.policy_uuid
    }

    /// Target scope.
    #[must_use]
    pub const fn scope(&self) -> FirewallRuleScope {
        self.scope
    }

    /// Target rule group UUID, if any.
    #[must_use]
    pub fn group_uuid(&self) -> Option<&str> {
        self.group_uuid.as_deref()
    }

    /// Target rule UUID, absent for create.
    #[must_use]
    pub fn rule_uuid(&self) -> Option<&str> {
        self.rule_uuid.as_deref()
    }

    /// Exact request body, `Null` for delete.
    #[must_use]
    pub const fn request(&self) -> &Value {
        &self.request
    }

    /// Rule state observed at prepare time, `Null` for create.
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
            &self.policy_uuid,
            self.scope,
            self.group_uuid.as_deref(),
            self.rule_uuid.as_deref(),
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
        if self.operation != "firewall_rule_write" {
            return Err(SdcError::PreparedChange(
                "prepared operation must be firewall_rule_write".to_owned(),
            ));
        }
        for (name, value) in [
            ("policy UUID", Some(self.policy_uuid.as_str())),
            ("group UUID", self.group_uuid.as_deref()),
            ("rule UUID", self.rule_uuid.as_deref()),
        ] {
            if let Some(value) = value
                && (value.is_empty()
                    || value.len() > 256
                    || value
                        .bytes()
                        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()))
            {
                return Err(SdcError::PreparedChange(format!(
                    "prepared {name} must be 1-256 non-whitespace bytes"
                )));
            }
        }
        let has_rule = self.rule_uuid.is_some();
        // Match the client's own body rule so an unexecutable plan cannot be
        // approved: create and update reject an empty object.
        let request_is_populated_object = self
            .request
            .as_object()
            .is_some_and(|fields| !fields.is_empty());
        // SDC ignores `position` on update; accepting it would let an
        // approved plan imply a move that never happens.
        let update_carries_position = self
            .request
            .as_object()
            .is_some_and(|fields| fields.contains_key("position"));
        let shape_ok = match self.action {
            FirewallRuleWriteOperation::Create => {
                !has_rule && request_is_populated_object && self.before.is_null()
            }
            FirewallRuleWriteOperation::Update => {
                has_rule
                    && request_is_populated_object
                    && !update_carries_position
                    && self.before.is_object()
            }
            FirewallRuleWriteOperation::Delete => {
                has_rule && self.request.is_null() && self.before.is_object()
            }
        };
        if !shape_ok {
            return Err(SdcError::PreparedChange(format!(
                "prepared {} does not match its required shape",
                self.action.as_str()
            )));
        }
        if crate::redact::contains_redaction_marker(&self.request) {
            return Err(SdcError::InvalidInput(
                "write body contains a redaction marker; re-read the field value out-of-band",
            ));
        }
        if canonical_digest(&self.plan())
            .map_err(|error| SdcError::PreparedChange(error.to_string()))?
            != self.plan_digest
        {
            return Err(SdcError::PreparedChange(
                "prepared firewall rule write does not match its digest".to_owned(),
            ));
        }
        if serde_json::to_vec(self)
            .map_err(|_| SdcError::Serialization)?
            .len()
            > MAX_ENVELOPE_BYTES
        {
            return Err(SdcError::PreparedChange(
                "prepared firewall rule write exceeds the 2097152-byte limit".to_owned(),
            ));
        }
        Ok(())
    }
}

fn plan_artifact(
    action: FirewallRuleWriteOperation,
    policy_uuid: &str,
    scope: FirewallRuleScope,
    group_uuid: Option<&str>,
    rule_uuid: Option<&str>,
    request: &Value,
    before: &Value,
) -> Value {
    json!({
        "action": action,
        "policy_uuid": policy_uuid,
        "scope": scope,
        "group_uuid": group_uuid,
        "rule_uuid": rule_uuid,
        "before": before,
        "after": request,
    })
}

/// Outcome of revalidating a rule write immediately before commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleValidationReport {
    /// Whether the envelope is intact and the target has not drifted.
    pub valid: bool,
    /// Which mutation was validated.
    pub action: FirewallRuleWriteOperation,
    /// Whether the live rule still matched its prepared `before` state.
    pub target_unchanged: bool,
}

/// SDC implementation of the shared transaction contract for rule writes.
#[derive(Clone)]
pub struct SdcFirewallRuleTransaction {
    client: SdcClient,
    expected_plan_digest: String,
    cancellation: CancellationToken,
    refused_before_write: Arc<AtomicBool>,
}

impl SdcFirewallRuleTransaction {
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
    #[must_use]
    pub fn refused_before_write(&self) -> bool {
        self.refused_before_write.load(Ordering::SeqCst)
    }

    /// Re-read the target and report whether it still matches its plan.
    ///
    /// Create has no prior rule, so it is vacuously unchanged.
    async fn target_unchanged(
        &self,
        staged: &SdcPreparedFirewallRuleWrite,
    ) -> Result<bool, SdcError> {
        let Some(rule_uuid) = staged.rule_uuid() else {
            return Ok(true);
        };
        let current = self
            .client
            .get_firewall_rule_at(
                staged.policy_uuid(),
                staged.scope().as_str(),
                staged.group_uuid(),
                rule_uuid,
                &self.cancellation,
            )
            .await?;
        let digest = |value: &Value| {
            canonical_digest(value).map_err(|error| SdcError::PreparedChange(error.to_string()))
        };
        Ok(digest(&current)? == digest(staged.before())?)
    }
}

#[async_trait]
impl DeviceTransaction for SdcFirewallRuleTransaction {
    type Action = SdcPreparedFirewallRuleWrite;
    type Staged = SdcPreparedFirewallRuleWrite;
    type Diff = Value;
    type Validation = FirewallRuleValidationReport;
    type Error = SdcError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        Ok(self.expected_plan_digest.clone())
    }

    /// Sole validation point for the envelope.
    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let [prepared] = actions else {
            return Err(SdcError::InvalidInput(
                "an SDC firewall rule write requires exactly one prepared change",
            ));
        };
        prepared.validate()?;
        if prepared.operation() != "firewall_rule_write"
            || prepared.plan_digest() != self.expected_plan_digest
        {
            return Err(SdcError::PreparedChange(
                "prepared action does not match the approved plan digest".to_owned(),
            ));
        }
        Ok(prepared.clone())
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        Ok(staged.plan())
    }

    /// Refuse the write if the target rule moved since it was prepared.
    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        let target_unchanged = self.target_unchanged(staged).await?;
        if !target_unchanged {
            return Err(SdcError::TargetDrifted);
        }
        Ok(FirewallRuleValidationReport {
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
        // Every exit until the request is issued is a pre-write refusal, so
        // the caller may discard the operation instead of stranding the
        // principal on a non-terminal record.
        self.refused_before_write.store(true, Ordering::SeqCst);
        if options.confirm_timeout.is_some() {
            return Err(SdcError::InvalidInput(
                "SDC does not support confirmed firewall rule writes",
            ));
        }
        // Re-check drift immediately before writing. SDC exposes no
        // conditional write, so this narrows the window rather than closing it.
        if !self.target_unchanged(staged).await? {
            return Err(SdcError::TargetDrifted);
        }
        let scope = staged.scope().as_str();
        let (policy, group) = (staged.policy_uuid(), staged.group_uuid());
        let missing_rule = || {
            SdcError::PreparedChange(
                "prepared firewall rule write is missing its rule UUID".to_owned(),
            )
        };
        // Resolve the target before the flag flips so a malformed envelope
        // still counts as a pre-write refusal.
        let rule = match staged.action() {
            FirewallRuleWriteOperation::Create => None,
            FirewallRuleWriteOperation::Update | FirewallRuleWriteOperation::Delete => {
                Some(staged.rule_uuid().ok_or_else(missing_rule)?)
            }
        };
        self.refused_before_write.store(false, Ordering::SeqCst);
        let result = match (staged.action(), rule) {
            (FirewallRuleWriteOperation::Create, _) => {
                self.client
                    .create_firewall_rule(
                        policy,
                        scope,
                        group,
                        staged.request(),
                        &self.cancellation,
                    )
                    .await
            }
            (FirewallRuleWriteOperation::Update, Some(rule)) => {
                self.client
                    .update_firewall_rule(
                        policy,
                        scope,
                        group,
                        rule,
                        staged.request(),
                        &self.cancellation,
                    )
                    .await
            }
            (FirewallRuleWriteOperation::Delete, Some(rule)) => {
                self.client
                    .delete_firewall_rule(policy, scope, group, rule, &self.cancellation)
                    .await
            }
            (FirewallRuleWriteOperation::Update | FirewallRuleWriteOperation::Delete, None) => {
                return Err(missing_rule());
            }
        };
        match result {
            Ok(_) => Ok(CommitOutcome::Reconciled {
                succeeded: true,
                job_id: None,
                details: Some(format!("SDC {} completed", staged.action().as_str())),
            }),
            Err(SdcError::Cancelled | SdcError::Timeout | SdcError::MutationOutcomeUnknown) => {
                Ok(CommitOutcome::Indeterminate {
                    reason:
                        "SDC firewall rule write was submitted but its outcome was not observed"
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
                    "no remote candidate exists; SDC firewall rule writes are not staged"
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
            "SDC does not support confirmed firewall rule writes",
        ))
    }
}

/// Result of planning a firewall rule write.
#[derive(Debug, Clone, Serialize)]
pub struct FirewallRulePrepareResult {
    /// Shared two-person change-set record.
    pub change_set: ChangeSetOutput,
    /// Exact rule write bound by the plan digest.
    pub prepared_change: SdcPreparedFirewallRuleWrite,
}

/// Result of applying one approved firewall rule write.
#[derive(Debug, Clone, Serialize)]
pub struct FirewallRuleApplyResult {
    /// Shared operation identifier.
    pub operation_id: String,
    /// Before/after plan used as the management-plane diff.
    pub plan: Value,
    /// Drift and envelope validation result.
    pub validation: FirewallRuleValidationReport,
    /// Known, detached, or indeterminate commit disposition.
    pub outcome: CommitOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn location(rule: Option<&str>) -> FirewallRuleLocation {
        FirewallRuleLocation {
            policy_uuid: "policy-1".to_owned(),
            scope: FirewallRuleScope::Zone,
            group_uuid: None,
            rule_uuid: rule.map(str::to_owned),
        }
    }

    fn create(location: FirewallRuleLocation, body: Value) -> SdcPreparedFirewallRuleWrite {
        SdcPreparedFirewallRuleWrite::new(
            FirewallRuleWriteOperation::Create,
            location,
            body,
            Value::Null,
        )
        .expect("valid create")
    }

    #[test]
    fn the_digest_binds_policy_scope_group_rule_and_position() {
        let body = json!({"name": "r", "position": 0});
        let base = create(location(None), body.clone());

        let mut other_policy = location(None);
        other_policy.policy_uuid = "policy-2".to_owned();
        let mut other_scope = location(None);
        other_scope.scope = FirewallRuleScope::Global;
        let mut other_group = location(None);
        other_group.group_uuid = Some("group-1".to_owned());

        for (label, other) in [
            ("policy", create(other_policy, body.clone())),
            ("scope", create(other_scope, body.clone())),
            ("group", create(other_group, body.clone())),
            (
                "position",
                create(location(None), json!({"name": "r", "position": 3})),
            ),
        ] {
            assert_ne!(
                base.plan_digest(),
                other.plan_digest(),
                "the {label} must be covered by the plan digest"
            );
        }
    }

    #[test]
    fn a_tampered_location_fails_validation() {
        let prepared = create(location(None), json!({"name": "r"}));
        for field in ["policy_uuid", "scope", "group_uuid"] {
            let mut raw = serde_json::to_value(&prepared).expect("serializes");
            raw[field] = if field == "scope" {
                json!("global")
            } else {
                json!("elsewhere")
            };
            let tampered: SdcPreparedFirewallRuleWrite =
                serde_json::from_value(raw).expect("still deserializes");
            assert!(
                matches!(tampered.validate(), Err(SdcError::PreparedChange(_))),
                "tampering with {field} must break the digest"
            );
        }
    }

    #[test]
    fn a_tampered_body_fails_validation() {
        let prepared = create(location(None), json!({"name": "r"}));
        let mut raw = serde_json::to_value(&prepared).expect("serializes");
        raw["request"]["name"] = json!("other");
        let tampered: SdcPreparedFirewallRuleWrite =
            serde_json::from_value(raw).expect("still deserializes");
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn a_mismatched_action_or_body_shape_is_refused() {
        let new = |action, rule: Option<&str>, request, before| {
            SdcPreparedFirewallRuleWrite::new(action, location(rule), request, before)
        };
        let live = json!({"uuid": "rule-1", "name": "r"});
        // Create must not name a rule, and carries no prior state.
        assert!(
            new(
                FirewallRuleWriteOperation::Create,
                Some("rule-1"),
                json!({"name": "r"}),
                Value::Null
            )
            .is_err()
        );
        assert!(
            new(
                FirewallRuleWriteOperation::Create,
                None,
                json!({}),
                Value::Null
            )
            .is_err()
        );
        assert!(
            new(
                FirewallRuleWriteOperation::Create,
                None,
                Value::Null,
                Value::Null
            )
            .is_err()
        );
        assert!(
            new(
                FirewallRuleWriteOperation::Create,
                None,
                json!({"name": "r"}),
                live.clone()
            )
            .is_err()
        );
        // Update and delete must name a rule and carry its prior state.
        assert!(
            new(
                FirewallRuleWriteOperation::Update,
                None,
                json!({"name": "r"}),
                live.clone()
            )
            .is_err()
        );
        assert!(
            new(
                FirewallRuleWriteOperation::Update,
                Some("rule-1"),
                json!({"name": "r"}),
                Value::Null
            )
            .is_err()
        );
        assert!(
            new(
                FirewallRuleWriteOperation::Delete,
                Some("rule-1"),
                json!({"name": "r"}),
                live.clone()
            )
            .is_err()
        );
        assert!(
            new(
                FirewallRuleWriteOperation::Delete,
                None,
                Value::Null,
                live.clone()
            )
            .is_err()
        );
        // Position is create-only; update would silently ignore it.
        assert!(
            new(
                FirewallRuleWriteOperation::Update,
                Some("rule-1"),
                json!({"name": "r", "position": 2}),
                live.clone()
            )
            .is_err()
        );
        // The well-formed shapes are accepted.
        assert!(
            new(
                FirewallRuleWriteOperation::Update,
                Some("rule-1"),
                json!({"name": "r"}),
                live.clone()
            )
            .is_ok()
        );
        assert!(
            new(
                FirewallRuleWriteOperation::Delete,
                Some("rule-1"),
                Value::Null,
                live
            )
            .is_ok()
        );
    }

    #[test]
    fn identifiers_with_whitespace_or_control_bytes_are_refused() {
        for bad in ["", "a b", "a\nb", "a\u{0}b"] {
            let mut loc = location(None);
            loc.policy_uuid = bad.to_owned();
            assert!(
                SdcPreparedFirewallRuleWrite::new(
                    FirewallRuleWriteOperation::Create,
                    loc,
                    json!({"name": "r"}),
                    Value::Null
                )
                .is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_redaction_marker_in_the_body_is_refused() {
        let error = SdcPreparedFirewallRuleWrite::new(
            FirewallRuleWriteOperation::Create,
            location(None),
            json!({"name": crate::REDACTED}),
            Value::Null,
        )
        .expect_err("a redaction marker must be refused");
        assert!(matches!(error, SdcError::InvalidInput(_)), "{error:?}");
    }
}
