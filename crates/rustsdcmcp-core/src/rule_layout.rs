//! Change-controlled rule ordering and rule-group creation for SDC firewall
//! policies.
//!
//! Neither write has an SDC-side preview endpoint, so the plan artifact is
//! built locally: it records the exact request, the policy and scope it lands
//! in, and the scope's observed rule and group ordering beforehand. Apply
//! refuses if that ordering has since moved.

use crate::{FirewallRuleScope, SdcClient, SdcError, prepared::canonical_digest};
use async_trait::async_trait;
use mecmcp_audit::Attribution;
use mecmcp_changeset::{
    ChangeSetOutput, CommitOptions, CommitOutcome, DeviceTransaction, RollbackOutcome, RollbackRef,
    UnlockOutcome,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio_util::sync::CancellationToken;

/// Hard cap on one serialized layout-write envelope.
const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
/// Most rules one move may name.
const MAX_MOVED_RULES: usize = 500;

/// Which layout mutation one write performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FirewallRuleLayoutOperation {
    /// Move one or more rules to a new position.
    MoveRules,
    /// Create a rule group.
    CreateGroup,
}

impl FirewallRuleLayoutOperation {
    /// Stable discriminator recorded in audit and change-control state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MoveRules => "firewall_rule_move",
            Self::CreateGroup => "firewall_rule_group_create",
        }
    }
}

/// Where a layout write lands and what it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallLayoutRequest {
    /// Firewall policy UUID.
    pub policy_uuid: String,
    /// Policy scope.
    pub scope: FirewallRuleScope,
    /// The mutation to plan.
    pub change: FirewallLayoutChange,
}

/// One layout mutation and the arguments only it accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallLayoutChange {
    /// Move rules, in the given order, to a position.
    MoveRules {
        /// Rules to move.
        rule_uuids: Vec<String>,
        /// Destination rule group, if any.
        target_group_uuid: Option<String>,
        /// Destination position.
        position: u32,
    },
    /// Create a rule group.
    CreateGroup {
        /// Group name.
        name: String,
        /// Group description.
        description: Option<String>,
        /// Position of the group in the policy, from 0.
        position: Option<u32>,
    },
}

/// The only request shape SDC accepts for a rule move.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MoveBody {
    rule_uuids: Vec<String>,
    #[serde(default)]
    target_rule_group_id: Option<String>,
    position: u32,
    target_scope: String,
}

/// The only request shape this tool sends for a rule-group create.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    position: Option<u32>,
}

/// Exact layout write bound into a change-set action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdcPreparedFirewallRuleLayout {
    operation: String,
    action: FirewallRuleLayoutOperation,
    policy_uuid: String,
    scope: FirewallRuleScope,
    request: Value,
    before: Value,
    plan_digest: String,
}

fn scope_enum(scope: FirewallRuleScope) -> &'static str {
    match scope {
        FirewallRuleScope::Zone => "ZONE",
        FirewallRuleScope::Global => "GLOBAL",
    }
}

fn bad_shape(action: FirewallRuleLayoutOperation) -> SdcError {
    SdcError::PreparedChange(format!(
        "prepared {} does not match its required shape",
        action.as_str()
    ))
}

fn valid_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

impl SdcPreparedFirewallRuleLayout {
    /// Plan moving `rule_uuids`, in the given order, to `position`.
    ///
    /// `before` is the scope's observed ordering. `target_scope` is derived
    /// from `scope`, so a plan cannot move rules across scopes.
    ///
    /// # Errors
    ///
    /// Refuses malformed identifiers, duplicate or empty rule lists, and
    /// oversized envelopes.
    pub fn move_rules(
        policy_uuid: String,
        scope: FirewallRuleScope,
        rule_uuids: Vec<String>,
        target_rule_group_id: Option<String>,
        position: u32,
        before: Value,
    ) -> Result<Self, SdcError> {
        let mut request = json!({
            "rule_uuids": rule_uuids,
            "position": position,
            "target_scope": scope_enum(scope),
        });
        if let (Some(group), Some(fields)) = (target_rule_group_id, request.as_object_mut()) {
            fields.insert("target_rule_group_id".to_owned(), Value::String(group));
        }
        Self::build(
            FirewallRuleLayoutOperation::MoveRules,
            policy_uuid,
            scope,
            request,
            before,
        )
    }

    /// Plan creating a rule group.
    ///
    /// # Errors
    ///
    /// Refuses a malformed identifier, name, or description, and oversized
    /// envelopes.
    pub fn create_group(
        policy_uuid: String,
        scope: FirewallRuleScope,
        name: String,
        description: Option<String>,
        position: Option<u32>,
        before: Value,
    ) -> Result<Self, SdcError> {
        let mut request = json!({ "name": name });
        if let Some(fields) = request.as_object_mut() {
            if let Some(description) = description {
                fields.insert("description".to_owned(), Value::String(description));
            }
            if let Some(position) = position {
                fields.insert("position".to_owned(), Value::from(position));
            }
        }
        Self::build(
            FirewallRuleLayoutOperation::CreateGroup,
            policy_uuid,
            scope,
            request,
            before,
        )
    }

    fn build(
        action: FirewallRuleLayoutOperation,
        policy_uuid: String,
        scope: FirewallRuleScope,
        request: Value,
        before: Value,
    ) -> Result<Self, SdcError> {
        let plan = plan_artifact(action, &policy_uuid, scope, &request, &before);
        let prepared = Self {
            operation: "firewall_rule_layout_write".to_owned(),
            action,
            policy_uuid,
            scope,
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
    pub const fn action(&self) -> FirewallRuleLayoutOperation {
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

    /// Exact request body.
    #[must_use]
    pub const fn request(&self) -> &Value {
        &self.request
    }

    /// Scope ordering observed at prepare time.
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
        if self.operation != "firewall_rule_layout_write" {
            return Err(SdcError::PreparedChange(
                "prepared operation must be firewall_rule_layout_write".to_owned(),
            ));
        }
        if !valid_atom(&self.policy_uuid) {
            return Err(SdcError::PreparedChange(
                "prepared policy UUID must be 1-256 non-whitespace bytes".to_owned(),
            ));
        }
        let items = complete_items(&self.before).ok_or_else(|| bad_shape(self.action))?;
        match self.action {
            FirewallRuleLayoutOperation::MoveRules => {
                let body: MoveBody = serde_json::from_value(self.request.clone())
                    .map_err(|_| bad_shape(self.action))?;
                let distinct: BTreeSet<&str> = body.rule_uuids.iter().map(String::as_str).collect();
                let ok = !body.rule_uuids.is_empty()
                    && body.rule_uuids.len() <= MAX_MOVED_RULES
                    && distinct.len() == body.rule_uuids.len()
                    && body.rule_uuids.iter().all(|uuid| valid_atom(uuid))
                    && body.target_rule_group_id.as_deref().is_none_or(valid_atom)
                    && body.target_scope == scope_enum(self.scope);
                // `position` is range-checked by its `u32` type.
                let _ = body.position;
                if !ok {
                    return Err(bad_shape(self.action));
                }
                // Every moved rule and the target group must be in the scope
                // the approver was shown; SDC is not trusted to refuse others.
                let known = |uuid: &str, group: bool| {
                    items.iter().any(|item| {
                        item.get("uuid").and_then(Value::as_str) == Some(uuid)
                            && is_group(item) == group
                    })
                };
                if !body.rule_uuids.iter().all(|uuid| known(uuid, false))
                    || !body
                        .target_rule_group_id
                        .as_deref()
                        .is_none_or(|g| known(g, true))
                {
                    return Err(SdcError::PreparedChange(
                        "moved rules and target group must exist in the observed scope ordering"
                            .to_owned(),
                    ));
                }
            }
            FirewallRuleLayoutOperation::CreateGroup => {
                let body: GroupBody = serde_json::from_value(self.request.clone())
                    .map_err(|_| bad_shape(self.action))?;
                let text_ok = |text: &str, max: usize| {
                    text.len() <= max && !text.chars().any(|c| c.is_control() && c != '\n')
                };
                let _ = body.position;
                if body.name.trim().is_empty()
                    || !text_ok(&body.name, 256)
                    || body.name.contains('\n')
                    || !body.description.as_deref().is_none_or(|d| text_ok(d, 2048))
                {
                    return Err(bad_shape(self.action));
                }
            }
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
                "prepared firewall rule layout write does not match its digest".to_owned(),
            ));
        }
        if serde_json::to_vec(self)
            .map_err(|_| SdcError::Serialization)?
            .len()
            > MAX_ENVELOPE_BYTES
        {
            return Err(SdcError::PreparedChange(
                "prepared firewall rule layout write exceeds the 2097152-byte limit".to_owned(),
            ));
        }
        Ok(())
    }
}

/// The items of an observed ordering, only if it is demonstrably complete.
fn complete_items(before: &Value) -> Option<&Vec<Value>> {
    let items = before.get("items")?.as_array()?;
    let count = before.get("count")?.as_u64()?;
    (items.len() as u64 >= count).then_some(items)
}

fn is_group(item: &Value) -> bool {
    item.get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.to_ascii_lowercase().contains("group"))
}

fn plan_artifact(
    action: FirewallRuleLayoutOperation,
    policy_uuid: &str,
    scope: FirewallRuleScope,
    request: &Value,
    before: &Value,
) -> Value {
    json!({
        "action": action,
        "policy_uuid": policy_uuid,
        "scope": scope,
        "before": before,
        "after": request,
    })
}

/// Outcome of revalidating a layout write immediately before commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleLayoutValidationReport {
    /// Whether the envelope is intact and the ordering has not drifted.
    pub valid: bool,
    /// Which mutation was validated.
    pub action: FirewallRuleLayoutOperation,
    /// Whether the live ordering still matched its prepared `before` state.
    pub target_unchanged: bool,
}

/// SDC implementation of the shared transaction contract for layout writes.
#[derive(Clone)]
pub struct SdcFirewallRuleLayoutTransaction {
    client: SdcClient,
    expected_plan_digest: String,
    cancellation: CancellationToken,
    refused_before_write: Arc<AtomicBool>,
}

impl SdcFirewallRuleLayoutTransaction {
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

    /// Re-read the scope ordering and report whether it still matches the plan.
    async fn target_unchanged(
        &self,
        staged: &SdcPreparedFirewallRuleLayout,
    ) -> Result<bool, SdcError> {
        let current = self
            .client
            .get_firewall_layout(
                staged.policy_uuid(),
                staged.scope().as_str(),
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
impl DeviceTransaction for SdcFirewallRuleLayoutTransaction {
    type Action = SdcPreparedFirewallRuleLayout;
    type Staged = SdcPreparedFirewallRuleLayout;
    type Diff = Value;
    type Validation = FirewallRuleLayoutValidationReport;
    type Error = SdcError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        Ok(self.expected_plan_digest.clone())
    }

    /// Sole validation point for the envelope.
    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let [prepared] = actions else {
            return Err(SdcError::InvalidInput(
                "an SDC firewall rule layout write requires exactly one prepared change",
            ));
        };
        prepared.validate()?;
        if prepared.plan_digest() != self.expected_plan_digest {
            return Err(SdcError::PreparedChange(
                "prepared action does not match the approved plan digest".to_owned(),
            ));
        }
        Ok(prepared.clone())
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        Ok(staged.plan())
    }

    /// Refuse the write if the scope ordering moved since it was prepared.
    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        let target_unchanged = self.target_unchanged(staged).await?;
        if !target_unchanged {
            return Err(SdcError::TargetDrifted);
        }
        Ok(FirewallRuleLayoutValidationReport {
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
                "SDC does not support confirmed firewall rule layout writes",
            ));
        }
        // Re-check drift immediately before writing. SDC exposes no
        // conditional write, so this narrows the window rather than closing it.
        if !self.target_unchanged(staged).await? {
            return Err(SdcError::TargetDrifted);
        }
        self.refused_before_write.store(false, Ordering::SeqCst);
        let (policy, scope) = (staged.policy_uuid(), staged.scope().as_str());
        let result = match staged.action() {
            FirewallRuleLayoutOperation::MoveRules => {
                self.client
                    .move_firewall_rules(policy, scope, staged.request(), &self.cancellation)
                    .await
            }
            FirewallRuleLayoutOperation::CreateGroup => {
                self.client
                    .create_firewall_rule_group(policy, scope, staged.request(), &self.cancellation)
                    .await
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
                    reason: "SDC firewall rule layout write was submitted but its outcome was not observed"
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
                    "no remote candidate exists; SDC firewall rule layout writes are not staged"
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
            "SDC does not support confirmed firewall rule layout writes",
        ))
    }
}

/// Result of planning a layout write.
#[derive(Debug, Clone, Serialize)]
pub struct FirewallRuleLayoutPrepareResult {
    /// Shared two-person change-set record.
    pub change_set: ChangeSetOutput,
    /// Exact layout write bound by the plan digest.
    pub prepared_change: SdcPreparedFirewallRuleLayout,
}

/// Result of applying one approved layout write.
#[derive(Debug, Clone, Serialize)]
pub struct FirewallRuleLayoutApplyResult {
    /// Shared operation identifier.
    pub operation_id: String,
    /// Before/after plan used as the management-plane diff.
    pub plan: Value,
    /// Drift and envelope validation result.
    pub validation: FirewallRuleLayoutValidationReport,
    /// Known, detached, or indeterminate commit disposition.
    pub outcome: CommitOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(order: &[&str]) -> Value {
        let mut items: Vec<Value> = order
            .iter()
            .map(|u| json!({"uuid": u, "type": "rule"}))
            .collect();
        items.push(json!({"uuid": "g", "type": "group"}));
        json!({"items": items, "count": items.len()})
    }

    fn mv(rules: &[&str], group: Option<&str>, position: u32) -> SdcPreparedFirewallRuleLayout {
        SdcPreparedFirewallRuleLayout::move_rules(
            "policy-1".to_owned(),
            FirewallRuleScope::Zone,
            rules.iter().map(|r| (*r).to_owned()).collect(),
            group.map(str::to_owned),
            position,
            layout(&["a", "b", "c"]),
        )
        .expect("valid move")
    }

    #[test]
    fn the_digest_binds_location_order_and_position() {
        let base = mv(&["a", "b"], None, 0);
        let other_policy = SdcPreparedFirewallRuleLayout::move_rules(
            "policy-2".to_owned(),
            FirewallRuleScope::Zone,
            vec!["a".to_owned(), "b".to_owned()],
            None,
            0,
            layout(&["a", "b", "c"]),
        )
        .expect("valid");
        let other_scope = SdcPreparedFirewallRuleLayout::move_rules(
            "policy-1".to_owned(),
            FirewallRuleScope::Global,
            vec!["a".to_owned(), "b".to_owned()],
            None,
            0,
            layout(&["a", "b", "c"]),
        )
        .expect("valid");
        let other_before = SdcPreparedFirewallRuleLayout::move_rules(
            "policy-1".to_owned(),
            FirewallRuleScope::Zone,
            vec!["a".to_owned(), "b".to_owned()],
            None,
            0,
            layout(&["c", "b", "a"]),
        )
        .expect("valid");
        for (label, other) in [
            ("rule order", mv(&["b", "a"], None, 0)),
            ("position", mv(&["a", "b"], None, 1)),
            ("target group", mv(&["a", "b"], Some("g"), 0)),
            ("policy", other_policy),
            ("scope", other_scope),
            ("observed ordering", other_before),
        ] {
            assert_ne!(base.plan_digest(), other.plan_digest(), "{label}");
        }
    }

    #[test]
    fn a_tampered_envelope_fails_validation() {
        let prepared = mv(&["a", "b"], None, 0);
        for (field, value) in [
            ("policy_uuid", json!("elsewhere")),
            ("scope", json!("global")),
            ("action", json!("create_group")),
            (
                "request",
                json!({"rule_uuids": ["b", "a"], "position": 0, "target_scope": "ZONE"}),
            ),
            ("before", json!({"items": [], "count": 0})),
            ("plan_digest", json!("00")),
        ] {
            let mut raw = serde_json::to_value(&prepared).expect("serializes");
            raw[field] = value;
            let tampered: SdcPreparedFirewallRuleLayout =
                serde_json::from_value(raw).expect("still deserializes");
            assert!(tampered.validate().is_err(), "{field}");
        }
    }

    #[test]
    fn malformed_move_shapes_are_refused() {
        let build = |rules: Vec<&str>, group: Option<&str>| {
            SdcPreparedFirewallRuleLayout::move_rules(
                "policy-1".to_owned(),
                FirewallRuleScope::Zone,
                rules.into_iter().map(str::to_owned).collect(),
                group.map(str::to_owned),
                0,
                layout(&["a"]),
            )
        };
        assert!(build(vec![], None).is_err(), "empty list");
        assert!(build(vec!["a", "a"], None).is_err(), "duplicate rule");
        assert!(build(vec!["a b"], None).is_err(), "whitespace");
        assert!(build(vec![""], None).is_err(), "empty id");
        assert!(build(vec!["a"], Some("g\n")).is_err(), "control byte");
        assert!(build(vec!["a"], Some("g")).is_ok());
        assert!(build(vec!["zz"], None).is_err(), "rule not in the scope");
        assert!(build(vec!["g"], None).is_err(), "a group is not a rule");
        assert!(
            build(vec!["a"], Some("a")).is_err(),
            "a rule is not a group"
        );
        assert!(build(vec!["a"], Some("nope")).is_err(), "unknown group");

        // A body shape the action does not allow is refused even if the
        // digest is recomputed to match.
        let forged = SdcPreparedFirewallRuleLayout::build(
            FirewallRuleLayoutOperation::MoveRules,
            "policy-1".to_owned(),
            FirewallRuleScope::Zone,
            json!({"name": "g"}),
            layout(&["a"]),
        );
        assert!(forged.is_err(), "group body under a move action");
        let cross_scope = SdcPreparedFirewallRuleLayout::build(
            FirewallRuleLayoutOperation::MoveRules,
            "policy-1".to_owned(),
            FirewallRuleScope::Zone,
            json!({"rule_uuids": ["a"], "position": 0, "target_scope": "GLOBAL"}),
            layout(&["a"]),
        );
        assert!(cross_scope.is_err(), "target scope must match the scope");
        let extra = SdcPreparedFirewallRuleLayout::build(
            FirewallRuleLayoutOperation::MoveRules,
            "policy-1".to_owned(),
            FirewallRuleScope::Zone,
            json!({"rule_uuids": ["a"], "position": 0, "target_scope": "ZONE", "x": 1}),
            layout(&["a"]),
        );
        assert!(extra.is_err(), "unknown field");
        let negative = SdcPreparedFirewallRuleLayout::build(
            FirewallRuleLayoutOperation::MoveRules,
            "policy-1".to_owned(),
            FirewallRuleScope::Zone,
            json!({"rule_uuids": ["a"], "position": -1, "target_scope": "ZONE"}),
            layout(&["a"]),
        );
        assert!(negative.is_err(), "negative position");
    }

    #[test]
    fn malformed_group_shapes_are_refused() {
        let build = |name: &str, description: Option<&str>| {
            SdcPreparedFirewallRuleLayout::create_group(
                "policy-1".to_owned(),
                FirewallRuleScope::Global,
                name.to_owned(),
                description.map(str::to_owned),
                Some(0),
                layout(&[]),
            )
        };
        assert!(build("web", Some("front door")).is_ok());
        assert!(build("", None).is_err());
        assert!(build("   ", None).is_err());
        assert!(build("a\nb", None).is_err());
        assert!(build("a\u{0}b", None).is_err());
        assert!(build(&"x".repeat(257), None).is_err());
        assert!(build("web", Some("bad\u{7}")).is_err());
        let forged = SdcPreparedFirewallRuleLayout::build(
            FirewallRuleLayoutOperation::CreateGroup,
            "policy-1".to_owned(),
            FirewallRuleScope::Global,
            json!({"rule_uuids": ["a"], "position": 0, "target_scope": "GLOBAL"}),
            layout(&[]),
        );
        assert!(forged.is_err(), "move body under a create_group action");
    }

    #[test]
    fn an_incomplete_or_malformed_ordering_is_refused() {
        let build = |before: Value| {
            SdcPreparedFirewallRuleLayout::create_group(
                "policy-1".to_owned(),
                FirewallRuleScope::Zone,
                "web".to_owned(),
                None,
                None,
                before,
            )
        };
        assert!(build(json!({"items": [{"uuid": "a", "type": "rule"}], "count": 2})).is_err());
        assert!(build(json!({"items": []})).is_err(), "missing count");
        assert!(
            build(json!({"items": [], "count": "0"})).is_err(),
            "non-numeric count"
        );
        assert!(build(json!({"count": 0})).is_err(), "missing items");
        assert!(build(json!({"items": [], "count": 0})).is_ok());
    }

    #[test]
    fn a_redaction_marker_is_refused() {
        let error = SdcPreparedFirewallRuleLayout::create_group(
            "policy-1".to_owned(),
            FirewallRuleScope::Zone,
            crate::REDACTED.to_owned(),
            None,
            None,
            layout(&[]),
        )
        .expect_err("redaction marker");
        assert!(matches!(error, SdcError::InvalidInput(_)), "{error:?}");
    }
}
