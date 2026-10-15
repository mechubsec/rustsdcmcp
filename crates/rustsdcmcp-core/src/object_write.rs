//! Change-controlled writes to the allowlisted SDC object families.
//!
//! Object writes have no SDC-side preview endpoint, so the plan artifact is
//! built locally: it records the exact request together with the object's
//! observed state beforehand. Apply refuses if that state has since moved,
//! which is the object-write analogue of binding a deploy to its preview.

use crate::{SdcClient, SdcError, WritableResource, prepared::canonical_digest};
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

/// Hard cap on one serialized object-write envelope.
const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;

/// Which mutation one object write performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObjectWriteAction {
    /// Create a new object in the family.
    Create,
    /// Replace an existing object by UUID.
    Update,
    /// Delete an existing object by UUID.
    Delete,
}

impl ObjectWriteAction {
    /// Stable discriminator recorded in audit and change-control state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "object_create",
            Self::Update => "object_update",
            Self::Delete => "object_delete",
        }
    }
}

/// Exact object write bound into a change-set action.
///
/// Product-owned while its vendor-neutral extraction is tracked in mecmcp#90.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdcPreparedObjectWrite {
    operation: String,
    action: ObjectWriteAction,
    resource: WritableResource,
    uuid: Option<String>,
    request: Value,
    before: Value,
    plan_digest: String,
}

impl SdcPreparedObjectWrite {
    /// Build a canonical, digest-bound object write.
    ///
    /// `before` is the object's observed state for update and delete, and
    /// `Value::Null` for create.
    ///
    /// # Errors
    ///
    /// Refuses shapes that do not match the action, and oversized envelopes.
    pub fn new(
        action: ObjectWriteAction,
        resource: WritableResource,
        uuid: Option<String>,
        request: Value,
        before: Value,
    ) -> Result<Self, SdcError> {
        let plan = plan_artifact(action, resource, uuid.as_deref(), &request, &before);
        let prepared = Self {
            operation: "object_write".to_owned(),
            action,
            resource,
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
    pub const fn action(&self) -> ObjectWriteAction {
        self.action
    }

    /// Which object family this write targets.
    #[must_use]
    pub const fn resource(&self) -> WritableResource {
        self.resource
    }

    /// Target object UUID, absent for create.
    #[must_use]
    pub fn uuid(&self) -> Option<&str> {
        self.uuid.as_deref()
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
            self.resource,
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
        if self.operation != "object_write" {
            return Err(SdcError::PreparedChange(
                "prepared operation must be object_write".to_owned(),
            ));
        }
        let has_uuid = self.uuid.is_some();
        // Match the client's own body rule here so an unexecutable plan cannot
        // be approved: `create_resource` and `update_resource` reject an empty
        // object, and discovering that only at commit would burn a change set.
        let request_is_populated_object = self
            .request
            .as_object()
            .is_some_and(|fields| !fields.is_empty());
        let before_is_object = self.before.is_object();
        let shape_ok = match self.action {
            ObjectWriteAction::Create => {
                !has_uuid && request_is_populated_object && self.before.is_null()
            }
            ObjectWriteAction::Update => {
                has_uuid && request_is_populated_object && before_is_object
            }
            ObjectWriteAction::Delete => has_uuid && self.request.is_null() && before_is_object,
        };
        if !shape_ok {
            return Err(SdcError::PreparedChange(format!(
                "prepared {} does not match its required shape",
                self.action.as_str()
            )));
        }
        if let Some(uuid) = self.uuid.as_deref()
            && (uuid.is_empty()
                || uuid.len() > 256
                || uuid
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()))
        {
            return Err(SdcError::PreparedChange(
                "prepared object UUID must be 1-256 non-whitespace bytes".to_owned(),
            ));
        }
        let plan = plan_artifact(
            self.action,
            self.resource,
            self.uuid.as_deref(),
            &self.request,
            &self.before,
        );
        if canonical_digest(&plan).map_err(|error| SdcError::PreparedChange(error.to_string()))?
            != self.plan_digest
        {
            return Err(SdcError::PreparedChange(
                "prepared object write does not match its digest".to_owned(),
            ));
        }
        if serde_json::to_vec(self)
            .map_err(|_| SdcError::Serialization)?
            .len()
            > MAX_ENVELOPE_BYTES
        {
            return Err(SdcError::PreparedChange(
                "prepared object write exceeds the 2097152-byte limit".to_owned(),
            ));
        }
        Ok(())
    }
}

fn plan_artifact(
    action: ObjectWriteAction,
    resource: WritableResource,
    uuid: Option<&str>,
    request: &Value,
    before: &Value,
) -> Value {
    json!({
        "action": action,
        "resource": resource,
        "uuid": uuid,
        "before": before,
        "after": request,
    })
}

/// Outcome of revalidating an object write immediately before commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectValidationReport {
    /// Whether the envelope is intact and the target has not drifted.
    pub valid: bool,
    /// Which mutation was validated.
    pub action: ObjectWriteAction,
    /// Whether the live object still matched its prepared `before` state.
    pub target_unchanged: bool,
}

/// SDC implementation of the shared transaction contract for object writes.
#[derive(Clone)]
pub struct SdcObjectTransaction {
    client: SdcClient,
    expected_plan_digest: String,
    cancellation: CancellationToken,
    refused_before_write: Arc<AtomicBool>,
}

impl SdcObjectTransaction {
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
    async fn target_unchanged(&self, staged: &SdcPreparedObjectWrite) -> Result<bool, SdcError> {
        let (ObjectWriteAction::Update | ObjectWriteAction::Delete, Some(uuid)) =
            (staged.action(), staged.uuid())
        else {
            return Ok(true);
        };
        let current = self
            .client
            .get_resource(staged.resource().into(), uuid, &self.cancellation)
            .await?;
        let digest = |value: &Value| {
            canonical_digest(value).map_err(|error| SdcError::PreparedChange(error.to_string()))
        };
        Ok(digest(&current)? == digest(staged.before())?)
    }
}

#[async_trait]
impl DeviceTransaction for SdcObjectTransaction {
    type Action = SdcPreparedObjectWrite;
    type Staged = SdcPreparedObjectWrite;
    type Diff = Value;
    type Validation = ObjectValidationReport;
    type Error = SdcError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        Ok(self.expected_plan_digest.clone())
    }

    /// Sole validation point for the envelope, mirroring `SdcTransaction`.
    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let [prepared] = actions else {
            return Err(SdcError::InvalidInput(
                "an SDC object write requires exactly one prepared change",
            ));
        };
        prepared.validate()?;
        if prepared.operation() != "object_write"
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
    /// An object write has no SDC preview to bind, so this drift check is what
    /// makes the approved digest meaningful at apply time.
    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        let target_unchanged = self.target_unchanged(staged).await?;
        if !target_unchanged {
            return Err(SdcError::TargetDrifted);
        }
        Ok(ObjectValidationReport {
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
                "SDC does not support confirmed object writes",
            ));
        }
        // Re-check drift immediately before writing. `validate` already checked,
        // but the coordinator releases and reacquires its guard in between, and
        // that guard cannot exclude a writer working directly against SDC.
        // Without this, a stale PUT or DELETE could overwrite state that was
        // never in the approved plan.
        //
        // A refusal here is recorded as the non-terminal `Failed` state, so the
        // flag lets `apply_object_write` discard it: nothing was sent, which
        // makes that discard truthful.
        //
        // This narrows the window rather than closing it. SDC exposes no
        // conditional write, so a change landing between this read and the
        // request below is still possible.
        if !self.target_unchanged(staged).await? {
            return Err(SdcError::TargetDrifted);
        }
        let resource = staged.resource();
        // The mutation is about to go out. Past this point its outcome is no
        // longer knowably clean, so the operation must not be auto-discarded.
        self.refused_before_write.store(false, Ordering::SeqCst);
        let result = match (staged.action(), staged.uuid()) {
            (ObjectWriteAction::Create, _) => {
                self.client
                    .create_resource(resource, staged.request(), &self.cancellation)
                    .await
            }
            (ObjectWriteAction::Update, Some(uuid)) => {
                self.client
                    .update_resource(resource, uuid, staged.request(), &self.cancellation)
                    .await
            }
            (ObjectWriteAction::Delete, Some(uuid)) => {
                self.client
                    .delete_resource(resource, uuid, &self.cancellation)
                    .await
            }
            (ObjectWriteAction::Update | ObjectWriteAction::Delete, None) => {
                return Err(SdcError::PreparedChange(
                    "prepared object write is missing its target UUID".to_owned(),
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
                    reason: "SDC object write was submitted but its outcome was not observed"
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

    /// Release a planned-but-uncommitted object write.
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
                    "no remote candidate exists; SDC object writes are not staged".to_owned(),
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
            "SDC does not support confirmed object writes",
        ))
    }
}
