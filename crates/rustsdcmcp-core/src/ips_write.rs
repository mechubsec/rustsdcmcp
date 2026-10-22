//! Change-controlled writes to SDC IPS signatures and IPS profiles (#266).
//!
//! Deliberately a separate path from [`crate::SdcPreparedObjectWrite`] rather
//! than two more [`crate::WritableResource`] families:
//!
//! - **Scope.** Folding IPS into `prepare_sdc_object_write` would hand every
//!   existing object-write token IPS authoring without anyone re-minting it.
//!   Separate tools keep that a deliberate grant.
//! - **Guards the generic path cannot express.** A predefined signature (one
//!   imported from Juniper's signature bundle) must never be rewritten, and a
//!   write body must not smuggle server-assigned identity fields.
//! - **Reference checks before delete.** A profile still referenced by a
//!   firewall rule or a global setting, or a signature still referenced by an
//!   IPS or exempt rule, is refused at prepare (see [`find_profile_references`]
//!   and [`find_signature_references`]) rather than left to fail upstream or
//!   orphan the referrer.
//!
//! Like object writes, IPS writes have no SDC-side preview endpoint, so the
//! plan artifact is built locally: the exact request together with the
//! target's observed state beforehand, and apply refuses if that state has
//! since moved.
//!
//! An IPS write changes SDC's model only. Nothing reaches a device until a
//! policy referencing the profile is deployed through
//! `prepare_sdc_policy_deploy` → approve → `apply_sdc_change_set`.

use crate::{ListRequest, ResourceKind, SdcClient, SdcError, prepared::canonical_digest};
use async_trait::async_trait;
use mecmcp_audit::Attribution;
use mecmcp_changeset::{
    CommitOptions, CommitOutcome, DeviceTransaction, RollbackOutcome, RollbackRef, UnlockOutcome,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use tokio_util::sync::CancellationToken;

/// Hard cap on one serialized IPS-write envelope.
const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;

/// Fields SDC assigns itself and a write body must therefore not carry.
///
/// `uuid` is allocated by SDC on create and addressed through the path on
/// update. `import_id` is the signature-bundle identifier the spec documents as
/// "applicable only for predefined signatures imported from signature
/// bundles"; letting a caller set it would let a custom signature masquerade as
/// predefined, or a predefined one be re-created under its bundle identity.
const SERVER_ASSIGNED_FIELDS: &[&str] = &["uuid", "import_id"];

/// IPS families this server may create and update.
///
/// Converts into [`ResourceKind`] one way only, for the same reason
/// [`crate::WritableResource`] does: exposing a family for reading must never
/// make it writable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IpsWriteFamily {
    /// A custom IPS signature, signature group, or anomaly
    /// (`/api/v1/ips_signatures`).
    Signature,
    /// An IPS profile (`/api/v1/ips_profiles`).
    Profile,
    /// An IPS rule inside one IPS profile
    /// (`/api/v1/ips_profiles/{profile_uuid}/ips_rules`). This is how
    /// signatures are added to a profile: a profile body carries only `name`
    /// and `description`.
    Rule,
    /// An IPS exempt rule inside one IPS profile
    /// (`/api/v1/ips_profiles/{profile_uuid}/exempt_rules`). It exempts the
    /// referenced signatures from the profile's rules, so it has no `then`.
    ExemptRule,
}

impl IpsWriteFamily {
    /// Every writable IPS family, for exhaustive iteration in tests.
    pub const ALL: &'static [Self] =
        &[Self::Signature, Self::Profile, Self::Rule, Self::ExemptRule];

    /// The flat read family used for before-state and drift detection, or
    /// `None` for a rule or exempt rule, which is read through its parent
    /// profile.
    #[must_use]
    pub const fn resource_kind(self) -> Option<ResourceKind> {
        match self {
            Self::Signature => Some(ResourceKind::IpsSignatures),
            Self::Profile => Some(ResourceKind::IpsProfiles),
            Self::Rule | Self::ExemptRule => None,
        }
    }

    /// Whether this family lives under a parent IPS profile.
    #[must_use]
    pub const fn requires_profile(self) -> bool {
        matches!(self, Self::Rule | Self::ExemptRule)
    }

    /// Exact collection path segments. Flat families delegate to the read
    /// catalog, so a write and its drift-detection read can never address
    /// different paths; a rule's collection is the same one
    /// `list_sdc_ips_rules` reads, an exempt rule's the one
    /// `list_sdc_ips_exempt_rules` reads. `None` when the parent profile is
    /// missing for a rule or exempt rule, or supplied for a flat family.
    #[must_use]
    pub fn collection_segments(self, profile_uuid: Option<&str>) -> Option<Vec<&str>> {
        match (self.resource_kind(), profile_uuid) {
            (Some(kind), None) => Some(kind.collection_segments().to_vec()),
            (None, Some(profile)) => {
                let leaf = if self == Self::ExemptRule {
                    "exempt_rules"
                } else {
                    "ips_rules"
                };
                Some(vec!["api", "v1", "ips_profiles", profile, leaf])
            }
            (Some(_), Some(_)) | (None, None) => None,
        }
    }
}

/// Which mutation one IPS write performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IpsWriteAction {
    /// Create a new signature, profile, rule, or exempt rule.
    Create,
    /// Replace an existing signature, profile, rule, or exempt rule by UUID.
    Update,
    /// Remove an existing signature, profile, rule, or exempt rule by UUID.
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

    /// Whether this action addresses an existing object, so it needs a target
    /// UUID and an observed before-state.
    #[must_use]
    pub const fn targets_existing(self) -> bool {
        matches!(self, Self::Update | Self::Delete)
    }
}

/// Exact IPS write bound into a change-set action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdcPreparedIpsWrite {
    operation: String,
    action: IpsWriteAction,
    family: IpsWriteFamily,
    /// Parent profile of a rule. Absent (not `null`) for flat families, so a
    /// signature or profile envelope serializes exactly as before rules
    /// existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile_uuid: Option<String>,
    uuid: Option<String>,
    request: Value,
    before: Value,
    plan_digest: String,
}

impl SdcPreparedIpsWrite {
    /// Build a canonical, digest-bound signature or profile write.
    ///
    /// `before` is the target's observed state for update and delete, and
    /// `Value::Null` for create. `request` is `Value::Null` for delete. A rule
    /// needs its parent profile: use [`Self::new_rule`].
    ///
    /// # Errors
    ///
    /// Refuses shapes that do not match the action, bodies carrying
    /// server-assigned fields, updates to predefined signatures, invalid
    /// profile names, and oversized envelopes.
    pub fn new(
        action: IpsWriteAction,
        family: IpsWriteFamily,
        uuid: Option<String>,
        request: Value,
        before: Value,
    ) -> Result<Self, SdcError> {
        Self::build(action, family, None, uuid, request, before)
    }

    /// Build a canonical, digest-bound IPS rule write inside `profile_uuid`.
    ///
    /// # Errors
    ///
    /// Everything [`Self::new`] refuses, plus a rule body without at least one
    /// well-formed `ips_signature` reference or without a `then.action`.
    pub fn new_rule(
        action: IpsWriteAction,
        profile_uuid: String,
        uuid: Option<String>,
        request: Value,
        before: Value,
    ) -> Result<Self, SdcError> {
        Self::build(
            action,
            IpsWriteFamily::Rule,
            Some(profile_uuid),
            uuid,
            request,
            before,
        )
    }

    /// Build a canonical, digest-bound IPS exempt-rule write inside
    /// `profile_uuid`.
    ///
    /// # Errors
    ///
    /// Everything [`Self::new`] refuses, plus an exempt-rule body without at
    /// least one well-formed `ips_signature` reference or carrying a `then`.
    pub fn new_exempt_rule(
        action: IpsWriteAction,
        profile_uuid: String,
        uuid: Option<String>,
        request: Value,
        before: Value,
    ) -> Result<Self, SdcError> {
        Self::build(
            action,
            IpsWriteFamily::ExemptRule,
            Some(profile_uuid),
            uuid,
            request,
            before,
        )
    }

    fn build(
        action: IpsWriteAction,
        family: IpsWriteFamily,
        profile_uuid: Option<String>,
        uuid: Option<String>,
        request: Value,
        before: Value,
    ) -> Result<Self, SdcError> {
        let plan = plan_artifact(
            action,
            family,
            profile_uuid.as_deref(),
            uuid.as_deref(),
            &request,
            &before,
        );
        let prepared = Self {
            operation: "ips_write".to_owned(),
            action,
            family,
            profile_uuid,
            uuid,
            request,
            before,
            plan_digest: canonical_digest(&plan)
                .map_err(|error| SdcError::PreparedChange(error.to_string()))?,
        };
        prepared.validate()?;
        Ok(prepared)
    }

    /// Parent profile of a rule write, absent for flat families.
    #[must_use]
    pub fn profile_uuid(&self) -> Option<&str> {
        self.profile_uuid.as_deref()
    }

    /// Product operation discriminator.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Which mutation this write performs.
    #[must_use]
    pub const fn action(&self) -> IpsWriteAction {
        self.action
    }

    /// Which IPS family this write targets.
    #[must_use]
    pub const fn family(&self) -> IpsWriteFamily {
        self.family
    }

    /// Target UUID, absent for create.
    #[must_use]
    pub fn uuid(&self) -> Option<&str> {
        self.uuid.as_deref()
    }

    /// Exact request body, `Null` for delete.
    #[must_use]
    pub const fn request(&self) -> &Value {
        &self.request
    }

    /// Target state observed at prepare time, `Null` for create.
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
            self.family,
            self.profile_uuid.as_deref(),
            self.uuid.as_deref(),
            &self.request,
            &self.before,
        )
    }

    /// Revalidate shape, IPS guards, bounds, and digest integrity.
    ///
    /// Runs at prepare and again when the persisted envelope is staged for
    /// apply, so every guard here also holds against a tampered state file.
    ///
    /// # Errors
    ///
    /// Returns a stable error if the plan is not executable or was tampered.
    pub fn validate(&self) -> Result<(), SdcError> {
        if self.operation != "ips_write" {
            return Err(SdcError::PreparedChange(
                "prepared operation must be ips_write".to_owned(),
            ));
        }
        // Mirror the client's body rule so an unexecutable plan cannot be
        // approved; discovering it only at commit would burn a change set.
        let fields = self.request.as_object().filter(|fields| !fields.is_empty());
        if self.action == IpsWriteAction::Delete {
            if !self.request.is_null() {
                return Err(SdcError::PreparedChange(
                    "prepared ips_delete must not carry a body".to_owned(),
                ));
            }
        } else if fields.is_none() {
            return Err(SdcError::PreparedChange(format!(
                "prepared {} requires a non-empty JSON object body",
                self.action.as_str()
            )));
        }
        let shape_ok = match self.action {
            IpsWriteAction::Create => self.uuid.is_none() && self.before.is_null(),
            IpsWriteAction::Update | IpsWriteAction::Delete => {
                self.uuid.is_some() && self.before.is_object()
            }
        };
        if !shape_ok {
            return Err(SdcError::PreparedChange(format!(
                "prepared {} does not match its required shape",
                self.action.as_str()
            )));
        }
        if let Some(uuid) = self.uuid.as_deref()
            && !is_allowed_identifier(uuid)
        {
            return Err(SdcError::PreparedChange(
                "prepared IPS UUID must be 1-256 characters from [A-Za-z0-9_-:+=]".to_owned(),
            ));
        }
        match (self.family.requires_profile(), self.profile_uuid.as_deref()) {
            (true, Some(profile)) if is_allowed_identifier(profile) => {}
            (true, _) => {
                return Err(SdcError::PreparedChange(
                    "an IPS rule or exempt-rule write requires a profile_uuid of 1-256 characters from \
                     [A-Za-z0-9_-:+=]"
                        .to_owned(),
                ));
            }
            (false, Some(_)) => {
                return Err(SdcError::PreparedChange(
                    "profile_uuid applies only to IPS rule and exempt-rule writes".to_owned(),
                ));
            }
            (false, None) => {}
        }
        if let Some(fields) = fields {
            self.validate_body(fields)?;
        }
        if self.family == IpsWriteFamily::Signature && self.action.targets_existing() {
            let verb = if self.action == IpsWriteAction::Delete {
                "delete"
            } else {
                "update"
            };
            // Fail closed: changing an existing signature needs positive
            // evidence that it is custom, not merely the absence of a
            // predefined mark.
            if !self
                .before
                .get("signature_type")
                .and_then(Value::as_str)
                .is_some_and(is_known_signature_type)
            {
                return Err(SdcError::PreparedChange(format!(
                    "refusing to {verb} a signature whose observed signature_type is \
                     missing or unknown"
                )));
            }
            if is_predefined_signature(&self.before) {
                return Err(SdcError::PreparedChange(format!(
                    "refusing to {verb} a predefined signature imported from the \
                     signature bundle; only custom signatures are writable"
                )));
            }
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

    /// Guards on a create or update body.
    fn validate_body(&self, fields: &serde_json::Map<String, Value>) -> Result<(), SdcError> {
        if let Some(field) = SERVER_ASSIGNED_FIELDS
            .iter()
            .find(|field| fields.contains_key(**field))
        {
            return Err(SdcError::PreparedChange(format!(
                "IPS write body must not set the server-assigned field `{field}`"
            )));
        }
        // Both input schemas require `name`; requiring it on update too keeps a
        // PUT from silently blanking it, since SDC replaces the whole object.
        let Some(name) = fields.get("name").and_then(Value::as_str) else {
            return Err(SdcError::PreparedChange(
                "IPS write body requires a string `name`".to_owned(),
            ));
        };
        match self.family {
            IpsWriteFamily::Rule => validate_rule_body(fields)?,
            IpsWriteFamily::ExemptRule => validate_exempt_rule_body(fields)?,
            IpsWriteFamily::Profile if !is_valid_profile_name(name) => {
                return Err(SdcError::PreparedChange(
                    "IPS profile name must be 1-127 characters with no space, `#`, `&`, `;`, \
                     CR or LF"
                        .to_owned(),
                ));
            }
            IpsWriteFamily::Signature => {
                if let Some(kind) = fields.get("signature_type")
                    && !kind.as_str().is_some_and(is_known_signature_type)
                {
                    return Err(SdcError::PreparedChange(format!(
                        "IPS signature_type must be one of {}",
                        SIGNATURE_TYPES.join(", ")
                    )));
                }
            }
            IpsWriteFamily::Profile => {}
        }
        Ok(())
    }
}

/// `signature_type` values the vendored spec allows.
const SIGNATURE_TYPES: &[&str] = &["anomaly", "signature", "chain", "static", "dynamic"];

fn is_known_signature_type(kind: &str) -> bool {
    SIGNATURE_TYPES.contains(&kind)
}

/// Bundle-provenance fields from the vendored spec's own field docs:
/// `import_id` "applicable only for predefined signatures imported from
/// signature bundles", and `activation_date`, set when a bundle activates a
/// signature. `signature_type` is the detection kind, shared by both origins.
const PREDEFINED_MARKERS: &[&str] = &["import_id", "activation_date"];

/// Whether an observed signature came from Juniper's signature bundle.
///
/// Any non-empty provenance marker counts, whatever its JSON type. Confirmed
/// on a lab tenant (2026-10-15): sampled bundle signatures of the anomaly,
/// chain and dynamic types all carried `import_id`, and signatures created
/// through this path carried neither marker.
fn is_predefined_signature(before: &Value) -> bool {
    PREDEFINED_MARKERS
        .iter()
        .any(|marker| match before.get(*marker) {
            None | Some(Value::Null) => false,
            Some(Value::String(text)) => !text.trim().is_empty(),
            Some(_) => true,
        })
}

/// Strict path-segment allowlist for IPS identifiers: 1-256 characters from
/// `[A-Za-z0-9_-:+=]`. A `/`, `.` or `%` can never reach a request path.
fn is_allowed_identifier(identifier: &str) -> bool {
    (1..=256).contains(&identifier.len())
        && identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-:+=".contains(&byte))
}

/// The UUID SDC allocated, read from a create response.
///
/// The spec documents both creates as returning the new object (`IpsSignature`
/// / `IpsProfile`, which carry `uuid`). A missing, empty, or non-string `uuid`
/// yields `None` rather than an error, because the write itself succeeded.
fn created_uuid_from(response: &Value) -> Option<String> {
    response
        .get("uuid")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|uuid| !uuid.is_empty())
        .map(str::to_owned)
}

/// The spec's `IpsProfileInput.name` format: `^[^#&;\r\n ]{1,127}$`.
fn is_valid_profile_name(name: &str) -> bool {
    let length = name.chars().count();
    (1..=127).contains(&length) && !name.contains(['#', '&', ';', '\r', '\n', ' '])
}

fn plan_artifact(
    action: IpsWriteAction,
    family: IpsWriteFamily,
    profile_uuid: Option<&str>,
    uuid: Option<&str>,
    request: &Value,
    before: &Value,
) -> Value {
    let mut plan = json!({
        "action": action,
        "family": family,
        "uuid": uuid,
        "before": before,
        "after": request,
    });
    // Bound into the digest for rules only, so the plan (and digest) of a
    // signature or profile write is byte-identical to before rules existed.
    if let (Some(profile), Value::Object(map)) = (profile_uuid, &mut plan) {
        map.insert("profile_uuid".to_owned(), Value::String(profile.to_owned()));
    }
    plan
}

/// Upper bound on signatures referenced by one rule.
const MAX_RULE_SIGNATURES: usize = 256;

/// Shared by rules and exempt rules: 1-256 `ips_signature` references, each
/// with a well-formed `uuid`. `what` names the family in the refusal.
fn validate_signature_references(
    fields: &serde_json::Map<String, Value>,
    what: &str,
) -> Result<(), SdcError> {
    let refused = |reason: String| Err(SdcError::PreparedChange(reason));
    let Some(Value::Array(references)) = fields.get("ips_signature") else {
        return refused(format!("an {what} body requires an `ips_signature` array"));
    };
    if references.is_empty() || references.len() > MAX_RULE_SIGNATURES {
        return refused(format!(
            "an {what} must reference 1-256 signatures in `ips_signature`"
        ));
    }
    for reference in references {
        if !reference
            .get("uuid")
            .and_then(Value::as_str)
            .is_some_and(is_allowed_identifier)
        {
            return refused(
                "every `ips_signature` entry needs a `uuid` of 1-256 characters from \
                 [A-Za-z0-9_-:+=]"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

/// A rule body must reference at least one signature by a well-formed UUID
/// and carry a `then.action`. `IPSRuleInput` requires `name`, `ips_signature`
/// and `then`; the spec leaves `then` fields unconstrained, so only `action`
/// is required here, as SDC's own rules always carry one.
fn validate_rule_body(fields: &serde_json::Map<String, Value>) -> Result<(), SdcError> {
    validate_signature_references(fields, "IPS rule")?;
    if !fields
        .get("then")
        .and_then(|then| then.get("action"))
        .and_then(Value::as_str)
        .is_some_and(|action| !action.trim().is_empty())
    {
        return Err(SdcError::PreparedChange(
            "an IPS rule body requires `then.action`".to_owned(),
        ));
    }
    Ok(())
}

/// An exempt-rule body references signatures like a rule but takes no `then`:
/// the action is "exempt", so a `then` is refused rather than silently sent.
fn validate_exempt_rule_body(fields: &serde_json::Map<String, Value>) -> Result<(), SdcError> {
    validate_signature_references(fields, "IPS exempt rule")?;
    if fields.contains_key("then") {
        return Err(SdcError::PreparedChange(
            "an IPS exempt rule body must not carry `then`".to_owned(),
        ));
    }
    Ok(())
}

/// Signature UUIDs a rule body references, in order.
#[must_use]
pub fn rule_signature_uuids(request: &Value) -> Vec<String> {
    request
        .get("ips_signature")
        .and_then(Value::as_array)
        .map(|references| {
            references
                .iter()
                .filter_map(|reference| reference.get("uuid").and_then(Value::as_str))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Upper bound on SDC reads one reference scan may issue.
///
/// A scan that cannot finish inside this budget has not shown the target is
/// unreferenced, so it refuses the delete instead of reporting a partial pass.
const MAX_REFERENCE_SCAN_REQUESTS: usize = 500;

/// How many referrers a refusal names; the total is always reported.
const MAX_REPORTED_REFERENCES: usize = 20;

/// Read budget shared by every request of one reference scan.
struct ScanBudget {
    remaining: usize,
}

impl ScanBudget {
    const fn new() -> Self {
        Self {
            remaining: MAX_REFERENCE_SCAN_REQUESTS,
        }
    }

    fn spend(&mut self) -> Result<(), SdcError> {
        let Some(remaining) = self.remaining.checked_sub(1) else {
            return Err(SdcError::PreparedChange(format!(
                "the reference check needed more than {MAX_REFERENCE_SCAN_REQUESTS} SDC reads; \
                 refusing the delete because the target could not be shown unreferenced"
            )));
        };
        self.remaining = remaining;
        Ok(())
    }
}

/// Refusal for a reference scan that could not read a collection completely.
fn partial_scan(reason: &str) -> SdcError {
    SdcError::PreparedChange(format!(
        "the reference check could not read a collection completely ({reason}); \
         refusing the delete because the target could not be shown unreferenced"
    ))
}

/// Every item of one paged collection, read at the client's maximum page size.
///
/// Stops at the first short page, then checks the items read against the
/// response's `count` (a number or numeric string, as the spec types it both
/// ways). A scan that read fewer items than `count`, a `count` it cannot
/// parse, a missing `items` beside a non-zero `count`, or an `items` that is
/// not an array is refused: a scan must not pass on a partial or unreadable
/// response. When `count` is absent a short page is taken as the end.
async fn collect_items<F, Fut>(
    client: &SdcClient,
    budget: &mut ScanBudget,
    mut fetch: F,
) -> Result<Vec<Value>, SdcError>
where
    F: FnMut(ListRequest) -> Fut,
    Fut: Future<Output = Result<Value, SdcError>>,
{
    let size = client.max_page_size();
    let mut from = 0_u64;
    let mut items = Vec::new();
    loop {
        budget.spend()?;
        let response = fetch(ListRequest::new(from, size, size)?).await?;
        let count = match response.get("count") {
            None | Some(Value::Null) => None,
            Some(Value::Number(n)) => n.as_u64(),
            Some(Value::String(s)) => s.trim().parse::<u64>().ok(),
            Some(_) => None,
        };
        if response.get("count").is_some_and(|c| !c.is_null()) && count.is_none() {
            return Err(partial_scan("a list response's `count` was not a number"));
        }
        let page = match response.get("items") {
            None | Some(Value::Null) if count.is_some_and(|c| c > 0) => {
                return Err(partial_scan(
                    "a list response carried a count but no `items`",
                ));
            }
            None | Some(Value::Null) => &[][..],
            Some(Value::Array(page)) => page.as_slice(),
            Some(_) => {
                return Err(SdcError::PreparedChange(
                    "the reference check could not read a list response's `items`".to_owned(),
                ));
            }
        };
        items.extend(page.iter().cloned());
        if page.len() < usize::try_from(size).unwrap_or(usize::MAX) {
            if count.is_some_and(|c| u64::try_from(items.len()).unwrap_or(u64::MAX) < c) {
                return Err(partial_scan(
                    "a list response ended before the reported `count` was read",
                ));
            }
            return Ok(items);
        }
        from += u64::from(size);
    }
}

/// Whether `holder.ips_profile.uuid` names `profile_uuid`.
fn names_profile(holder: Option<&Value>, profile_uuid: &str) -> bool {
    holder
        .and_then(|holder| holder.get("ips_profile"))
        .and_then(|reference| reference.get("uuid"))
        .and_then(Value::as_str)
        == Some(profile_uuid)
}

/// UUID of a listed item, or a placeholder when SDC omitted it.
fn item_uuid(item: &Value) -> &str {
    item.get("uuid").and_then(Value::as_str).unwrap_or("?")
}

/// Refuse a delete when anything still references its target.
fn refuse_if_referenced(target: &str, referrers: &[String]) -> Result<(), SdcError> {
    if referrers.is_empty() {
        return Ok(());
    }
    let shown = referrers
        .iter()
        .take(MAX_REPORTED_REFERENCES)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let more = referrers.len().saturating_sub(MAX_REPORTED_REFERENCES);
    let more = if more > 0 {
        format!(" and {more} more")
    } else {
        String::new()
    };
    Err(SdcError::PreparedChange(format!(
        "refusing to delete {target}: still referenced by {} object(s): {shown}{more}",
        referrers.len()
    )))
}

/// Everything that still references one IPS profile.
///
/// Checks every firewall policy's global and zone rules
/// (`advanced_security.ips_profile`), the tenant's firewall global settings
/// and global profile, and every device's firewall global settings. A rule
/// that inherits its profile carries no UUID, so it is covered by the global
/// setting it inherits from. Bounded at 500 SDC reads.
///
/// # Errors
///
/// Returns an error when any read fails or the scan exceeds its budget; the
/// delete is then refused rather than planned on an incomplete check.
pub async fn find_profile_references(
    client: &SdcClient,
    profile_uuid: &str,
    cancellation: &CancellationToken,
) -> Result<Vec<String>, SdcError> {
    let mut budget = ScanBudget::new();
    let mut referrers = Vec::new();
    for (label, singleton) in [
        (
            "firewall global settings",
            client.get_firewall_global_settings(cancellation).await?,
        ),
        (
            "firewall global profile",
            client.get_firewall_global_profile(cancellation).await?,
        ),
    ] {
        budget.spend()?;
        if names_profile(Some(&singleton), profile_uuid) {
            referrers.push(label.to_owned());
        }
    }
    for device in collect_items(client, &mut budget, move |page| {
        client.list_device_global_settings(None, page, cancellation)
    })
    .await?
    {
        if names_profile(Some(&device), profile_uuid) {
            let id = device
                .get("device_id")
                .and_then(Value::as_str)
                .unwrap_or_else(|| item_uuid(&device));
            referrers.push(format!("device global settings {id}"));
        }
    }
    let policies = collect_items(client, &mut budget, move |page| {
        client.list_firewall_policies(page, cancellation)
    })
    .await?;
    for policy in &policies {
        let policy_uuid = item_uuid(policy);
        for scope in ["global", "zone"] {
            for rule in collect_items(client, &mut budget, move |page| {
                client.list_firewall_rules(policy_uuid, scope, page, cancellation)
            })
            .await?
            {
                if names_profile(rule.get("advanced_security"), profile_uuid) {
                    referrers.push(format!(
                        "firewall rule {policy_uuid}/{scope}/{}",
                        item_uuid(&rule)
                    ));
                }
            }
        }
    }
    Ok(referrers)
}

/// Every IPS rule and exempt rule, in any profile, that still references one
/// signature through `ips_signature[].uuid`.
///
/// Signature-group membership is not scanned: finding it means reading every
/// signature in the tenant (tens of thousands with the predefined bundle), so
/// SDC's own `409` remains the backstop there. Bounded by
/// 500 SDC reads.
///
/// # Errors
///
/// Returns an error when any read fails or the scan exceeds its budget.
pub async fn find_signature_references(
    client: &SdcClient,
    signature_uuid: &str,
    cancellation: &CancellationToken,
) -> Result<Vec<String>, SdcError> {
    let mut budget = ScanBudget::new();
    let mut referrers = Vec::new();
    let profiles = collect_items(client, &mut budget, move |page| {
        client.list_resource(ResourceKind::IpsProfiles, page, &[], cancellation)
    })
    .await?;
    for profile in &profiles {
        let profile_uuid = item_uuid(profile);
        let rules = collect_items(client, &mut budget, move |page| {
            client.list_ips_rules(profile_uuid, page, cancellation)
        })
        .await?;
        let exempt = collect_items(client, &mut budget, move |page| {
            client.list_ips_exempt_rules(profile_uuid, page, cancellation)
        })
        .await?;
        for (kind, items) in [("IPS rule", rules), ("IPS exempt rule", exempt)] {
            for rule in items {
                if rule_signature_uuids(&rule)
                    .iter()
                    .any(|uuid| uuid == signature_uuid)
                {
                    referrers.push(format!("{kind} {profile_uuid}/{}", item_uuid(&rule)));
                }
            }
        }
    }
    Ok(referrers)
}

/// Refuse deleting a profile or signature that is still referenced.
///
/// Rules and exempt rules are leaves, so a rule delete needs no scan.
///
/// # Errors
///
/// Returns an error naming the referrers, or when the scan cannot complete.
pub async fn ensure_unreferenced(
    client: &SdcClient,
    family: IpsWriteFamily,
    uuid: &str,
    cancellation: &CancellationToken,
) -> Result<(), SdcError> {
    match family {
        IpsWriteFamily::Profile => refuse_if_referenced(
            &format!("IPS profile {uuid}"),
            &find_profile_references(client, uuid, cancellation).await?,
        ),
        IpsWriteFamily::Signature => refuse_if_referenced(
            &format!("IPS signature {uuid}"),
            &find_signature_references(client, uuid, cancellation).await?,
        ),
        IpsWriteFamily::Rule | IpsWriteFamily::ExemptRule => Ok(()),
    }
}

/// Outcome of revalidating an IPS write immediately before commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsValidationReport {
    /// Whether the envelope is intact and the target has not drifted.
    pub valid: bool,
    /// Which mutation was validated.
    pub action: IpsWriteAction,
    /// Which IPS family was validated.
    pub family: IpsWriteFamily,
    /// Whether the live target still matched its prepared `before` state.
    pub target_unchanged: bool,
}

/// Result of planning one IPS write.
#[derive(Debug, Clone, Serialize)]
pub struct IpsPrepareResult {
    /// Shared two-person change-set record.
    pub change_set: mecmcp_changeset::ChangeSetOutput,
    /// Exact IPS write bound by the plan digest.
    pub prepared_change: SdcPreparedIpsWrite,
}

/// Result of applying one approved IPS write.
#[derive(Debug, Clone, Serialize)]
pub struct IpsApplyResult {
    /// Shared operation identifier.
    pub operation_id: String,
    /// Before/after plan used as the management-plane diff.
    pub plan: Value,
    /// Drift and envelope validation result.
    pub validation: IpsValidationReport,
    /// Known, detached, or indeterminate commit disposition.
    pub outcome: CommitOutcome,
    /// UUID SDC allocated for a successful create, so a follow-up update can
    /// address it without searching the collection. `None` for update and
    /// delete, and for a create whose response carried no UUID.
    pub created_uuid: Option<String>,
}

/// SDC implementation of the shared transaction contract for IPS writes.
#[derive(Clone)]
pub struct SdcIpsTransaction {
    client: SdcClient,
    expected_plan_digest: String,
    cancellation: CancellationToken,
    refused_before_write: Arc<AtomicBool>,
    created_uuid: Arc<OnceLock<String>>,
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
            created_uuid: Arc::new(OnceLock::new()),
        }
    }

    /// Whether commit refused before issuing any request to SDC.
    ///
    /// Distinguishes "nothing was written, safe to discard" from "the write
    /// may have landed", which the coordinator's flattened error cannot.
    #[must_use]
    pub fn refused_before_write(&self) -> bool {
        self.refused_before_write.load(Ordering::SeqCst)
    }

    /// UUID SDC returned for a successful create, if any.
    ///
    /// The coordinator's [`CommitOutcome`] has no slot for it, so the
    /// transaction keeps it for the caller to report.
    #[must_use]
    pub fn created_uuid(&self) -> Option<String> {
        self.created_uuid.get().cloned()
    }

    /// Re-read the target and report whether it still matches its plan.
    ///
    /// Create has no prior object, so it is vacuously unchanged.
    async fn target_unchanged(&self, staged: &SdcPreparedIpsWrite) -> Result<bool, SdcError> {
        let Some(uuid) = staged.uuid().filter(|_| staged.action().targets_existing()) else {
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

    /// Sole validation point for the persisted envelope.
    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let [prepared] = actions else {
            return Err(SdcError::InvalidInput(
                "an SDC IPS write requires exactly one prepared change",
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

    /// Refuse the write if the target moved since it was prepared.
    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        let target_unchanged = self.target_unchanged(staged).await?;
        if !target_unchanged {
            return Err(SdcError::TargetDrifted);
        }
        Ok(IpsValidationReport {
            valid: true,
            action: staged.action(),
            family: staged.family(),
            target_unchanged,
        })
    }

    async fn commit(
        &self,
        staged: &Self::Staged,
        _attribution: &Attribution,
        options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        // Every exit until the request is issued is a pre-write refusal, so the
        // caller may discard instead of leaving a record that blocks the tenant.
        self.refused_before_write.store(true, Ordering::SeqCst);
        if options.confirm_timeout.is_some() {
            return Err(SdcError::InvalidInput(
                "SDC does not support confirmed IPS writes",
            ));
        }
        // Re-check drift immediately before writing: the coordinator releases
        // its guard between validate and commit, and that guard cannot exclude
        // a writer working directly against SDC. SDC has no conditional write,
        // so this narrows the window rather than closing it.
        if !self.target_unchanged(staged).await? {
            return Err(SdcError::TargetDrifted);
        }
        let family = staged.family();
        // From here the outcome is no longer knowably clean.
        self.refused_before_write.store(false, Ordering::SeqCst);
        let result = match (staged.action(), staged.uuid()) {
            (IpsWriteAction::Create, _) => {
                self.client
                    .create_ips_object(
                        family,
                        staged.profile_uuid(),
                        staged.request(),
                        &self.cancellation,
                    )
                    .await
            }
            (IpsWriteAction::Update, Some(uuid)) => {
                self.client
                    .update_ips_object(
                        family,
                        staged.profile_uuid(),
                        uuid,
                        staged.request(),
                        &self.cancellation,
                    )
                    .await
            }
            (IpsWriteAction::Delete, Some(uuid)) => {
                self.client
                    .delete_ips_object(family, staged.profile_uuid(), uuid, &self.cancellation)
                    .await
            }
            (IpsWriteAction::Update | IpsWriteAction::Delete, None) => {
                self.refused_before_write.store(true, Ordering::SeqCst);
                return Err(SdcError::PreparedChange(format!(
                    "prepared {} is missing its target UUID",
                    staged.action().as_str()
                )));
            }
        };
        match result {
            Ok(response) => {
                let created = (staged.action() == IpsWriteAction::Create)
                    .then(|| created_uuid_from(&response))
                    .flatten();
                let identity = match &created {
                    Some(uuid) => {
                        // Set once per transaction; a second commit cannot occur.
                        let _ = self.created_uuid.set(uuid.clone());
                        format!(" as {uuid}")
                    }
                    None => String::new(),
                };
                Ok(CommitOutcome::Reconciled {
                    succeeded: true,
                    job_id: None,
                    details: Some(format!(
                        "SDC {} completed{identity}; nothing reaches a device until a policy using it is deployed",
                        staged.action().as_str()
                    )),
                })
            }
            Err(SdcError::Cancelled | SdcError::Timeout | SdcError::MutationOutcomeUnknown) => {
                Ok(CommitOutcome::Indeterminate {
                    reason: "SDC IPS write was submitted but its outcome was not observed"
                        .to_owned(),
                })
            }
            Err(error) => {
                if error.is_definitive_rejection() {
                    self.refused_before_write.store(true, Ordering::SeqCst);
                }
                Err(error)
            }
        }
    }

    /// Release a planned-but-uncommitted IPS write.
    ///
    /// SDC has no candidate store and the coordinator only reaches `rollback`
    /// from pre-commit states, so nothing was written.
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
    use super::{
        IpsWriteAction, IpsWriteFamily, SdcPreparedIpsWrite, created_uuid_from,
        is_valid_profile_name, refuse_if_referenced,
    };
    use crate::ResourceKind;
    use serde_json::{Value, json};

    fn custom_signature() -> Value {
        json!({
            "uuid": "sig-1",
            "name": "CUSTOM-SQL-TIME-BASED",
            "signature_type": "signature",
            "severity": "major",
            "direction": "client-to-server"
        })
    }

    #[test]
    fn ips_families_read_and_write_the_same_collections() {
        for family in [IpsWriteFamily::Signature, IpsWriteFamily::Profile] {
            let kind = family.resource_kind().expect("flat family");
            assert_eq!(
                family.collection_segments(None),
                Some(kind.collection_segments().to_vec())
            );
            assert_eq!(family.collection_segments(Some("p-1")), None);
        }
        assert_eq!(
            IpsWriteFamily::Signature.resource_kind(),
            Some(ResourceKind::IpsSignatures)
        );
        assert_eq!(
            IpsWriteFamily::Profile.resource_kind(),
            Some(ResourceKind::IpsProfiles)
        );
        // A rule's collection is the one list_sdc_ips_rules reads.
        assert_eq!(IpsWriteFamily::Rule.resource_kind(), None);
        assert_eq!(IpsWriteFamily::Rule.collection_segments(None), None);
        assert_eq!(
            IpsWriteFamily::Rule.collection_segments(Some("p-1")),
            Some(vec!["api", "v1", "ips_profiles", "p-1", "ips_rules"])
        );
        assert_eq!(json!(IpsWriteFamily::Rule), json!("rule"));
        // An exempt rule's collection is the one list_sdc_ips_exempt_rules reads.
        assert_eq!(IpsWriteFamily::ExemptRule.resource_kind(), None);
        assert!(IpsWriteFamily::ExemptRule.requires_profile());
        assert_eq!(IpsWriteFamily::ExemptRule.collection_segments(None), None);
        assert_eq!(
            IpsWriteFamily::ExemptRule.collection_segments(Some("p-1")),
            Some(vec!["api", "v1", "ips_profiles", "p-1", "exempt_rules"])
        );
        assert_eq!(json!(IpsWriteFamily::ExemptRule), json!("exempt_rule"));
    }

    fn exempt_rule_body() -> Value {
        json!({
            "name": "CUSTOM-EXEMPT",
            "ips_signature": [
                { "uuid": "8ad65be9-3307-4763-b21e-5cf15b3f4653", "name": "CUSTOM-A" }
            ]
        })
    }

    /// Adding a family must not move the digest of an existing envelope.
    #[test]
    fn signature_and_rule_digests_are_pinned() {
        let signature = SdcPreparedIpsWrite::new(
            IpsWriteAction::Create,
            IpsWriteFamily::Signature,
            None,
            json!({ "name": "CUSTOM-X" }),
            Value::Null,
        )
        .expect("signature");
        let rule = SdcPreparedIpsWrite::new_rule(
            IpsWriteAction::Create,
            "p-1".to_owned(),
            None,
            rule_body(),
            Value::Null,
        )
        .expect("rule");
        assert_eq!(
            signature.plan_digest(),
            "sha256:126c123405f600cdab025deae326b157ff7ebe5b82e8a94f2185188d1b04d932"
        );
        assert_eq!(
            rule.plan_digest(),
            "sha256:d985a0501640fd458589187a981881f8503a1cea46275d41458539b0641ea43e"
        );
    }

    #[test]
    fn an_exempt_rule_body_needs_signatures_and_refuses_then() {
        let build = |body: Value| {
            SdcPreparedIpsWrite::new_exempt_rule(
                IpsWriteAction::Create,
                "p-1".to_owned(),
                None,
                body,
                Value::Null,
            )
        };
        let created = build(exempt_rule_body()).expect("valid exempt rule");
        assert_eq!(created.family(), IpsWriteFamily::ExemptRule);
        assert_eq!(created.profile_uuid(), Some("p-1"));

        let mut missing = exempt_rule_body();
        missing
            .as_object_mut()
            .expect("object")
            .remove("ips_signature");
        assert!(build(missing).is_err());
        for references in [
            json!([]),
            json!([{ "name": "no uuid" }]),
            json!([{ "uuid": "../escape" }]),
        ] {
            let mut body = exempt_rule_body();
            body["ips_signature"] = references.clone();
            assert!(build(body).is_err(), "{references} accepted");
        }
        let mut with_then = exempt_rule_body();
        with_then["then"] = json!({ "action": "no-action" });
        let error = build(with_then).expect_err("then is refused");
        assert!(error.to_string().contains("must not carry `then`"));
        // A rule body is not an exempt-rule body, and vice versa.
        assert!(build(rule_body()).is_err());
        assert!(
            SdcPreparedIpsWrite::new_rule(
                IpsWriteAction::Create,
                "p-1".to_owned(),
                None,
                exempt_rule_body(),
                Value::Null,
            )
            .is_err()
        );
        // Needs its profile, like a rule.
        assert!(
            SdcPreparedIpsWrite::new(
                IpsWriteAction::Create,
                IpsWriteFamily::ExemptRule,
                None,
                exempt_rule_body(),
                Value::Null,
            )
            .is_err()
        );
    }

    fn rule_body() -> Value {
        json!({
            "name": "CLAUDE-TEST-266-RULE",
            "ips_signature": [
                { "uuid": "8ad65be9-3307-4763-b21e-5cf15b3f4653", "name": "CLAUDE-TEST-266-SIG" },
                { "uuid": "16955805-a9cd-4a5d-8d77-c6e5b03d558c", "name": "CLAUDE-TEST-266B-SIG" }
            ],
            "then": { "action": "no-action", "log_attacks": true },
            "position": 0
        })
    }

    #[test]
    fn a_rule_create_is_bound_to_its_profile() {
        let rule = SdcPreparedIpsWrite::new_rule(
            IpsWriteAction::Create,
            "ffc405a7-ef24-4a10-a6cb-0f8d4dfabfcc".to_owned(),
            None,
            rule_body(),
            Value::Null,
        )
        .expect("rule create");
        assert_eq!(rule.family(), IpsWriteFamily::Rule);
        assert_eq!(
            rule.profile_uuid(),
            Some("ffc405a7-ef24-4a10-a6cb-0f8d4dfabfcc")
        );
        assert_eq!(
            rule.plan()["profile_uuid"],
            "ffc405a7-ef24-4a10-a6cb-0f8d4dfabfcc"
        );
        assert_eq!(
            super::rule_signature_uuids(rule.request()),
            vec![
                "8ad65be9-3307-4763-b21e-5cf15b3f4653".to_owned(),
                "16955805-a9cd-4a5d-8d77-c6e5b03d558c".to_owned()
            ]
        );

        // The same rule in another profile is a different plan.
        let elsewhere = SdcPreparedIpsWrite::new_rule(
            IpsWriteAction::Create,
            "other-profile".to_owned(),
            None,
            rule_body(),
            Value::Null,
        )
        .expect("rule create");
        assert_ne!(rule.plan_digest(), elsewhere.plan_digest());

        // Moving a persisted rule to another profile breaks the digest.
        let mut stored = serde_json::to_value(&rule).expect("serialize");
        stored["profile_uuid"] = json!("other-profile");
        let moved: SdcPreparedIpsWrite = serde_json::from_value(stored).expect("deserialize");
        assert!(moved.validate().is_err());
    }

    #[test]
    fn flat_families_carry_no_profile_and_keep_their_plan_shape() {
        let signature = SdcPreparedIpsWrite::new(
            IpsWriteAction::Create,
            IpsWriteFamily::Signature,
            None,
            json!({ "name": "CUSTOM-X" }),
            Value::Null,
        )
        .expect("signature");
        assert!(signature.plan().get("profile_uuid").is_none());
        assert!(
            serde_json::to_value(&signature)
                .expect("serialize")
                .get("profile_uuid")
                .is_none(),
            "a signature envelope must serialize exactly as before rules existed"
        );
        // A rule cannot be built without its profile.
        assert!(
            SdcPreparedIpsWrite::new(
                IpsWriteAction::Create,
                IpsWriteFamily::Rule,
                None,
                rule_body(),
                Value::Null,
            )
            .is_err()
        );
        // A persisted signature envelope with a profile attached is refused.
        let mut stored = serde_json::to_value(&signature).expect("serialize");
        stored["profile_uuid"] = json!("p-1");
        let tampered: SdcPreparedIpsWrite = serde_json::from_value(stored).expect("deserialize");
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn a_rule_body_needs_signatures_and_an_action() {
        let refused = |body: Value| {
            SdcPreparedIpsWrite::new_rule(
                IpsWriteAction::Create,
                "p-1".to_owned(),
                None,
                body,
                Value::Null,
            )
            .is_err()
        };
        let without = |key: &str| {
            let mut body = rule_body();
            body.as_object_mut().expect("object").remove(key);
            body
        };
        assert!(refused(without("ips_signature")));
        assert!(refused(without("then")));
        for references in [
            json!([]),
            json!("8ad65be9"),
            json!([{ "name": "no uuid" }]),
            json!([{ "uuid": "../escape" }]),
            json!([{ "uuid": 42 }]),
        ] {
            let mut body = rule_body();
            body["ips_signature"] = references.clone();
            assert!(refused(body), "{references} accepted");
        }
        for then in [json!({}), json!({ "action": "" }), json!({ "action": 1 })] {
            let mut body = rule_body();
            body["then"] = then.clone();
            assert!(refused(body), "{then} accepted");
        }
        let mut body = rule_body();
        body["ips_signature"] = Value::Array(
            (0..257)
                .map(|index| json!({ "uuid": format!("sig-{index}") }))
                .collect(),
        );
        assert!(refused(body), "257 references accepted");
        assert!(
            SdcPreparedIpsWrite::new_rule(
                IpsWriteAction::Create,
                "../p".to_owned(),
                None,
                rule_body(),
                Value::Null,
            )
            .is_err(),
            "the parent profile is held to the identifier allowlist"
        );
    }

    #[test]
    fn a_custom_signature_create_and_update_are_accepted() {
        let created = SdcPreparedIpsWrite::new(
            IpsWriteAction::Create,
            IpsWriteFamily::Signature,
            None,
            json!({ "name": "CUSTOM-X", "signature_type": "signature" }),
            Value::Null,
        )
        .expect("custom create");
        assert_eq!(created.operation(), "ips_write");
        assert!(created.plan_digest().starts_with("sha256:"));

        SdcPreparedIpsWrite::new(
            IpsWriteAction::Update,
            IpsWriteFamily::Signature,
            Some("sig-1".to_owned()),
            json!({ "name": "CUSTOM-SQL-TIME-BASED", "severity": "critical" }),
            custom_signature(),
        )
        .expect("custom update");
    }

    #[test]
    fn a_predefined_signature_is_never_updated() {
        let mut predefined = custom_signature();
        predefined["import_id"] = json!("HTTP:SQL:INJ:COMMENT");
        let error = SdcPreparedIpsWrite::new(
            IpsWriteAction::Update,
            IpsWriteFamily::Signature,
            Some("sig-1".to_owned()),
            json!({ "name": "HTTP:SQL:INJ:COMMENT", "severity": "info" }),
            predefined,
        )
        .expect_err("predefined update must be refused");
        assert!(error.to_string().contains("predefined"));
    }

    #[test]
    fn an_activation_date_also_marks_a_signature_predefined() {
        for marker in [
            json!("2026-09-01T00:00:00Z"),
            json!(1_756_684_800),
            json!(true),
        ] {
            let mut bundled = custom_signature();
            bundled["activation_date"] = marker.clone();
            assert!(
                SdcPreparedIpsWrite::new(
                    IpsWriteAction::Update,
                    IpsWriteFamily::Signature,
                    Some("sig-1".to_owned()),
                    json!({ "name": "CUSTOM-SQL-TIME-BASED" }),
                    bundled,
                )
                .is_err(),
                "activation_date {marker} must mark the signature predefined"
            );
        }
    }

    #[test]
    fn an_update_needs_a_known_observed_signature_type() {
        for observed in [Value::Null, json!("custom"), json!(""), json!(7)] {
            let mut before = custom_signature();
            if observed.is_null() {
                before
                    .as_object_mut()
                    .expect("object")
                    .remove("signature_type");
            } else {
                before["signature_type"] = observed.clone();
            }
            let error = SdcPreparedIpsWrite::new(
                IpsWriteAction::Update,
                IpsWriteFamily::Signature,
                Some("sig-1".to_owned()),
                json!({ "name": "CUSTOM-SQL-TIME-BASED" }),
                before,
            )
            .expect_err("unknown observed type must fail closed");
            assert!(
                error.to_string().contains("signature_type"),
                "{observed}: {error}"
            );
        }
    }

    #[test]
    fn a_body_signature_type_must_be_one_the_spec_allows() {
        for kind in ["anomaly", "signature", "chain", "static", "dynamic"] {
            SdcPreparedIpsWrite::new(
                IpsWriteAction::Create,
                IpsWriteFamily::Signature,
                None,
                json!({ "name": "CUSTOM-X", "signature_type": kind }),
                Value::Null,
            )
            .expect("spec value accepted");
        }
        for kind in [json!("custom"), json!("Signature"), json!(1)] {
            assert!(
                SdcPreparedIpsWrite::new(
                    IpsWriteAction::Create,
                    IpsWriteFamily::Signature,
                    None,
                    json!({ "name": "CUSTOM-X", "signature_type": kind }),
                    Value::Null,
                )
                .is_err(),
                "{kind} accepted"
            );
        }
    }

    #[test]
    fn identifiers_are_held_to_a_strict_allowlist() {
        assert!(super::is_allowed_identifier(
            "8ad65be9-3307-4763-b21e-5cf15b3f4653"
        ));
        assert!(super::is_allowed_identifier("abc_DEF:1+2="));
        for bad in [
            "", "../sig", "sig/1", "sig%2F1", "sig.1", "sig 1", "sig\n1", "sigé",
        ] {
            assert!(!super::is_allowed_identifier(bad), "{bad:?} accepted");
        }
        assert!(!super::is_allowed_identifier(&"a".repeat(257)));
        assert!(
            SdcPreparedIpsWrite::new(
                IpsWriteAction::Update,
                IpsWriteFamily::Profile,
                Some("p/../1".to_owned()),
                json!({ "name": "P" }),
                json!({ "uuid": "p", "name": "P" }),
            )
            .is_err()
        );
    }

    #[test]
    fn an_empty_import_id_does_not_mark_a_signature_predefined() {
        let mut custom = custom_signature();
        custom["import_id"] = json!("  ");
        SdcPreparedIpsWrite::new(
            IpsWriteAction::Update,
            IpsWriteFamily::Signature,
            Some("sig-1".to_owned()),
            json!({ "name": "CUSTOM-SQL-TIME-BASED" }),
            custom,
        )
        .expect("blank import_id is custom");
    }

    #[test]
    fn a_body_cannot_set_server_assigned_fields() {
        for field in ["uuid", "import_id"] {
            let mut body = json!({ "name": "CUSTOM-X" });
            body[field] = json!("forged");
            let error = SdcPreparedIpsWrite::new(
                IpsWriteAction::Create,
                IpsWriteFamily::Signature,
                None,
                body,
                Value::Null,
            )
            .expect_err("server-assigned field must be refused");
            assert!(error.to_string().contains(field), "{error}");
        }
    }

    #[test]
    fn a_write_must_match_the_shape_of_its_action() {
        // Create with a UUID.
        assert!(
            SdcPreparedIpsWrite::new(
                IpsWriteAction::Create,
                IpsWriteFamily::Profile,
                Some("p-1".to_owned()),
                json!({ "name": "P" }),
                Value::Null,
            )
            .is_err()
        );
        // Update without a UUID.
        assert!(
            SdcPreparedIpsWrite::new(
                IpsWriteAction::Update,
                IpsWriteFamily::Profile,
                None,
                json!({ "name": "P" }),
                json!({ "uuid": "p-1", "name": "P" }),
            )
            .is_err()
        );
        // Update without observed before-state.
        assert!(
            SdcPreparedIpsWrite::new(
                IpsWriteAction::Update,
                IpsWriteFamily::Profile,
                Some("p-1".to_owned()),
                json!({ "name": "P" }),
                Value::Null,
            )
            .is_err()
        );
        // Empty or non-object bodies, and a missing name.
        for body in [
            json!({}),
            json!([]),
            json!("P"),
            json!({ "description": "x" }),
        ] {
            assert!(
                SdcPreparedIpsWrite::new(
                    IpsWriteAction::Create,
                    IpsWriteFamily::Profile,
                    None,
                    body,
                    Value::Null,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn a_delete_carries_no_body_and_binds_the_observed_target() {
        let delete = SdcPreparedIpsWrite::new(
            IpsWriteAction::Delete,
            IpsWriteFamily::Profile,
            Some("p-1".to_owned()),
            Value::Null,
            json!({ "uuid": "p-1", "name": "P" }),
        )
        .expect("profile delete");
        assert!(delete.request().is_null());
        assert_eq!(delete.plan()["action"], "delete");
        assert_eq!(delete.plan()["before"]["name"], "P");

        let rule = SdcPreparedIpsWrite::new_rule(
            IpsWriteAction::Delete,
            "p-1".to_owned(),
            Some("r-1".to_owned()),
            Value::Null,
            json!({ "uuid": "r-1", "name": "R" }),
        )
        .expect("rule delete needs no rule body");
        assert_eq!(rule.plan()["profile_uuid"], "p-1");

        for (uuid, request, before) in [
            // A body.
            (
                Some("p-1".to_owned()),
                json!({ "name": "P" }),
                json!({ "uuid": "p-1" }),
            ),
            // No target UUID.
            (None, Value::Null, json!({ "uuid": "p-1" })),
            // No observed before-state.
            (Some("p-1".to_owned()), Value::Null, Value::Null),
        ] {
            assert!(
                SdcPreparedIpsWrite::new(
                    IpsWriteAction::Delete,
                    IpsWriteFamily::Profile,
                    uuid,
                    request,
                    before,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn a_predefined_or_unknown_signature_is_never_deleted() {
        assert!(
            SdcPreparedIpsWrite::new(
                IpsWriteAction::Delete,
                IpsWriteFamily::Signature,
                Some("sig-1".to_owned()),
                Value::Null,
                custom_signature(),
            )
            .is_ok(),
            "a custom signature is deletable"
        );
        let mut predefined = custom_signature();
        predefined["activation_date"] = json!("2026-01-01");
        let mut unknown = custom_signature();
        unknown["signature_type"] = json!("bundle");
        for before in [predefined, unknown] {
            let error = SdcPreparedIpsWrite::new(
                IpsWriteAction::Delete,
                IpsWriteFamily::Signature,
                Some("sig-1".to_owned()),
                Value::Null,
                before,
            )
            .expect_err("only a known custom signature may be deleted");
            assert!(error.to_string().contains("refusing to delete"), "{error}");
        }
    }

    #[test]
    fn a_refusal_names_a_bounded_number_of_referrers() {
        assert!(refuse_if_referenced("IPS profile p-1", &[]).is_ok());
        let referrers = (0..25)
            .map(|n| format!("firewall rule pol/zone/r-{n}"))
            .collect::<Vec<_>>();
        let error = refuse_if_referenced("IPS profile p-1", &referrers)
            .expect_err("referenced")
            .to_string();
        assert!(error.contains("25 object(s)"), "{error}");
        assert!(error.contains("r-19"), "{error}");
        assert!(!error.contains("r-20"), "{error}");
        assert!(error.contains("and 5 more"), "{error}");
    }

    #[test]
    fn profile_names_follow_the_spec_format() {
        assert!(is_valid_profile_name("PROTECT-DVWA"));
        assert!(is_valid_profile_name(&"a".repeat(127)));
        assert!(!is_valid_profile_name(""));
        assert!(!is_valid_profile_name(&"a".repeat(128)));
        for bad in ["has space", "a#b", "a&b", "a;b", "a\rb", "a\nb"] {
            assert!(!is_valid_profile_name(bad), "{bad:?} accepted");
        }
        assert!(
            SdcPreparedIpsWrite::new(
                IpsWriteAction::Create,
                IpsWriteFamily::Profile,
                None,
                json!({ "name": "bad name" }),
                Value::Null,
            )
            .is_err()
        );
    }

    #[test]
    fn a_tampered_envelope_fails_its_digest() {
        let prepared = SdcPreparedIpsWrite::new(
            IpsWriteAction::Create,
            IpsWriteFamily::Signature,
            None,
            json!({ "name": "CUSTOM-X", "severity": "minor" }),
            Value::Null,
        )
        .expect("prepared");
        let mut stored = serde_json::to_value(&prepared).expect("serialize");
        stored["request"]["severity"] = json!("critical");
        let tampered: SdcPreparedIpsWrite = serde_json::from_value(stored).expect("deserialize");
        let error = tampered.validate().expect_err("digest mismatch");
        assert!(error.to_string().contains("digest"));
    }

    #[test]
    fn a_tampered_before_state_cannot_hide_a_predefined_signature() {
        // A predefined signature planned as custom by editing the stored
        // before-state also breaks the digest, so the guard cannot be bypassed
        // through the state file.
        let prepared = SdcPreparedIpsWrite::new(
            IpsWriteAction::Update,
            IpsWriteFamily::Signature,
            Some("sig-1".to_owned()),
            json!({ "name": "CUSTOM-SQL-TIME-BASED" }),
            custom_signature(),
        )
        .expect("prepared");
        let mut stored = serde_json::to_value(&prepared).expect("serialize");
        stored["before"]["import_id"] = json!("HTTP:SQL:INJ:COMMENT");
        let tampered: SdcPreparedIpsWrite = serde_json::from_value(stored).expect("deserialize");
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn a_create_response_yields_the_allocated_uuid_when_present() {
        assert_eq!(
            created_uuid_from(&json!({ "uuid": "8ad65be9-0000", "name": "X" })).as_deref(),
            Some("8ad65be9-0000")
        );
        for response in [
            Value::Null,
            json!({}),
            json!({ "uuid": "" }),
            json!({ "uuid": "  " }),
            json!({ "uuid": 42 }),
            json!([{ "uuid": "nested" }]),
        ] {
            assert_eq!(created_uuid_from(&response), None, "{response}");
        }
    }

    #[test]
    fn the_wire_names_are_stable() {
        assert_eq!(json!(IpsWriteFamily::Signature), json!("signature"));
        assert_eq!(json!(IpsWriteFamily::Profile), json!("profile"));
        assert_eq!(json!(IpsWriteAction::Create), json!("create"));
        assert_eq!(json!(IpsWriteAction::Update), json!("update"));
        assert_eq!(json!(IpsWriteAction::Delete), json!("delete"));
        assert_eq!(IpsWriteAction::Delete.as_str(), "ips_delete");
    }
}
