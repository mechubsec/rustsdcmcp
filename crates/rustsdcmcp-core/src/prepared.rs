//! SDC-specific preview envelope pending the shared abstraction in mecmcp#90.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const MAX_TARGETS: usize = 4096;
const MAX_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;

/// One target bound to an SDC preview.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdcPreparedTarget {
    kind: String,
    identifier: String,
}

impl SdcPreparedTarget {
    /// Construct a bounded SDC target.
    ///
    /// # Errors
    ///
    /// Refuses empty, oversized, whitespace, and control-character values.
    pub fn new(
        kind: impl Into<String>,
        identifier: impl Into<String>,
    ) -> Result<Self, PreparedError> {
        let target = Self {
            kind: kind.into(),
            identifier: identifier.into(),
        };
        target.validate()?;
        Ok(target)
    }

    fn validate(&self) -> Result<(), PreparedError> {
        validate_atom("target kind", &self.kind, 64)?;
        validate_atom("target identifier", &self.identifier, 256)
    }
}

/// Exact SDC request and preview bound into a change-set action.
///
/// This product-owned compatibility type is intentionally narrow. Its
/// vendor-neutral extraction is tracked in mecmcp issue #90.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdcPreparedChange {
    operation: String,
    targets: Vec<SdcPreparedTarget>,
    request: Value,
    preview: Value,
    preview_digest: String,
    preview_job_id: String,
}

impl SdcPreparedChange {
    /// Build a canonical, preview-bound SDC policy deployment.
    ///
    /// # Errors
    ///
    /// Refuses duplicate/empty target sets, invalid job IDs, and oversized
    /// artifacts.
    pub fn new(
        mut targets: Vec<SdcPreparedTarget>,
        request: Value,
        preview: Value,
        preview_job_id: String,
    ) -> Result<Self, PreparedError> {
        targets.sort();
        let prepared = Self {
            operation: "policy_deploy".to_owned(),
            targets,
            request,
            preview_digest: canonical_digest(&preview)?,
            preview,
            preview_job_id,
        };
        prepared.validate()?;
        Ok(prepared)
    }

    /// Product operation discriminator.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Exact deploy request.
    #[must_use]
    pub const fn request(&self) -> &Value {
        &self.request
    }

    /// Complete preview artifact.
    #[must_use]
    pub const fn preview(&self) -> &Value {
        &self.preview
    }

    /// Canonical SHA-256 digest of the preview artifact.
    #[must_use]
    pub fn preview_digest(&self) -> &str {
        &self.preview_digest
    }

    /// SDC preview job identifier.
    #[must_use]
    pub fn preview_job_id(&self) -> &str {
        &self.preview_job_id
    }

    /// Revalidate bounds, ordering, and preview integrity.
    ///
    /// # Errors
    ///
    /// Returns a stable error if persisted content was malformed or tampered.
    pub fn validate(&self) -> Result<(), PreparedError> {
        if self.operation != "policy_deploy" {
            return Err(PreparedError::Operation);
        }
        if self.targets.is_empty() || self.targets.len() > MAX_TARGETS {
            return Err(PreparedError::Targets);
        }
        let mut previous = None;
        for target in &self.targets {
            target.validate()?;
            if previous.is_some_and(|value: &SdcPreparedTarget| value >= target) {
                return Err(PreparedError::Targets);
            }
            previous = Some(target);
        }
        validate_atom("preview job ID", &self.preview_job_id, 256)?;
        if canonical_digest(&self.preview)? != self.preview_digest {
            return Err(PreparedError::Digest);
        }
        if serde_json::to_vec(self)
            .map_err(|_| PreparedError::Serialization)?
            .len()
            > MAX_ARTIFACT_BYTES
        {
            return Err(PreparedError::TooLarge);
        }
        Ok(())
    }
}

/// Canonical SHA-256 digest of a JSON value with object keys ordered.
///
/// Shared with the object-write envelope so both change-controlled paths bind
/// their plans the same way.
pub(crate) fn canonical_digest(value: &Value) -> Result<String, PreparedError> {
    let bytes =
        serde_json::to_vec(&canonicalize(value)).map_err(|_| PreparedError::Serialization)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize(value)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        value => value.clone(),
    }
}

fn validate_atom(field: &'static str, value: &str, maximum: usize) -> Result<(), PreparedError> {
    if value.is_empty()
        || value.len() > maximum
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(PreparedError::InvalidField { field, maximum });
    }
    Ok(())
}

/// Invalid SDC prepared-change envelope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PreparedError {
    /// A bounded field was invalid.
    #[error("{field} must be 1-{maximum} non-whitespace bytes")]
    InvalidField {
        /// Field label.
        field: &'static str,
        /// Maximum byte length.
        maximum: usize,
    },
    /// Operation discriminator was changed.
    #[error("prepared operation must be policy_deploy")]
    Operation,
    /// Target set was empty, duplicate, out of order, or excessive.
    #[error("prepared targets must contain 1-4096 unique canonical entries")]
    Targets,
    /// Preview no longer matched its stored digest.
    #[error("prepared preview does not match its digest")]
    Digest,
    /// JSON serialization failed.
    #[error("prepared change could not be serialized")]
    Serialization,
    /// Serialized envelope exceeded its hard cap.
    #[error("prepared change exceeds the 8388608-byte limit")]
    TooLarge,
}

/// Whether a free-text description looks like markup or an HTML entity.
///
/// SDC rejects such descriptions at apply with an opaque error; refuse them at
/// prepare with a clear one. A lone `<` or `>` and the empty `<>`
/// are accepted by SDC and stay accepted here.
pub(crate) fn description_looks_like_markup(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut open: Option<usize> = None;
    let mut tag_like = false;
    for (i, b) in bytes.iter().enumerate() {
        match b {
            b'<' => {
                open.get_or_insert(i);
            }
            b'>' => {
                if open.is_some_and(|o| i > o + 1) {
                    tag_like = true;
                    break;
                }
                open = None;
            }
            _ => {}
        }
    }
    let entity_like = bytes.iter().enumerate().any(|(start, byte)| {
        *byte == b'&' && {
            let rest = &bytes[start + 1..];
            let len = rest
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric() || **b == b'#')
                .count();
            len > 0 && rest.get(len) == Some(&b';')
        }
    });
    tag_like || entity_like
}

#[cfg(test)]
mod description_tests {
    use super::description_looks_like_markup as bad;

    #[test]
    fn markup_and_entities_are_flagged() {
        for text in [
            "<b>x</b>",
            "a<b>c",
            "<b>",
            "</b>",
            "x<y>",
            "&lt;b&gt;",
            "&#60;",
            "<script>alert(1)</script>",
        ] {
            assert!(bad(text), "{text}");
        }
    }

    #[test]
    fn accepted_punctuation_is_not_flagged() {
        for text in [
            "",
            "plain",
            "a<b",
            "a>b",
            "<>",
            "a < b",
            "a&b",
            "a & b;",
            "caf\u{e9} \u{2014} ok",
            "a(b)#@'\"/;:,.-_",
        ] {
            assert!(!bad(text), "{text}");
        }
    }
}
