//! Byte-budgeted pagination for list results SDC does not paginate itself.
//!
//! `list_config_versions` and similar endpoints return every item in one
//! response; SDC documents no `from`/`size` parameters for them (unlike
//! [`crate::ListRequest`], which wraps endpoints that do). Left alone, a
//! large tenant's list exceeds `max_response_bytes` and the whole call is
//! refused. This module slices an already-fetched `{"items": [...], ...}`
//! value into a byte-budgeted page plus a continuation token, so a big tenant
//! degrades to more calls rather than an outright failure.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Opaque continuation-token prefix. Bumping it invalidates tokens issued by
/// an older build rather than let them be silently misread as an offset.
const TOKEN_PREFIX: &str = "sdcpage1:";

/// One page of a budget-paginated list result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListPage {
    /// This page's items, in original order and optionally field-projected.
    pub items: Vec<Value>,
    /// Items in this page.
    pub page_item_count: usize,
    /// Items in the full source list.
    pub total_item_count: usize,
    /// Opaque token to fetch the next page; `None` once the list is exhausted.
    pub continuation_token: Option<String>,
}

/// A paging request could not be satisfied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PageError {
    /// `items_key` did not resolve to a JSON array on the source value.
    #[error("list result has no `{0}` array to page")]
    NotAList(&'static str),
    /// The supplied continuation token was not issued by this module.
    #[error("continuation token is not valid")]
    InvalidContinuationToken,
}

/// Slice `value[items_key]` into one byte-budgeted page.
///
/// `fields`, when given, keeps only those top-level keys on each item before
/// it is sized or returned, letting a caller shrink the page further than
/// the budget alone would. The budget is soft in one direction only: once any
/// items remain, the page always contains at least one, even if that single
/// item alone exceeds `budget_bytes` -- paging always makes progress rather
/// than stalling on one oversized item.
///
/// # Errors
///
/// Returns [`PageError::NotAList`] if `value[items_key]` is missing or is not
/// a JSON array, and [`PageError::InvalidContinuationToken`] if
/// `continuation_token` was not produced by a prior call to this function.
pub fn page_list(
    value: &Value,
    items_key: &'static str,
    fields: Option<&[String]>,
    continuation_token: Option<&str>,
    budget_bytes: usize,
) -> Result<ListPage, PageError> {
    let items = value
        .get(items_key)
        .and_then(Value::as_array)
        .ok_or(PageError::NotAList(items_key))?;
    let total_item_count = items.len();
    let offset = match continuation_token {
        Some(token) => decode_offset(token)?,
        None => 0,
    };
    let start = offset.min(total_item_count);

    let mut page = Vec::new();
    let mut used = 0usize;
    for item in &items[start..] {
        let projected = project_fields(item, fields);
        let size = serde_json::to_string(&projected).unwrap_or_default().len();
        if !page.is_empty() && used.saturating_add(size) > budget_bytes {
            break;
        }
        used = used.saturating_add(size);
        page.push(projected);
    }

    let next_offset = start + page.len();
    let continuation_token = (next_offset < total_item_count).then(|| encode_offset(next_offset));

    Ok(ListPage {
        page_item_count: page.len(),
        items: page,
        total_item_count,
        continuation_token,
    })
}

/// Page two independent list envelopes against one shared byte budget, split
/// evenly so neither alone can exhaust it.
///
/// `list_users_and_roles` returns users and roles as two unrelated arrays
/// rather than one `items` list, so [`page_list`] alone cannot page it: each
/// sub-list needs its own continuation token and its own share of the budget.
///
/// # Errors
///
/// Returns [`PageError`] if either envelope does not resolve to a JSON array
/// under its key, or either continuation token is invalid.
pub fn page_paired_lists(
    first_envelope: &Value,
    first_key: &'static str,
    first_token: Option<&str>,
    second_envelope: &Value,
    second_key: &'static str,
    second_token: Option<&str>,
    budget_bytes: usize,
) -> Result<(ListPage, ListPage), PageError> {
    let half_budget = budget_bytes / 2;
    let first = page_list(first_envelope, first_key, None, first_token, half_budget)?;
    let second = page_list(second_envelope, second_key, None, second_token, half_budget)?;
    Ok((first, second))
}

fn project_fields(item: &Value, fields: Option<&[String]>) -> Value {
    let Some(fields) = fields else {
        return item.clone();
    };
    let Value::Object(map) = item else {
        return item.clone();
    };
    let mut projected = Map::new();
    for field in fields {
        if let Some(value) = map.get(field) {
            projected.insert(field.clone(), value.clone());
        }
    }
    Value::Object(projected)
}

fn encode_offset(offset: usize) -> String {
    format!("{TOKEN_PREFIX}{offset}")
}

fn decode_offset(token: &str) -> Result<usize, PageError> {
    token
        .strip_prefix(TOKEN_PREFIX)
        .ok_or(PageError::InvalidContinuationToken)?
        .parse()
        .map_err(|_| PageError::InvalidContinuationToken)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tenant_with_rules(count: usize) -> Value {
        let items: Vec<Value> = (0..count)
            .map(|index| json!({"uuid": format!("rule-{index}"), "name": format!("rule {index}"), "action": "permit", "source": "any", "destination": "any", "application": "any"}))
            .collect();
        json!({"items": items, "count": count})
    }

    #[test]
    fn a_ten_thousand_rule_tenant_pages_without_hitting_a_size_refusal() {
        let tenant = tenant_with_rules(10_000);
        let mut token: Option<String> = None;
        let mut seen = 0usize;
        let mut pages = 0usize;
        loop {
            let page = page_list(&tenant, "items", None, token.as_deref(), 65_536).expect("pages");
            seen += page.page_item_count;
            assert_eq!(page.total_item_count, 10_000);
            pages += 1;
            assert!(pages < 10_000, "paging did not converge");
            match page.continuation_token {
                Some(next) => token = Some(next),
                None => break,
            }
        }
        assert_eq!(seen, 10_000);
        assert!(pages > 1, "10,000 rules must not fit in one 64 KiB page");
    }

    #[test]
    fn a_continuation_token_round_trips_across_three_pages() {
        let tenant = tenant_with_rules(300);
        let page1 = page_list(&tenant, "items", None, None, 8_192).expect("page 1");
        assert!(page1.page_item_count < 300);
        let token1 = page1.continuation_token.expect("more pages remain");

        let page2 = page_list(&tenant, "items", None, Some(&token1), 8_192).expect("page 2");
        let token2 = page2.continuation_token.expect("more pages remain");
        assert_eq!(page1.items[0]["uuid"], "rule-0");
        assert_eq!(
            page2.items[0]["uuid"],
            format!("rule-{}", page1.page_item_count)
        );

        let page3 = page_list(&tenant, "items", None, Some(&token2), 8_192).expect("page 3");
        assert_eq!(
            page3.items[0]["uuid"],
            format!("rule-{}", page1.page_item_count + page2.page_item_count)
        );

        // Every item across the three pages is present exactly once, in order.
        let mut collected: Vec<Value> = page1.items;
        collected.extend(page2.items);
        collected.extend(page3.items);
        assert!(collected.len() < 300, "test setup must need a 4th page");
        for (index, item) in collected.iter().enumerate() {
            assert_eq!(item["uuid"], format!("rule-{index}"));
        }
    }

    #[test]
    fn fields_selector_projects_each_item() {
        let tenant = tenant_with_rules(2);
        let fields = vec!["uuid".to_owned()];
        let page = page_list(&tenant, "items", Some(&fields), None, 65_536).expect("pages");
        assert_eq!(page.items[0], json!({"uuid": "rule-0"}));
        assert!(page.items[0].get("name").is_none());
    }

    #[test]
    fn an_oversized_single_item_still_makes_progress() {
        let tenant = tenant_with_rules(3);
        // A budget far smaller than one item still returns that one item
        // rather than looping forever.
        let page = page_list(&tenant, "items", None, None, 1).expect("pages");
        assert_eq!(page.page_item_count, 1);
        assert!(page.continuation_token.is_some());
    }

    #[test]
    fn exhausting_the_list_returns_no_continuation_token() {
        let tenant = tenant_with_rules(3);
        let page = page_list(&tenant, "items", None, None, 65_536).expect("pages");
        assert_eq!(page.page_item_count, 3);
        assert_eq!(page.continuation_token, None);
    }

    #[test]
    fn an_invalid_continuation_token_is_refused() {
        let tenant = tenant_with_rules(3);
        let error = page_list(&tenant, "items", None, Some("garbage"), 65_536).unwrap_err();
        assert_eq!(error, PageError::InvalidContinuationToken);
    }

    #[test]
    fn a_missing_items_array_is_refused() {
        let error = page_list(&json!({}), "items", None, None, 65_536).unwrap_err();
        assert_eq!(error, PageError::NotAList("items"));
    }

    fn users_envelope(count: usize) -> Value {
        let users: Vec<Value> = (0..count)
            .map(|index| json!({"user_id": format!("user-{index}"), "email": format!("user{index}@example.com"), "name": "User Name", "status": "active", "last_login": "2026-01-01T00:00:00Z", "role": []}))
            .collect();
        json!({"users": users})
    }

    fn roles_envelope(count: usize) -> Value {
        let roles: Vec<Value> = (0..count)
            .map(|index| json!({"uuid": format!("role-{index}"), "name": format!("role {index}"), "capabilities": ["read", "write"], "predefined": false}))
            .collect();
        json!({"roles": roles})
    }

    #[test]
    fn page_paired_lists_pages_each_list_independently() {
        let users = users_envelope(500);
        let roles = roles_envelope(3);
        let (users_page, roles_page) =
            page_paired_lists(&users, "users", None, &roles, "roles", None, 8_192).expect("pages");
        assert_eq!(roles_page.page_item_count, 3);
        assert_eq!(roles_page.continuation_token, None);
        assert!(
            users_page.page_item_count < 500,
            "500 users must not fit in half of an 8 KiB budget"
        );
        assert!(users_page.continuation_token.is_some());
    }

    #[test]
    fn page_paired_lists_splits_the_budget_so_one_list_cannot_starve_the_other() {
        // Both lists are individually large enough to exhaust the full budget
        // alone; proving each gets at least one item back from its own half
        // is what distinguishes this from a naive "page users with the whole
        // budget, then roles with whatever (nothing) is left" bug.
        let users = users_envelope(10_000);
        let roles = roles_envelope(10_000);
        let (users_page, roles_page) =
            page_paired_lists(&users, "users", None, &roles, "roles", None, 8_192).expect("pages");
        assert!(users_page.page_item_count >= 1);
        assert!(roles_page.page_item_count >= 1);
    }

    #[test]
    fn page_paired_lists_round_trips_continuation_tokens_independently() {
        let users = users_envelope(10);
        let roles = roles_envelope(10);
        let (first_users, first_roles) =
            page_paired_lists(&users, "users", None, &roles, "roles", None, 256)
                .expect("first page");
        let users_token = first_users.continuation_token.expect("more users remain");
        // Roles already exhausted in the first page; its token must stay `None`
        // rather than being coupled to the users side advancing.
        let (second_users, second_roles) = page_paired_lists(
            &users,
            "users",
            Some(&users_token),
            &roles,
            "roles",
            first_roles.continuation_token.as_deref(),
            256,
        )
        .expect("second page");
        assert_eq!(
            second_users.items[0]["user_id"],
            format!("user-{}", first_users.page_item_count)
        );
        assert_eq!(second_roles.total_item_count, 10);
    }

    #[test]
    fn page_paired_lists_refuses_the_wrong_key_on_either_side() {
        let users = users_envelope(1);
        let roles = roles_envelope(1);
        let error =
            page_paired_lists(&users, "roles", None, &roles, "roles", None, 65_536).unwrap_err();
        assert_eq!(error, PageError::NotAList("roles"));
    }
}
