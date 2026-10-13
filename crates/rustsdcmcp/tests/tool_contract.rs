//! Security tripwires for MCP tool and HTTP preflight registries.

use rustsdcmcp::{KNOWN_TOOLS, SCOPED_READ_TOOLS, WILDCARD_EXCLUDED_TOOLS, WRITE_TOOLS};
use std::collections::BTreeSet;

#[test]
fn tool_registry_has_expected_unique_surface() {
    // 60 reads / 18 writes. The firewall rule-write pair (#226) and the rule-layout pair (#229, #230) each added 2 writes. #32 added 6 license/certificate reads (PR #49) and
    // 2 license/certificate writes; #34 added device-group list and get; #63
    // added discard_sdc_operation, which must be a write tool so a wildcard
    // scope cannot reach it; #21 added list_sdc_config_versions (read) and the
    // device-sync prepare/apply pair. #156 added 12 reads: sites (redacted),
    // IPS rules and exempt-rules, ECF rule-sets and rules, and global-settings.
    // #155 added 7 reads: device config sections and revision, image definitions
    // and job status, MNHA sync and RMA status. MEC-224 added
    // list_users_and_roles, a read-only metadata-only IAM tool reopening
    // CLAUDE.md's IAM decision narrowly (see the decision log entry there);
    // it is a `SCOPED_READ_TOOLS` entry, excluded from wildcard tool grants
    // like a write tool, but not itself a write.
    assert_eq!(KNOWN_TOOLS.len(), 78);
    assert_eq!(
        KNOWN_TOOLS.iter().copied().collect::<BTreeSet<_>>().len(),
        KNOWN_TOOLS.len()
    );
    assert_eq!(
        WRITE_TOOLS.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "apply_sdc_change_set",
            "apply_sdc_device_inventory_sync",
            "apply_sdc_firewall_layout_write",
            "apply_sdc_firewall_rule_write",
            "apply_sdc_firewall_write",
            "apply_sdc_license_write",
            "apply_sdc_nat_write",
            "apply_sdc_object_write",
            "approve_sdc_change_set",
            "discard_sdc_operation",
            "prepare_sdc_device_inventory_sync",
            "prepare_sdc_firewall_layout_write",
            "prepare_sdc_firewall_rule_write",
            "prepare_sdc_firewall_write",
            "prepare_sdc_license_write",
            "prepare_sdc_nat_write",
            "prepare_sdc_object_write",
            "prepare_sdc_policy_deploy",
        ])
    );
}

/// Reads must stay the majority of the surface.
///
/// `CLAUDE.md` requires read-only tools to land first and remain dominant, so
/// a change that tips the balance toward mutation should fail here rather than
/// pass unnoticed.
#[test]
fn read_tools_remain_the_majority_of_the_surface() {
    let writes = WRITE_TOOLS.len();
    let reads = KNOWN_TOOLS.len() - writes;
    assert!(
        reads > writes,
        "{reads} read tools must outnumber {writes} write tools"
    );
}

/// Every scoped-read tool is registered, and none doubles as a write tool.
///
/// `SCOPED_READ_TOOLS` and `WRITE_TOOLS` share one property — excluded from a
/// wildcard tool grant — but for different reasons (mutation risk vs. tenant
/// identity disclosure), and a tool conflating the two would blur that in the
/// audit log's `action` field.
#[test]
fn scoped_read_tools_are_registered_and_disjoint_from_write_tools() {
    for tool in SCOPED_READ_TOOLS {
        assert!(
            KNOWN_TOOLS.contains(tool),
            "{tool} is a scoped-read tool but is not registered"
        );
        assert!(
            !WRITE_TOOLS.contains(tool),
            "{tool} is in both SCOPED_READ_TOOLS and WRITE_TOOLS"
        );
    }
}

/// `WILDCARD_EXCLUDED_TOOLS` backs the HTTP preflight
/// (`mecmcp_transport::ToolScopePreflight`, which needs a `&'static` slice
/// and so can't be built from `WRITE_TOOLS`/`SCOPED_READ_TOOLS` at runtime).
/// It is a hand-written literal for that reason; this pins it equal to their
/// union so the preflight and the handler's own `authorize_request` check
/// can't silently drift apart again.
#[test]
fn wildcard_excluded_tools_equals_write_tools_union_scoped_read_tools() {
    let expected: BTreeSet<&str> = WRITE_TOOLS
        .iter()
        .chain(SCOPED_READ_TOOLS.iter())
        .copied()
        .collect();
    let actual: BTreeSet<&str> = WILDCARD_EXCLUDED_TOOLS.iter().copied().collect();
    assert_eq!(actual, expected);
    assert_eq!(
        WILDCARD_EXCLUDED_TOOLS.len(),
        actual.len(),
        "WILDCARD_EXCLUDED_TOOLS must not contain duplicates"
    );
}

/// Every write tool is registered, and no read tool is silently a write.
#[test]
fn write_tools_are_all_registered_and_named_for_their_lifecycle() {
    for tool in WRITE_TOOLS {
        assert!(
            KNOWN_TOOLS.contains(tool),
            "{tool} is a write tool but is not registered"
        );
        assert!(
            tool.starts_with("prepare_")
                || tool.starts_with("approve_")
                || tool.starts_with("apply_")
                // discard is a lifecycle operation rather than a phase: it clears
                // a wedged operation so applies are unblocked, not a change-control
                // phase like prepare/approve/apply.
                || tool.starts_with("discard_"),
            "{tool} mutates but is not named for a change-control phase or lifecycle operation"
        );
    }
}

#[test]
fn a_device_group_list_accepts_an_omitted_from_and_fields() {
    // `ListArgs::from` is `#[serde(default)]`, so every other list tool accepts
    // a call without `from`. The device-group list uses its own argument type
    // to carry `fields`, and dropping that default would have broken a
    // previously valid call shape without any test noticing.
    let args: rustsdcmcp::DeviceGroupListArgs =
        serde_json::from_value(serde_json::json!({"tenant": "production", "size": 10}))
            .expect("omitting from must stay valid");
    assert_eq!(args.from, 0);
    assert!(args.fields.is_empty());

    let projected: rustsdcmcp::DeviceGroupListArgs = serde_json::from_value(
        serde_json::json!({"tenant": "production", "size": 10, "fields": ["uuid", "name"]}),
    )
    .expect("fields is a list, not a comma-joined string");
    assert_eq!(projected.fields, vec!["uuid".to_owned(), "name".to_owned()]);
}

/// Tools that return credential-bearing responses use `finish_redacted`.
///
/// Reverting a redacted handler to plain `finish` would pass the existing
/// tests, because no test exercises a live credential field. This tripwire
/// fails if any REDACTED_TOOLS handler does not call `finish_redacted`, or
/// if it calls plain `finish`.
#[test]
fn redacted_tools_call_finish_redacted() {
    const REDACTED_TOOLS: &[&str] = &[
        "list_sdc_resources",
        "get_sdc_resource",
        "list_sdc_sites",
        "get_sdc_site",
        "get_sdc_firewall_global_settings",
        "get_sdc_firewall_global_profile",
        "get_sdc_content_security_settings",
        "list_sdc_device_global_settings",
        "list_sdc_device_config",
        "get_sdc_device_config_revision",
        "list_sdc_image_definitions",
        "get_sdc_image_job_status",
        "get_sdc_mnha_sync_status",
        "get_sdc_rma_state",
        "get_sdc_rma_reactivation_status",
        "list_sdc_ips_rules",
        "get_sdc_ips_rule",
        "list_sdc_ips_exempt_rules",
        "get_sdc_ips_exempt_rule",
        "list_sdc_ecf_rule_sets",
        "list_sdc_ecf_rules",
        "list_sdc_ipsec_profiles",
        "get_sdc_ipsec_profile",
        "get_sdc_tenant_scope",
        "list_sdc_devices",
        "get_sdc_device",
        "list_sdc_config_versions",
        "list_sdc_firewall_policies",
        "get_sdc_firewall_policy",
        "list_sdc_nat_policies",
        "get_sdc_nat_policy",
        "list_sdc_firewall_rules",
        "get_sdc_firewall_rule",
        "list_sdc_firewall_rule_groups",
        "get_sdc_firewall_hierarchy",
        "list_sdc_nat_rules",
        "get_sdc_nat_rule",
        "list_sdc_nat_rule_groups",
        "get_sdc_nat_hierarchy",
        "list_sdc_nat_pools",
        "list_sdc_device_groups",
        "get_sdc_device_group",
        "get_sdc_nat_pool",
        "list_sdc_ca_certificates",
        "list_sdc_local_certificates",
        "list_sdc_device_ca_certificates",
        "list_sdc_device_local_certificates",
        "list_sdc_licenses",
        "get_sdc_license",
        "get_sdc_firewall_policy_state",
        "list_sdc_tunnels",
        "get_sdc_tunnel",
        "get_sdc_tunnel_count",
        "get_sdc_preview_status",
        "get_sdc_deploy_status",
        "get_sdc_preview_device_result",
        "get_sdc_deploy_device_result",
        "get_sdc_change_set",
        "get_sdc_change_set_details",
        // Write tools (Percy B2, MEC-440): prepare/apply echo raw upstream
        // before-state, so their output is redacted too.
        "prepare_sdc_policy_deploy",
        "prepare_sdc_firewall_write",
        "prepare_sdc_firewall_rule_write",
        "prepare_sdc_firewall_layout_write",
        "prepare_sdc_license_write",
        "prepare_sdc_device_inventory_sync",
        "prepare_sdc_object_write",
        "prepare_sdc_nat_write",
        "approve_sdc_change_set",
        "apply_sdc_change_set",
        "apply_sdc_firewall_write",
        "apply_sdc_firewall_rule_write",
        "apply_sdc_firewall_layout_write",
        "apply_sdc_license_write",
        "apply_sdc_device_inventory_sync",
        "apply_sdc_object_write",
        "apply_sdc_nat_write",
        "discard_sdc_operation",
        "list_users_and_roles",
    ];

    // Every REDACTED_TOOLS entry must be a known tool.
    for tool in REDACTED_TOOLS {
        assert!(
            KNOWN_TOOLS.contains(tool),
            "{tool} is in REDACTED_TOOLS but not KNOWN_TOOLS"
        );
    }

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let server_rs = std::fs::read_to_string(format!("{manifest_dir}/src/server.rs"))
        .expect("server.rs must be readable");
    let file = syn::parse_file(&server_rs).expect("server.rs must parse");

    let mut found_tools = BTreeSet::new();

    for item in &file.items {
        if let syn::Item::Impl(impl_block) = item {
            for impl_item in &impl_block.items {
                if let syn::ImplItem::Fn(method) = impl_item {
                    // Convert method to string to search for tool names
                    let method_str = quote::quote!(#method).to_string();

                    // Check each redacted tool
                    for tool in REDACTED_TOOLS {
                        let tool_marker = format!("name = \"{}\"", tool);
                        if method_str.contains(&tool_marker) {
                            found_tools.insert(*tool);

                            assert!(
                                method_str.contains("finish_redacted"),
                                "{tool} is in REDACTED_TOOLS but does not call finish_redacted"
                            );
                            // Check that plain finish( is not called (but finish_redacted is OK)
                            // We look for "finish (" with a space to distinguish from finish_redacted
                            let has_plain_finish = method_str.contains("finish (")
                                || (method_str.contains("finish(")
                                    && !method_str.contains("finish_redacted("));
                            assert!(
                                !has_plain_finish,
                                "{tool} is in REDACTED_TOOLS but may call plain finish()"
                            );
                        }
                    }
                }
            }
        }
    }

    // Ensure we found all expected tools
    for tool in REDACTED_TOOLS {
        assert!(
            found_tools.contains(tool),
            "{tool} is in REDACTED_TOOLS but was not found in server.rs"
        );
    }

    // Reverse check: every method that calls finish_redacted must be in REDACTED_TOOLS.
    let mut tools_calling_finish_redacted = BTreeSet::new();
    let mut all_tool_methods = BTreeSet::new();

    for item in &file.items {
        if let syn::Item::Impl(impl_block) = item {
            for impl_item in &impl_block.items {
                if let syn::ImplItem::Fn(method) = impl_item {
                    let method_str = quote::quote!(#method).to_string();

                    // Find tool name from #[tool(name = "...")] attribute, or fall back to fn ident
                    let mut tool_name = None;
                    for attr in &method.attrs {
                        let attr_str = quote::quote!(#attr).to_string();
                        // Check for #[tool(...)] or # [tool (...)] (quote may add spaces)
                        if attr_str.contains("tool") && attr_str.contains("name =") {
                            // Extract name = "tool_name"
                            if let Some(start) = attr_str.find("name = \"") {
                                let rest = &attr_str[start + 8..];
                                if let Some(end) = rest.find('"') {
                                    tool_name = Some(rest[..end].to_owned());
                                    break;
                                }
                            }
                        }
                    }

                    // If we didn't find explicit name but have a tool attr, fall back to fn ident
                    if tool_name.is_none() {
                        for attr in &method.attrs {
                            let attr_str = quote::quote!(#attr).to_string();
                            if attr_str.contains("tool") {
                                tool_name = Some(method.sig.ident.to_string());
                                break;
                            }
                        }
                    }

                    if let Some(name) = &tool_name {
                        all_tool_methods.insert(name.clone());

                        if method_str.contains("finish_redacted") {
                            tools_calling_finish_redacted.insert(name.clone());
                        }
                    }
                }
            }
        }
    }

    // Every tool that calls finish_redacted must be in REDACTED_TOOLS
    for tool in &tools_calling_finish_redacted {
        assert!(
            REDACTED_TOOLS.contains(&tool.as_str()),
            "{tool} calls finish_redacted but is not in REDACTED_TOOLS"
        );
    }

    // Sanity check: parser should find as many tool methods as KNOWN_TOOLS has entries
    assert_eq!(
        all_tool_methods.len(),
        KNOWN_TOOLS.len(),
        "tripwire parser found {} tool methods but KNOWN_TOOLS has {}",
        all_tool_methods.len(),
        KNOWN_TOOLS.len()
    );
}

/// Percy B2 (MEC-440): write tools echo raw upstream before-state
/// (`prepared_change`, `plan`), so every tool handler — read or write — must
/// return through `finish_redacted`. The only plain `finish(` call allowed in
/// server.rs is the one inside `finish_redacted` itself.
#[test]
fn every_tool_handler_output_is_redacted() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let server_rs = std::fs::read_to_string(format!("{manifest_dir}/src/server.rs"))
        .expect("server.rs must be readable");
    let plain_calls = server_rs
        .match_indices("finish(")
        .filter(|(i, _)| {
            let prev = server_rs[..*i].chars().next_back();
            !matches!(prev, Some(c) if c == '_' || c.is_ascii_alphanumeric())
        })
        .count();
    assert_eq!(
        plain_calls, 1,
        "server.rs must call plain `finish(` only inside `finish_redacted`; \
         route every tool handler through `finish_redacted`"
    );
}
