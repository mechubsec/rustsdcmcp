# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`rustsdcmcp` is an MCP server for **HPE Juniper Security Director Cloud** (SDC).
The repository is a Rust workspace with `rustsdcmcp-core` (SDC client, models,
and change adapter) and `rustsdcmcp` (rmcp handler and runtime composition).
Use `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D
warnings`, and `cargo fmt --all --check`.

## The one architectural rule

This repo is a **consumer** of [`mecmcp`](https://github.com/mechubsec/mecmcp)
(local checkout: `~/Projects/mecmcp`), the vendor-neutral Rust foundation shared
across the mechub MCP server family. The split is not negotiable:

- **Consumed from `mecmcp`:** token auth/scopes/grants (`mecmcp-auth`), audit and
  redaction (`mecmcp-audit`), streamable-HTTP transport and limits
  (`mecmcp-transport`), CLI/TLS/shutdown (`mecmcp-runtime`), change-control
  state machine (`mecmcp-changeset`), inventory (`mecmcp-inventory`).
- **Here:** the SDC REST client, exact opaque OAuth-token/API-key headers,
  response models, endpoint allowlist, and MCP tool surface.

Do not modify `mecmcp` from this repository task. Missing shared cloud-client
foundations are tracked in mecmcp#90, and target-neutral auth vocabulary in
mecmcp#91. Keep temporary compatibility code product-specific and isolated;
do not expand it into a competing shared framework.

Sibling reference implementations for the *shape* of a mechub MCP server:
`~/Projects/RustJunosMCP` (NETCONF/SSH, runtime hardening) and
`~/Projects/rust-panosmcp` (HTTPS XML-API, change-control lifecycle). SDC is
closest to the PAN-OS repo — HTTPS REST against a remote management plane — so
prefer its structure when adding the client and tool layers.

## Management plane, not device plane

SDC is a SASE portal fronting an entire estate. One API call can move policy
across thousands of managed devices. Consequences that must hold in any code
added here:

- Mutating tools are reachable **only** through `mecmcp-changeset`'s
  plan → digest → approve → apply → verify lifecycle. Never a direct write.
- Read-only tools land first and stay the majority of the surface.
- Response sizes are bounded — an estate-wide query will return far more than a
  single-device one.
- HTTP bearer tokens carry explicit tool **and tenant** scopes. Write tools
  reject unauthenticated stdio/loopback callers.

## What this server is not for

Decided 2026-08-20 (#34). SDC's API spans the whole product; this server covers
the part of it that manages SRX devices and their policy. The rest is recorded
here so an absence reads as a decision rather than as work nobody got to.

**Out of scope — do not implement.**

- **IAM** (user and role administration, 9 operations beyond the `GetTokenScope`
  used for startup tenant validation). Narrowed 2026-09-29 (MEC-224, below):
  `ListUsers`/`GetUser`/`ListRoles`/`GetRole` are read-only, metadata-only, and
  in scope. `CreateUser`, `EditUser`, `DeleteUser`, `ChangePassword`, and
  `SendActivateUserEmail` stay excluded under this decision.
- **Subscriptions** (tenant entitlement, 3 operations)
- **`GET /api/v1/devices/{device_id}/rma/reactivation_config`** — returns
  `config_contents`, a full bootstrap device configuration. A credential-bearing
  blob with no review value; the RMA state and reactivation-status reads cover
  the lifecycle question.

**Deferred writes** — reads exist; writes need prepare → approve → apply.

Image stage/deploy (`POST /api/v1/device_image_definitions/{image_uuid}/stage_image`,
`POST /api/v1/device_image_definitions/{image_uuid}/deploy_image`, and
`POST /api/v1/device_image_definitions/deploy_image` for bulk), MNHA sync,
RMA activate/reactivate, image-definition create/delete, and RMA
`reactivation_preferences` stay unbuilt as writes. If needed, they go through
prepare → approve → apply, never direct.

IAM and subscriptions are tenant administration, not network management. An MCP
client that can create users, alter roles or change entitlements holds a surface
with no networking value and a large blast radius — the same reasoning that puts
Mist's portal identity flows in `ExecuteClass::Excluded` over in rustmistmcp.
If a future need appears, it needs its own decision recorded here, not a quiet
addition.

### IAM read-only exception: `list_users_and_roles`

Decided 2026-09-29 (MEC-224). #34 excluded IAM outright — no networking value,
large blast radius. The need that reopened it is narrower than #34 addressed:
SOC incident review (MEC-38-style "who has access") needs a read of who has
what role, not any ability to change it.

**In scope, read-only, metadata-only:** `ListUsers`, `GetUser`, `ListRoles`,
`GetRole` (`/api/v2/users`, `/api/v2/user/{user_id}`, `/api/v2/roles`,
`/api/v2/role/{ID}` — all `/api/v2/`, confirmed against the vendored spec;
there is no `/api/v1/` IAM path). The `list_users_and_roles` tool wires up
`ListUsers` and `ListRoles`; `GetUser`/`GetRole` are in scope for a future
single-lookup tool but are not implemented by this one.

SDC's `ListUsers` response has no `created`/`created_by` field — only
`user_id`, `email`, `name`, `status`, `last_login`, `role[].role_name`.
`ListRoles` has `UUID`, `name`, `capabilities`, `predefined`, and no timestamp
at all. Neither carries key or secret material; SDC's IAM surface has no
API-key concept. `list_users_and_roles` returns exactly these fields — it does
not synthesize a `created`/`created_by` value the API does not have.

**Still excluded under #34, unchanged:** `CreateUser`, `EditUser`,
`DeleteUser`, `ChangePassword`, `SendActivateUserEmail` — the five operations
that can alter a user's access rather than report it.

`list_users_and_roles` is in `SCOPED_READ_TOOLS`
(`crates/rustsdcmcp/src/server.rs`), excluded from a wildcard tool scope the
same way `WRITE_TOOLS` is: an existing wildcard-scoped bearer token does not
gain it automatically, and a caller must name it explicitly. Unlike a write
tool, stdio access is unaffected — stdio has no bearer token to scope.

`get_audit_log` and `get_device_connection_history` were considered alongside
this tool for the same SOC incident-review need and dropped: no matching
endpoint exists anywhere in the vendored OpenAPI export, and inventing one
would fail `scripts/spec-drift.py self-check`. That need is tracked separately
as a research question into whether SDC exposes audit/connection data through
a different surface (webhook/syslog export, SIEM integration, a different API
version), not as unfinished work on this decision.

**Deferred with SASE**, if this repo ever grows a SASE remit: PAC Manager (2),
Service Location Management (1).

## The API surface is pinned — read it, don't re-derive it

**`docs/sdc-api/README.md` is the authority.** It is written entirely from
Juniper's OpenAPI 3 export, which is vendored alongside it. Read it before
writing any client code, and never restate an endpoint, header, or parameter
from memory.

Do not try to scrape the HTML reference — the portal is client-rendered
(APIMatic) and fetching pages returns only the shell. That is a dead end
someone will otherwise rediscover. The spec comes from the portal's export
route; `docs/sdc-api/fetch-spec.sh` refreshes it and
`scripts/gen-endpoint-inventory.py` regenerates `docs/sdc-api/endpoints.md`.
`scripts/spec-drift.py self-check` runs on every PR and fails if the client calls a path the vendored spec lacks (matches paths only, not HTTP methods). `.github/workflows/spec-drift.yml` compares against the live export weekly and files a `spec-drift` issue. It never commits.
`endpoints.md` is generated — never hand-edit it.

Load-bearing facts, all verified in the spec:

- Base URL `https://api.sdcloud.juniperclouds.net/`, single server.
- Auth is a header — `x-api-key` or `x-oauth2-token` — declared at the document
  root, and **no operation overrides it** (0 of 377).
- Path versioning is **mixed**: `/api/v1/` for policies/devices/templates,
  `/api/v2/` for IAM/site/tunnels. Never assume one version.
- Bulk mutations are **async**: `POST` → job id, then status and per-device
  result `GET`s. Same shape for `preview`/`deploy`/`selective_deploy`/`cleanup`
  and for device `sync`/`reboot`/`rollback`.
- Preview and deploy are separate endpoints — bind `mecmcp-changeset` to that
  boundary and digest the *preview output*, never a re-render at apply time.
- `size=0` on a list call means "return as many as possible". Never emit it.
- `429` means rate-limited **or** payload-too-large; the remedies differ.

`docs/sdc-api/README.md` ends with a **Still unverified** list (rate-limit
numbers, retry headers, OAuth token format, polling intervals, `409`
retryability, regional hosts). Treat those as open questions requiring a live
tenant — do not close them by inference.

## Conventions inherited from the family

- Rust edition 2024, MSRV 1.89, build toolchain pinned in `rust-toolchain.toml`.
- Workspace lints: `missing_docs = "warn"`, `unsafe_code = "forbid"`,
  `clippy::all` warn, `dbg_macro`/`todo` deny, `unwrap_used` warn.
- Single MIT license (not dual). Repo name is lowercase, no dashes — mechub
  brand rule.
- `.gitignore` deliberately blocks `tokens.json`, `*.tokens.json`, `.env`,
  `*.pem`, `*.key`. Test fixtures under `crates/*/tests/fixtures/` are the only
  exception.
