# Changelog

`v0.0.1` is the first full release. The `v0.1.0-lab.N` tags that precede it
were published as prereleases; their entries are kept below as the historical
record and are not renumbered.

The upstream blocker that previously appeared here — 59 compatibility ledger
entries awaiting one coherent `mecmcp` release — **is cleared**. The `compat/`
layer was deleted in #36 on the move to mecmcp 0.7.2, and the ledger itself in
`369f9bb` on the move to 0.8.0.

## Unreleased

### Documentation
- Fixed version/doc drift ahead of v0.1.0 (#183): the README's `mecmcp`
  pin reference was stale at `v0.24.0`/six crates (actual: `v0.26.0`, eight
  crates); the SSDF hash-chained audit transport was still described as
  "specified, not yet implemented" although it shipped and is wired into
  `--ssdf-audit-endpoint`; the container image's
  `org.opencontainers.image.licenses` label said `MIT OR Apache-2.0` against
  Cargo's `MIT`; a stray `## Unreleased` heading in this file, left over from
  an untagged release, is renamed to `v0.1.0-lab.9`. The read-path security
  test suite was re-run against current `main` and the README records the
  2026-10-06 result. `--validate-package` was confirmed to already pass
  against the packaged example config.

### Changed
- **Every list tool with no upstream SDC pagination is now byte-budget
  paginated, not just `list_sdc_config_versions` (#172).** Each tool's
  arguments gained an optional `continuation_token`; `list_users_and_roles`
  pages its users and roles sub-lists independently against split halves of
  the shared budget, since they are two unrelated arrays rather than one
  `items` list (MEC-982).
- **Wholesale-redaction and denylist key-exemption rules now go through
  `mecmcp-redact`'s `Profile` hooks instead of a local implementation.**
  Behavior is unchanged; this is an internal consolidation onto the shared
  crate's extension mechanism (MEC-1244).
- **The pinned `mecmcp` release moved to `v0.26.0`.** Updates every file
  that pins or asserts the exact tag/commit: `Cargo.toml`/`Cargo.lock`,
  the dependency contract test, `docs/operations.md`, and the packaging
  scripts and CI checks that verify the BUILD-INFO `mecmcp_ref` and the
  shipped SBOM's `mecmcp-*` component versions.
- **The container image now pre-provisions its audit HMAC key.** The
  `rustsdcmcp` binary generates `--audit-hmac-key-file` on first run if it
  is absent or empty (mirroring `packaging/lxc/install.sh`'s own
  key-generation step), and the Dockerfile's `ENTRYPOINT` now always passes
  `--audit-hmac-key-file /var/lib/rustsdcmcp/audit-hmac.key`. Previously the
  container image ran with no HMAC key configured at all, unlike the LXC
  package of the same binary (mecmcp#376 / MEC-978). `--audit-redact`
  itself still defaults to empty — redaction stays opt-in — so this alone
  does not change what is logged; an operator who now turns on `=hmac`
  redaction no longer hits a key-file error on the first restart.

### Added
- `list_users_and_roles` (MEC-224): read-only, metadata-only tenant users and
  roles (`ListUsers`/`ListRoles`), for SOC incident review ("who has
  access") without a portal session. Narrows CLAUDE.md's IAM exclusion
  (decision #34) to these two read operations only; `CreateUser`, `EditUser`,
  `DeleteUser`, `ChangePassword`, and `SendActivateUserEmail` stay excluded.
  Excluded from a wildcard tool scope like a write tool — an existing bearer
  token must name it explicitly.
- `egress_proxy`: optional explicit HTTP(S) forward-proxy setting for
  outbound SDC traffic. Unset by default — the client never autodiscovers a
  proxy from environment variables, and the SDC endpoint stays fixed either
  way. See `docs/operations.md#explicit-egress-proxy`.
- `--enable-metrics`, `--max-requests-per-second-per-ip`,
  `--max-request-burst-per-ip`, `--max-requests-per-second-per-token`, and
  `--max-request-burst-per-token` flags (MEC-347). Metrics and rate limits
  were previously hardcoded (`false`, unbounded) with no way for an operator
  to change them. Rate limits are now on by default without operator
  action; `/metrics` stays off by default and is an explicit opt-in. See
  `docs/operations.md`.

### Fixed
- A `GET` rate-limited or overloaded by SDC (`429`/`503`) is now retried,
  honouring `Retry-After` when SDC sends one, with jitter and a capped
  number of attempts, instead of failing immediately. Writes are unaffected
  and still never retry automatically — a mutation must not be silently
  resent into an unknown state.

### Changed
- **Container images now publish to `ghcr.io/mechubsec/rustsdcmcp`** —
  the repo moved to the mechubsec organization, and images are renamed to
  match. Older tags were copied from the previous name.

### Security
- Bumped `mecmcp` to v0.24.0. `approve_sdc_change_set` now refuses an
  approval unless the approver's actor type is `Human` — an agent-minted
  token or an unattributed stdio caller can no longer stand in as the
  independent second principal on a change set, closing the gap where only
  self-approval (not actor type) was checked. `/healthz` and `/readyz` are
  now mounted, both unauthenticated and returning no device or customer
  data.
  **Upgrade note:** existing approver tokens minted without
  `--actor-type human` will be refused; re-mint them with the flag before
  they are next used to approve a change set.
- ICAP server passwords (`password_ascii`, `password_base64`) are redacted from
  `list_sdc_resources` / `get_sdc_resource`. The spec declares them; the lab
  tenant has not been checked for them.
- Site PSKs (`psk`, `pre_shared_key`) and rendered device-config bodies
  (`site_config`, `cpe_config`) are redacted from `list_sdc_sites` /
  `get_sdc_site`. SDC-generated IPsec config embeds the IKE PSK, so both config
  bodies are withheld as a whole.

### Fixed
- `list_sdc_tunnels` now sends `spec.from`/`spec.size`. The unprefixed
  parameters were ignored, so `size` did not bound the response.
- An explicitly configured `--tokens-file` is now the primary token store, never
  shadowed by a file at the canonical location (#162). The old code treated both
  the canonical `/var/lib/rustsdcmcp/tokens.json` and the legacy
  `/etc/rustsdcmcp/tokens.json` the same way: when either path was configured, it
  called the fallback logic that prefers canonical over legacy. An empty
  canonical file (even `{"version":1,"tokens":[]}`) shadowed an explicitly
  configured legacy store, rejecting all bearer tokens. The configured path is
  now used verbatim unless it is byte-exactly the canonical path, in which case
  the legacy fallback applies. This matches rust-junosmcp's behaviour.

### Added (#156)
- 12 read tools: `list/get_sdc_sites` (PSKs redacted), IPS rule and exempt-rule
  list/get, ECF rule-set and rule lists, three global-settings singletons, and
  `list_sdc_device_global_settings`.
- **Operators:** tokens minted with explicit tool lists do not gain these tools.
  Re-mint or widen scopes to use them. Tokens with a wildcard read scope DO gain
  the new tools, including `list/get_sdc_sites`, whose output is redacted but
  still exposes topology (private_nets, IKE IDs, tunnel peer addresses).

### Added (#155)
- 7 read tools: device config section list and revision read, image definition
  list and job status read, MNHA sync status, and RMA state and reactivation
  status reads. `get_sdc_rma_state` redacts `missing_licenses` values (the count
  is preserved).
- **Operators:** tokens minted with explicit tool lists do not gain these tools.
  Re-mint or widen scopes to use them. Tokens with a wildcard read scope DO gain
  the new tools.

### Changed
- CI: weekly upstream spec-drift check and a per-PR check that every called path exists in the vendored spec (#154).
- Raised MSRV from 1.88 to 1.89.

## `v0.0.5` — 2026-09-16

### Changed

- **`rustls` 0.23.44 -> 0.23.45**, closing **RUSTSEC-2026-0285** (#146). TLS 1.3
  handshake messages accepted across encryption-level boundaries, CVSS 5.3.
  This is the reason this release exists.
- **`rmcp` 3.2.0 -> 3.4.0** (#147), incorporating the `ServerInfo` to
  `ServerConfig` rename. No source change was required; the server does not
  construct or inspect these types.

### Documentation

- **HOW-TO-SETUP-LXC now documents how to build a rustsdcmcp container** (#138),
  and lets the packager use a CI-built binary instead of requiring a local build.

### Dependencies

- `reqwest` 0.13.4 -> 0.13.5 (#143)
- `uuid` 1.26.0 -> 1.26.1 (#144)
- `toml` 1.1.5+spec-1.1.0 -> 1.1.6+spec-1.1.0 (#141)
- `futures` 0.3.33 -> 0.3.34 (#134)
- `distroless/cc-debian13` base image updated (#139)
- `rust` toolchain image updated (#140)

**This release contains no behavior change beyond the dependency updates.**

## `v0.0.4` — 2026-09-06

### Changed

- **Shipped systemd unit now documents the fleet seccomp posture** agreed in
  mecmcp#354. Added a comment explaining why `SystemCallErrorNumber=EPERM` must
  not be removed: without it systemd's default raises SIGSYS and kills the
  process mid-request, which is what happened to rustunifimcp during a
  change-set state write (mecmcp#351). This server was not affected precisely
  because it already sets EPERM, and that is why the line must stay. The comment
  also notes that an EPERM denial is silent at the systemd layer; the only place
  it can become visible is the application, which must stop discarding the errno.

## `v0.0.3` — 2026-09-05

### Changed

- **`mecmcp` 0.23.0 -> 0.23.1** (mecmcp#351), pinned across all eleven files.
  Currency update: removes an unnecessary `chown` syscall from the change-set
  state write path by skipping it entirely when the replacement file's
  ownership already matches the destination's. When the owners genuinely differ
  the call still happens, so the fix is conditional rather than universal.
  
  rustsdcmcp itself was unaffected: LXC 951 (`prod-sdcmcp`) runs
  `SystemCallFilter=~@privileged` with `SystemCallErrorNumber=EPERM`, so the
  denied `chown` returns an error the `let _ =` swallows rather than killing
  the process. Verified live: the 0.0.2 production binary (mecmcp v0.23.0) was
  driven through `prepare_sdc_object_write` on LXC 615 `test-labmode-sdc`
  (identical unit) against an already-existing `changeset-state.json` — the
  exact branch that takes the `chown` — and the write landed without restart or
  `status=31/SYS`.

## `v0.0.2` — 2026-09-01

### Changed

- **`mecmcp` 0.21.0 -> 0.23.0** (#124), in every file that pins it exactly,
  plus the pinned upstream commit in the dependency-contract test. 0.23.0 binds
  a change set's preview digest into its approval digest, so an approval
  vouches for the exact preview a reviewer saw, and the coordinator refuses any
  write that swaps or drops a preview once an approval exists. No source change
  was needed here: this repository does not construct `ApprovalRecord` and does
  not call the renamed digest helpers.
- Dependabot weekly workflow no longer attempts to bump the git-pinned `mecmcp`
  crates (#129), which failed every week because a registry crate cannot depend
  on a git source.

### Fixed

- **The operations doc no longer names a specific deployment host** (#123),
  which was decommissioned in the 2026-08-12 VMID renumber. Instructions now
  use `your-deployment-host` as an operator-supplied placeholder.
- **SSH tunnel systemd unit template that fails closed** (#123). The new
  `packaging/systemd/rustsdcmcp-tunnel.service.example` sets start-limit keys
  in the correct `[Unit]` section (not `[Service]`, where they are parsed but
  ignored), uses explicit `ConnectTimeout` and restart counts that actually
  trip the limit instead of retrying forever, binds loopback explicitly,
  disables `~/.ssh/config` inheritance via `-F /dev/null`, and is verified by
  `systemd-analyze verify --user` to prevent silent regressions.

### Dependencies

- `uuid` 1.25.0 -> 1.26.0 (#128)
- `syn` 3.0.3 -> 3.0.4 (#127)
- `distroless/cc-debian13` base image updated (#126)
- `rust` toolchain image updated (#125)

## `v0.0.1` — 2026-08-28

The first release not marked as a prerelease, cut from the surface that
`v0.1.0-lab.10` carried plus the dependency and packaging work below. **The version number moves
down**, from the `0.1.0` the lab archives declared to `0.0.1`, because the
earlier number described a release that was never cut. Nothing in the tool
surface was removed to justify it.

### Changed

- **Version `0.1.0` -> `0.0.1`** across the workspace, the `Cargo.lock`, and
  the packaging chain. The archive is now
  `rustsdcmcp_0.0.1.<date>.<source-commit-12>_amd64.tar.gz`; the `-lab.`
  infix is gone, `BUILD-INFO` carries `version=0.0.1` and
  `release_status=release` instead of `lab-only`, and `packaging/lxc/install.sh`
  asserts both new values. An older archive will **not** install under this
  installer, and vice versa — the assertions are exact-match by design.
- **`scripts/build-lab-package.sh` is now `scripts/build-package.sh`.** Any
  local automation calling the old path breaks; there is no shim.
- **`mecmcp` 0.19.0 -> 0.21.0**, in the ten files that pin it exactly.
- The CI package steps and the uploaded artifact drop their `lab` naming
  (`rustsdcmcp-<sha>`, was `rustsdcmcp-lab-<sha>`).

### Fixed

- **The yanked `chacha20` 0.10.1 is out of the lockfile** (#120). It arrives
  through `rand` -> `rmcp` -> `mecmcp-server`, so nothing here selected it
  directly, and `cargo-deny`'s advisories check fails on a yanked crate. `main`
  looked green only because its last run predated the yank.

### Documentation

- The README describes a release rather than a private prerelease, and its
  stale claims are corrected: **54 tools (40 read, 14 change-control)**, not
  48; the pinned build toolchain is **1.98.0** with MSRV 1.88, not 1.88 for
  both; `mecmcp` is pinned at **v0.21.0**, not v0.8.0. The roadmap no longer
  lists the container image or the shared change-set CLI standard (#54) as
  outstanding — both shipped.

## `v0.1.0-lab.10` — 2026-08-25

Measured against the preceding **`v0.1.0-lab.9`** tag, not against intermediate
untagged commits. The **Unreleased** block below is byte-identical to lab.9 and
therefore describes surface that tag already carried — it does not cover
anything in this release.

### Added — action required for existing tokens

- **`prepare_sdc_device_inventory_sync` and `apply_sdc_device_inventory_sync`**
  (#21) take `KNOWN_TOOLS` from 52 to 54. Both are **write** tools, gated by a
  change set. They reconcile *inventory*, not configuration.

  **Existing bearer tokens will not see them until re-minted.** Tokens carry
  explicit tool scopes, so a token issued against lab.9 keeps working for the
  52 tools it names and silently omits the two new ones — which presents as a
  broken upgrade rather than as a scoping decision.

- **Templates as a read family** (#33).
- **Three residual read families** that fit the generic resource pair, with the
  four that do not documented rather than forced (#83).
- **SSDF evidence pipeline** (mecmcp#292), flushed even when serving ends in an
  error.

### Fixed

- **`get_sdc_change_set_details` works at all** (#81). It was created keyed by
  tenant and looked up by endpoint, so it could never find a change set.
- **License write-path before-state is projected to callers** (#55), and an
  unprojectable before-state is now withheld rather than failing the call.
  Previously the raw upstream before-state bypassed the read-path allowlist.
- A `2xx` whose body could not be read is treated as the sync having landed,
  and the job id and per-device results survive acceptance (#21).
- The installer `chmod`s only files that actually exist during a legacy
  upgrade.
- The packaging SBOM check rejects duplicate members instead of chasing
  encodings, closing a duplicate-key bypass.

### Security

- **Tier-2 hardening.** `tokens.json` moves to `/var/lib/rustsdcmcp`, the unit
  gains `--audit-log-file $STATE_DIRECTORY/audit.jsonl`, stale secrets are
  scanned for, and the container image is built and checked in CI.

  The systemd unit's *sandboxing* is unchanged: `NoNewPrivileges`,
  `ProtectSystem`, `PrivateDevices`, namespace restrictions and syscall filters
  were already present at lab.9. Named here only so this entry is not read as
  claiming they arrived in lab.10.
- **The legacy token store is no longer shadowed by an empty one.** An upgrade
  that found an empty primary could mask a populated legacy store, which reads
  as "every credential was rejected" rather than as a packaging fault.

### Changed

- **`mecmcp` 0.11.0 -> 0.19.0.** That is the jump from the lab.9 baseline;
  0.17.0 was an intermediate untagged step. This repo pins mecmcp at an exact
  version in **ten** files — `Cargo.toml`, `Cargo.lock`,
  `crates/rustsdcmcp/tests/mecmcp_dependency_contract.rs`,
  `crates/rustsdcmcp/tests/sbom_validation.rs`,
  `crates/rustsdcmcp/src/main.rs`, `.github/workflows/ci.yml`,
  `scripts/verify-packaging.sh`,
  `scripts/build-lab-package.sh`, `packaging/lxc/install.sh`, and
  `packaging/tests/package-smoke.sh` (which hard-codes the BUILD-INFO and SBOM
  versions on top of the package set). The guards are exact, so a partial bump
  fails the build rather than shipping a mixed package.
- `rmcp` 3.1.1 -> 3.1.4.
- Pinned toolchain moved to 1.98.0, with a CI toolchain-pin guard and a PR
  image build. The Docker builder must match the pin rather than drift ahead.
- Dependabot now watches the Dockerfile.

### Documentation

- Recorded what this server is not for (#34), and why the distroless image has
  no `HEALTHCHECK`.

## `v0.1.0-lab.9` — 2026-08-19

### Added

- 24 read-only resource families on the generic `list_sdc_resources` /
  `get_sdc_resource` pair, covering every uniform five-operation collection in
  the pinned spec that was not already exposed: AAMW, anti-spam, anti-virus,
  content-filtering, content-security, enhanced content-filtering, flow-based
  antivirus, ICAP profiles and servers, identity objects, IPS profiles, IPS
  signatures, proxy servers, redirect profiles, rule options, SecIntel profiles
  and groups, SSL initiations, SSL proxy profiles, SWP profiles, URL category
  lists, URL patterns, variable zones, and web-filtering profiles.
- A `fields` projection on `list_sdc_resources`, matching `list_device_groups`.
  Profile families embed rule and pattern lists, so `size` alone does not bound
  the response.

### Changed

- The resource catalog is split by capability. `ResourceKind` is the read
  catalog; the new `WritableResource` is the write catalog and still holds
  exactly four families. The conversion goes one way only, and the gate sits on
  `SdcClient`, so adding a readable family cannot compile into a writable one.

### Notes

- **No token re-mint is required.** No tool was added, removed, or renamed, so
  an existing scoped token still matches the surface. This is unlike the last
  three releases, where new tools were invisible to tokens minted earlier.
- The new families are verified for **authentication and dispatch only**. The
  lab tenant holds no security-profile objects, so no live response payload has
  been observed for any of the 23. Payload shape stays unverified.

## `v0.1.0-lab.7` — 2026-08-13

Phase A of the completion plan: the four change-control defects.

### Changed

- **Previews are now requested as XML, and this changes what a reviewer
  reads.** `GET /api/v1/policies/preview/{id}/devices/{id}` accepts a `format`
  parameter — `CLI` (the default) or `XML` — and this client never passed it.
  The CLI rendering omits parent objects that XML names: the same preview
  rendered 273 bytes naming one deletion in CLI and 570 bytes naming two in
  XML, the second being a `<feed-server operation="delete">`. Since the preview
  digest is computed over that artifact, an approver could be shown less than
  the change (#66).

  SDC was never concealing anything — its XML answer was always complete. This
  client digested the lossy rendering of it. Verified live: the parent object
  now appears in the digest-bound artifact.

### Added

- `discard_sdc_operation`, which clears a terminal-but-unreconciled operation
  (#63). A failed deploy previously refused **every later apply on the tenant**,
  and the only remedy was editing `changeset-state.json` on a running
  deployment. Owner-only, fingerprint-bound, and in `WRITE_TOOLS` so a wildcard
  token scope cannot reach it. The failed operation stays visible: this
  unblocks applies, it does not erase the failure.

  Exposing the upstream call alone would not have worked, and would have made
  things worse. It invokes `transaction.rollback`, which returned an error that
  the caller converts to `Indeterminate` — a state that can never be discarded.
  `SdcTransaction::rollback` now reports truthfully first, since SDC reverts the
  device itself on a failed deploy.

  **The tool surface is now 51.** A token minted against the previous 50 will
  not see this tool until re-minted; tool scopes are explicit allowlists.

### Fixed

- Refuse a `DEVICE_GROUP` deploy target locally instead of sending a request
  SDC rejects (#61). The pinned spec marks the target type "Not supported,
  future support", so the refusal happens before a preview job is spent and
  names the limitation. One guard and one call site, deletable when SDC
  supports it.

## `v0.1.0-lab.6` — 2026-08-12

### Added

- Device group read tools: `list_sdc_device_groups` and `get_sdc_device_group`
  (#34). The tool surface is now 50: 39 reads and 11 change-control tools.

  **Anyone holding a token minted against the previous 48 must re-mint it.** A
  token's tool scope is an explicit allowlist of names, so an upgrade that adds
  tools leaves existing tokens seeing exactly what they saw before. The new
  tools simply do not appear, which looks like a failed deployment and is not.

### Documentation

- Show how to enable `--lab-mode`, which the previous release documented the
  meaning of without ever showing the invocation. `--lab-mode` is CLI-only:
  unlike `--state-file` and `--approval-timeout-secs` it has no `sdc.json`
  fallback, deliberately.
- Record that a policy deploy **deletes template-placed configuration** that no
  imported policy references, confirmed by a committed apply (#33). Template
  origin confers no protection, so the co-management boundary in #23 stands and
  templates are not a remedy for it.
- Record that **a deploy can commit more than its preview disclosed** (#66). In
  the observed case the preview named one object and the commit removed two,
  with the omitted object absent from the digest-bound artifact entirely. The
  change-set binding behaved correctly; what it bound did not describe the whole
  change. Treat a preview as a lower bound until the conditions are understood.
- Record the undocumented custom-template upload schema, and an edge WAF that
  rejects a template body containing `http://` plus an RFC1918 address.
- Record that `DEVICE_GROUP` is not a supported deploy target — the pinned spec
  marks it "not supported, future support" — correcting a claim in #34 (#61).

## `v0.1.0-lab.5` — 2026-08-12

### Added since `v0.1.0-lab.4`

- Certificate and licence tools: six read operations and eight write operations
  under change control (#32).
- IPsec profile and tunnel read tools (#28).
- Firewall and NAT policy rule read tools (#25), NAT pool read tools (#30), and
  NAT policy authoring under change control (#27).
- Firewall policy write tools under change control (#24, partial).
- Object authoring for address, application, service, and scheduler objects
  under change control (#29).
- `get_sdc_change_set_details`, which recovers a preview digest that is
  otherwise returned only once by prepare and cannot be recomputed (#22).
- An allowlist projection over the certificate and licence read tools, applied
  at the MCP boundary so change-control drift detection keeps full-fidelity
  state (#50).

### Changed since `v0.1.0-lab.4`

- Adopt the shared `mecmcp` change-set CLI standard: `--lab-mode`,
  `--state-file`, and `--approval-timeout-secs`, with explicit CLI beating
  product configuration and neither silently relocating an existing
  deployment's state file (#54). Parsing through `parse_with_provenance` also
  repairs `--version`, which previously failed as an unknown argument and is
  how a deployment identifies the build it is running.
- Wire `--lab-mode` through to the change-set coordinator. Setting the flag
  alone was not enough: nothing called the waiver, so a single operator still
  could not move a plan past `Planned`. The waiver is now applied at change-set
  creation, records `approver: null` with `approval_waiver: "lab-mode"`, and
  never fabricates an approver.
- Refuse `--approval-timeout-secs 0`, which expired every change set at
  creation and disabled the entire write surface.

- Adopt mecmcp 0.8.0 and its generic scope preflight; adopt 0.7.2 and delete the
  local compatibility transport copies (#36). This removed the last temporary
  compatibility symbols and the ledger tracking them.

### Fixed since `v0.1.0-lab.4`

- Attribute an `expected_preview_digest` mismatch to that argument by name. The
  error previously blamed the wrong input, sending an operator to inspect a
  value that was correct.

### Documentation since `v0.1.0-lab.4`

- Record live-observed SDC API behaviour verified against a real tenant: the
  certificate and licence field sets and their date-format and sentinel traps,
  device sync direction, and what a template is and can express. Device sync
  **imports** rather than pushes, but reconciles inventory only and does not
  clear `OUT_OF_BAND_CHANGED` (#21, #33, #50).
- Document SDC co-management and destructive deploy behaviour: a policy deploy
  removes device configuration SDC does not model (#23).
- Document response-shape mismatches observed live (#26).
- Correct release claims across README, CHANGELOG, and the operations guide.
  Five places asserted a compatibility blocker that cleared in #36/`369f9bb`,
  and the README denied a live policy deploy that had in fact happened and is
  the reason #23 exists.
- Document `--lab-mode`, what it weakens, and why two tokens are preferable
  where the ceremony has value.

## `v0.1.0-lab.4` — 2026-08-05

- Generate the package README instead of copying the repository one. Every
  archive previously shipped download instructions for the *previous* release,
  because a release is built from a commit predating the docs describing it
  (#15).
- Point the release documentation at `v0.1.0-lab.3` (#14).

## `v0.1.0-lab.3` — 2026-08-05

Released the work recorded below under "Fixed since `v0.1.0-lab.2`" and
"Added".

### Fixed since `v0.1.0-lab.2`

- Refuse `--tokens-file` together with `--allow-no-auth`. The pair previously
  fell through to a catch-all arm that dropped the token store, producing an
  unauthenticated listener on any bind address with no diagnostic.
- Bind tool calls to the per-request cancellation token. Every tool previously
  built a fresh token, so the cancellation plumbing threaded through the client
  was connected to nothing and no client cancellation or shutdown could
  interrupt an SDC call or job poll.
- Abort in-flight SDC work on SIGTERM/SIGINT, and drain both listeners behind a
  single forced deadline. Streamable HTTP sessions end on the process token and
  stdio uses `serve_with_ct`, so a signal during the handshake exits cleanly
  instead of reporting a startup failure.
- Preserve SDC job statuses this build does not recognize instead of failing the
  whole read, keeping the vendor's own string in the audit and preview
  artifacts. Unrecognized states are never terminal and never successful.
- Digest the prepared-change envelope once per apply rather than four times.
- Exclude nested checkouts from the SBOM scan; a git worktree under the repo
  root made local package builds impossible.
- Scope workflow `push` triggers to `main`, halving Actions minutes for
  identical checks.

### Added

- systemd egress policy denying the cloud metadata endpoints, with
  `IPAccounting=yes` and an installer probe reporting whether the filters are
  actually enforced. These directives are defence in depth only: systemd
  implements them with cgroup eBPF and fails open where it cannot attach, which
  includes the recommended unprivileged LXC.
- Per-runtime guidance for enforcing egress where systemd cannot, plus a
  verification command that distinguishes a blocked route from an unprobed one.
- Assertions that the tool registry matches the registered router, that a
  tampered prepared-change envelope is refused at the trust boundary, and that
  an injected credential field is rejected.


- Add the Rust workspace and Security Director Cloud MCP binary.
- Add bounded device, policy, shared-object, and asynchronous-job read tools.
- Add preview-bound two-person policy deployment through `mecmcp-changeset`.
- Add shared `mecmcp` auth, audit, server, transport, runtime, and TLS
  composition.
- Add fixture tests, configuration example, operations guide, and security
  policy.
- Add Rust 1.97/MSRV 1.88, packaging, and security CI gates for the lab-only
  package.
- Document the lab artifact workflow, loopback-only listener, token ownership,
  journald forwarding exception, and the public-release compatibility blocker.
- Bind each lab package, checksum, and CI upload to its exact full source
  commit directory; require a Cargo-derived CycloneDX SBOM.
- Fail closed for staged live-installer tests and harden commit artifact output
  directories, SBOM metadata, and upload allowlists.
