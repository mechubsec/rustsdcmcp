<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rustsdcmcp</h1>

<p align="center"><strong>Async Rust Model Context Protocol server for HPE Juniper Security Director Cloud</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This is an independent community project
> and does not claim affiliation with or endorsement by Hewlett Packard
> Enterprise or Juniper Networks. Product names and trademarks are used only to
> identify the systems with which the software interoperates.

---

`rustsdcmcp` exposes HPE Juniper **Security Director Cloud** (SDC) to MCP
clients as a bounded, auditable tool surface. SDC is the HPE Juniper SASE
portal for an SRX estate, so this server talks to that management plane rather
than to any single firewall. Where
[`rustjunosmcp`](https://github.com/mechubsec/rustjunosmcp) talks NETCONF to
individual SRX devices, `rustsdcmcp` talks HTTPS REST to the portal that governs
them.

That distinction has a large blast radius: one SDC action can affect many
managed SRX devices. Strict approval, credential-safe attribution, and bounded
I/O therefore protect the management plane rather than merely decorate it.

## Current status

`rustsdcmcp` exposes **73 MCP tools** (on `main` and unreleased branches; v0.0.5
shipped 54): 59 bounded read tools and 14 change-control tools. The surface
covers the part of the SDC API that manages SRX devices and their policy; the
rest of the product's API is deliberately out of scope.

Every mutation is reachable only through prepare → independent approval →
apply. A wildcard token scope deliberately grants no write tool, so each must be
named explicitly when a token is minted.

Live validation against SDC has gone well beyond read-only. On 2026-08-07 a
full `prepare → approve → apply` policy deploy ran against the lab tenant and
reached a managed vSRX, which is how the co-management behaviour in #23 was
discovered: within hierarchies SDC owns, objects **not reachable from a policy
SDC imported** are deleted on deploy. Interfaces, routing, `system`, and the
management instance were untouched. The full boundary and the observed diff are
in [`docs/operations.md`](docs/operations.md). `JobStatus` and
`DeviceStatusEntry` are validated against live preview and deploy responses.

On 2026-08-12 the certificate and licence readers, `BulkSyncDevices`, and the
template endpoints were exercised live. Device sync **imports** into SDC rather
than pushing to the device, but reconciles inventory only and does not clear
`device_config_state: OUT_OF_BAND_CHANGED`.

Read-path security properties were last verified live on 2026-08-07 against
commit `ea81805d2b4b97df9bdd3f70423e047524896a3d` with `mecmcp` `v0.5.0`. The
transport and scope preflight were replaced afterwards in `e28d0cc` and
`369f9bb`, so that result no longer speaks for current `main`; no lab SDC
tenant was available to repeat it live. On 2026-10-06, against commit
`2036523` with `mecmcp` `v0.26.0`, the automated integration suite that
encodes the same properties was re-run instead — `cargo test --workspace`,
258 passed, 0 failed, covering: credential-based startup tenant validation
(`crates/rustsdcmcp-core/tests/contracts.rs`), a scoped grant exposing exactly
its permitted tools and no write tools and `401` for missing and invalid
bearers (`crates/rustsdcmcp/tests/http_boundary.rs`), and HMAC-redaction of
sensitive fields (`crates/rustsdcmcp-core/src/redact.rs` unit tests). This
confirms the properties hold at the integration-test level on current `main`;
it is not a substitute for the live-tenant exercise and does not re-establish
one.

Observed response shapes and the remaining endpoint questions are tracked in
[`docs/sdc-api/README.md`](docs/sdc-api/README.md#still-unverified).

## Download

Assets for the current release are on the
[`v0.0.5` release page](https://github.com/mechubsec/rustsdcmcp/releases/tag/v0.0.5).
The Debian archive is commit-addressed and ships with a sibling `.sha256`:

```console
gh release download v0.0.5 \
  --repo mechubsec/rustsdcmcp \
  --pattern 'rustsdcmcp_0.0.5.*_amd64.tar.gz*'
sha256sum -c rustsdcmcp_0.0.5.*_amd64.tar.gz.sha256
```

Take the expected checksum from the release page over an authenticated
connection. A `.sha256` carried alongside the tarball only proves that the two
files agree, so it is not independent evidence of either.

A `linux/amd64` container image is published for the same tag to
`ghcr.io/mechubsec/rustsdcmcp:0.0.5`.

## Build from approved source

`rust-toolchain.toml` pins the build toolchain at 1.98.0; the declared MSRV in
`Cargo.toml` is 1.89. Operators must bind their checkout to the commit they
intend to ship before building, testing, or packaging — the release tag is the
usual choice:

```console
approved_commit=$(git rev-parse v0.0.5^{commit})
git checkout --detach "$approved_commit"
test "$(git rev-parse HEAD)" = "$approved_commit"
cargo build --release --locked
cargo test --workspace --locked
scripts/build-package.sh
cp examples/sdc.example.json /secure/operator/path/sdc.json
```

In that configuration, `credential_env` names the external process variable;
the credential itself never belongs in JSON. For a local commit-addressed
package, verify the newly built archive and its embedded `BUILD-INFO` from the
approved commit directory—never glob across `dist/` because the checksum
records only the archive basename:

```console
artifact_dir="dist/$approved_commit"
mapfile -t archives < <(find "$artifact_dir" -maxdepth 1 -type f -name 'rustsdcmcp_*_amd64.tar.gz' -print)
test "${#archives[@]}" -eq 1
archive="${archives[0]}"
(cd "$artifact_dir" && sha256sum -c "$(basename "$archive").sha256")
package_root=$(tar -tzf "$archive" | sed -n '1s#/.*##p')
test -n "$package_root"
tar -xOf "$archive" "$package_root/BUILD-INFO" | grep -Fx "git_commit=$approved_commit"
```

## Docker quick start

For running the published container image, see [HOW-TO-SETUP-DOCKER.md](docs/HOW-TO-SETUP-DOCKER.md).

## Debian 13 LXC quick start

For building an LXC from scratch, see [HOW-TO-SETUP-LXC.md](docs/HOW-TO-SETUP-LXC.md).

Prerequisites:

- Debian 13 AMD64; an unprivileged LXC is recommended.
- 1 vCPU, 512 MiB RAM, 512 MiB swap, and 4 GiB disk for the minimum profile.
- Working DNS and time synchronization, plus outbound HTTPS to
  `api.sdcloud.juniperclouds.net`.
- Root or equivalent operator access inside the LXC.

After downloading the release assets, install the verified package:

```bash
set -euo pipefail
mapfile -t archives < <(find . -maxdepth 1 -type f -name 'rustsdcmcp_0.0.5.*_amd64.tar.gz' -print)
test "${#archives[@]}" -eq 1
archive="${archives[0]}"
sha256sum -c "$archive.sha256"
package_root=$(tar -tzf "$archive" | sed -n '1s#/.*##p')
test -n "$package_root"
tar -xzf "$archive"
sudo "$package_root/packaging/lxc/install.sh"
```

Create the configuration and credential file without exposing a credential:

```bash
sudo install -o root -g rustsdcmcp -m 0640 \
  /etc/rustsdcmcp/sdc.json.example /etc/rustsdcmcp/sdc.json
sudoedit /etc/rustsdcmcp/sdc.json
sudo install -o root -g root -m 0600 /dev/null \
  /etc/rustsdcmcp/credentials.env
sudoedit /etc/rustsdcmcp/credentials.env
```

`sdc.json` must retain the HTTPS SDC endpoint, use the desired local tenant
alias, and set `expected_tenant_id` to the operator-obtained SDC tenant ID. The
credentials file contains one shell-compatible assignment using the name from
`credential_env`, for example `SDC_API_TOKEN=...`; never put a real value in
the README or JSON.

Create the initial exact 14-tool read-only grant. The redirect destination must
already be mode `0600`; the output is a one-time bearer token.

```console
sudo /usr/local/bin/rustsdcmcp token add \
  --tokens-file /etc/rustsdcmcp/tokens.json \
  --device-mapping /etc/rustsdcmcp/sdc.json \
  --name sdc-read \
  --devices production \
  --tools get_sdc_tenant_scope,list_sdc_devices,get_sdc_device,list_sdc_firewall_policies,get_sdc_firewall_policy,list_sdc_nat_policies,get_sdc_nat_policy,list_sdc_resources,get_sdc_resource,get_sdc_preview_status,get_sdc_deploy_status,get_sdc_preview_device_result,get_sdc_deploy_device_result,get_sdc_change_set \
  --actor-type human > /secure/local/path/rustsdcmcp-sdc-read-token
```

Start the service and access it through an authenticated SSH tunnel:

```console
sudo systemctl enable --now rustsdcmcp.service
sudo systemctl --no-pager --full status rustsdcmcp.service
sudo ss -ltnp 'sport = :30032'
ssh -N -L 30032:127.0.0.1:30032 root@your-deployment-host
```

The expected listener is only `127.0.0.1:30032`. While the tunnel is active,
the local MCP client uses `http://127.0.0.1:30032/mcp`. Each installation
supplies its own SSH host; the server is never exposed directly.

## Security commitments

- External credentials use restrictive file modes and never belong in JSON.
- Startup verifies the configured identity against `expected_tenant_id`.
- Bearer tokens carry exact tool and tenant scopes.
- Request, response, and page sizes are bounded.
- Audit attribution is credential-safe and target values receive HMAC redaction.
- Mutations require two-principal prepare → approve → apply change control.
- There is no direct deploy tool and no unauthenticated write path.
- A wildcard token scope grants **no** write tool. `--tools '*'` yields the read
  surface only; every write tool must be named explicitly when minting a token.

Detailed deployment, recovery, audit-retention, and write-workflow guidance is
in [`docs/operations.md`](docs/operations.md).

### `--lab-mode`

`--lab-mode` waives the second principal, for a single-operator lab where
two-person control is theatre rather than a control. **It is off by default and
should stay off anywhere the estate matters.**

What it does and does not change:

- The waiver is applied automatically when the change set is created. There is
  no waive tool, and the flow stays prepare → apply, identical to production.
- Planning, the plan digest, drift detection, and apply-time revalidation all
  still run. Lab mode removes the *second reviewer*, not the change record.
- **No approver is ever fabricated.** A waived change set records
  `approver: null` alongside `approval_waiver: "lab-mode"`, and carries a
  waiver digest over `(change_set_id, plan_digest, owner, approved_at)`. It is
  cryptographically distinguishable from a genuine two-person approval and
  cannot be relabelled afterwards — which matters if anyone later has to prove
  which changes had real separation of duties.
- The server warns loudly at startup whenever it is enabled.

If you want solo write-testing *without* waiving the control, mint two tokens
with different names and use one to prepare and the other to approve: the
principal is the token name, and self-approval is refused. That gives one person
the complete lifecycle with the control intact, and is the better choice
wherever the ceremony has any value.

#### Enabling it

Add the flag to the service unit. On a package install, use a drop-in rather
than editing the shipped unit, so an upgrade does not silently drop it:

```console
sudo systemctl edit rustsdcmcp
```

Replacing `ExecStart` means restating it in full, so **copy the shipped
command and append the flag** rather than writing a shorter one. Dropping the
`--audit-*` arguments would turn off HMAC target redaction and structured
journald auditing as a side effect of enabling lab mode:

```ini
[Service]
# Clear the shipped ExecStart before replacing it; systemd appends otherwise.
ExecStart=
ExecStart=/usr/local/bin/rustsdcmcp \
    --device-mapping /etc/rustsdcmcp/sdc.json \
    --transport streamable-http \
    --host 127.0.0.1 \
    --port 30032 \
    --tokens-file /etc/rustsdcmcp/tokens.json \
    --audit-format json \
    --audit-journald \
    --audit-redact devices=hmac \
    --audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key \
    --lab-mode
```

Check it against `packaging/systemd/rustsdcmcp.service` before applying it — the
shipped arguments are the authority, and this snippet is a copy that can age.

```console
sudo systemctl daemon-reload && sudo systemctl restart rustsdcmcp
```

Confirm it took effect. The two startup records use different spellings —
`--lab-mode` in the warning and `lab_mode` in the resolved-configuration line —
so match both, and read the journal with enough privilege to see a system unit:

```console
sudo journalctl -u rustsdcmcp -b | grep -E 'lab.mode'
{"level":"WARN","fields":{"message":"--lab-mode: two-person control is DISABLED. …"}}
{"level":"INFO","fields":{"message":"change-control configuration resolved","lab_mode":true,…}}
```

Silence means it is off. An unprivileged `journalctl` can also print nothing
here for lack of access rather than because the flag is unset, which is why the
command uses `sudo`.

A waived change set then reports `"state": "approved"` with `"approver": null`
and `"approval_waiver": "lab-mode"` straight out of `prepare_sdc_policy_deploy`,
and `apply_sdc_change_set` needs no separate approval call.

For a one-off run rather than a service, pass `--lab-mode` on the command line
the same way.

#### Precedence

`--lab-mode` is part of `mecmcp`'s shared change-set CLI standard, alongside
`--state-file` and `--approval-timeout-secs`. For those other two, an
explicitly supplied flag wins and `sdc.json` supplies the value otherwise
(`changeset_state_file`, `approval_ttl_secs`).

**`--lab-mode` is CLI-only.** There is no `sdc.json` field for it, deliberately:
a relaxed security control should have to be typed into the unit an operator can
see, not inherited from a configuration file edited months ago. Whether the
shared standard permits a product-config fallback is an open upstream question
(mecmcp#267); this server takes the conservative reading.

## Deployment maturity

The Debian 13 package has been installed and run end to end from the
commit-addressed archive built by CI for
`ea81805d2b4b97df9bdd3f70423e047524896a3d`. It starts under the packaged
`rustsdcmcp.service` unit as a non-root account, binds a loopback-only
endpoint, enforces the bearer boundary, and passes the startup tenant-scope
check against live SDC.

One packaging limit is worth stating plainly: the unit's `IPAddressAllow` and
`IPAddressDeny` lines take effect only where the host lets systemd attach its
cgroup BPF program, which is runtime-dependent. On the validated deployment the
installer probe reported `NOT ENFORCED`, so egress had to be enforced outside
the unit; every other sandbox directive still applied. Follow the probe's
result on your own host rather than assuming either way. Deployment, recovery,
audit-retention, and the per-runtime egress mechanism are in
[`docs/operations.md`](docs/operations.md).

Specific hosts, addresses, and container identifiers are deliberately not
published here; each operator supplies their own.

## Roadmap

`v0.0.1` is the first full release; everything before it was published as a
prerelease. It ships the Debian archive and a container image, and the shared change-set CLI standard — `--lab-mode`,
`--state-file`, `--approval-timeout-secs`, and a `--version` that answers — is
already adopted (#54). What remains:

1. Compose support with secret injection and health checks, on top of the
   published image.
2. Remote audit-journal forwarding, so the trail does not stay on the host that
   produced it.
3. Broader bounded live validation across the remaining read endpoints, with
   write workflows exercised only through approved change control.
4. Wider API coverage. The tool surface is a minority of the SDC API by
   design — subscriptions are excluded outright, and IAM is excluded except for
   the read-only, metadata-only `list_users_and_roles` tool (CLAUDE.md,
   MEC-224) — but several in-scope families are simply unbuilt.

## Relationship to `mecmcp`

[`mecmcp`](https://github.com/mechubsec/mecmcp) is the vendor-neutral Rust
foundation shared by the mechub MCP server family. This repository consumes it,
rather than forking it. `main` pins all eight shared crates — `mecmcp-audit`,
`mecmcp-auth`, `mecmcp-changeset`, `mecmcp-redact`, `mecmcp-runtime`,
`mecmcp-secret`, `mecmcp-server`, and `mecmcp-transport` — to `v0.26.0`.

**The compatibility blocker is cleared.** Earlier revisions of this section
said a release was blocked until 59 temporary compatibility declarations were
replaced by one coherent upstream release. That happened: the local `compat/`
layer was deleted in #36 on the move to mecmcp 0.7.2, and the compatibility
ledger itself was removed in `369f9bb` on the move to 0.8.0. There are no
temporary compatibility symbols left, and no ledger to track.

## API provenance

The API surface is pinned from Juniper's OpenAPI 3 export, vendored in
[`docs/sdc-api/`](docs/sdc-api/README.md). It is the authoritative inventory of
the supported SDC API surface and its remaining open questions.

Primary references:

- [Security Director Cloud API Reference](https://www.juniper.net/documentation/us/en/software/sd-cloud/api/http/getting-started/how-to-get-started)
- [API Security Overview](https://www.juniper.net/documentation/us/en/software/sd-cloud/sd-cloud-user-guide/user-guide/topics/concept/about-api-access.html)
- [Security Director Cloud documentation portal](https://www.juniper.net/documentation/product/us/en/juniper-security-director-cloud/)

## Audit forwarding to the event store

The audit trail does not stay on this host. This server follows the family
standard — [AUDIT-FORWARDING-STANDARD.md](https://github.com/mechubsec/mecmcp/blob/main/docs/AUDIT-FORWARDING-STANDARD.md).

An audit record that only exists on the machine that produced it is not an audit
trail: it is a log file on a box whose operator is the party the record is about.

### Emission (in effect now)

```
--audit-format json \
--audit-log-file /var/lib/rustsdcmcp/audit.jsonl
```

JSON is mandatory. The `text` format is for reading in a terminal and is not a
parse target. The file is the operator-facing artifact and must be rotated — the
server never truncates it.

### Transport

Records are written directly into SSDF's `ssdf.audit` as **hash-chained** rows,
per SSDF's merged evidence contract, so that deleting or editing a row is
detectable. This is implemented: the server wires an
`EvidenceService`/`EvidenceHttpTransport` pair at startup when evidence
forwarding is configured (`crates/rustsdcmcp/src/main.rs`), landed as the
SSDF evidence pipeline in
[mecmcp#292](https://github.com/mechubsec/mecmcp/issues/292).

A cheaper syslog path was designed and rejected: it works, but the records are
unchained, and every other link here is tamper-evident by construction — plan
digests bind approvals, approvals name a distinct principal, and
`token_verified_fields` separates vouched-for provenance from asserted. An
unchained final hop would discard that guarantee exactly where an auditor needs
it. The reasoning is recorded in the standard.

### Reading the result

`token_verified_fields` names the provenance fields the **token** vouched for.
The rest of that group — `client_name`, `model_id`, `session_id` — is
client-asserted and authenticated by nothing. Do not read them as equivalent.

`request_id` correlates the transport event, the handler event, and (on Junos)
the device commit comment.

## License

Licensed under [MIT](LICENSE).
