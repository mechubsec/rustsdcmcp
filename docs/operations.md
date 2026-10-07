# Operations

## Artifact boundary

Every archive is commit-addressed. It is named
`rustsdcmcp_0.1.0.YYYYMMDD.<source-commit-12>_amd64.tar.gz` and is paired
with a sibling `.sha256` file under `dist/<full-source-commit>/`. Select the
approved full source commit explicitly; never glob across `dist/`. The checksum
contains the archive basename, so verify it from that commit directory:

```console
source_commit="$(git rev-parse HEAD)"
artifact_dir="dist/$source_commit"
mapfile -t archives < <(find "$artifact_dir" -maxdepth 1 -type f -name 'rustsdcmcp_*_amd64.tar.gz' -print)
test "${#archives[@]}" -eq 1
(cd "$artifact_dir" && sha256sum -c "$(basename "${archives[0]}").sha256")
```

Current source pins all seven shared `mecmcp` crates — `mecmcp-audit`,
`mecmcp-auth`, `mecmcp-changeset`, `mecmcp-redact`, `mecmcp-runtime`,
`mecmcp-server`, and `mecmcp-transport` — to `v0.26.0`.
The immutable acceptance record for the
original lab deployment, built before any of the tagged releases, is
[`lab-deployment-606.md`](lab-deployment-606.md).

The temporary compatibility symbols this section used to warn about are gone.
The `compat/` layer was deleted in #36 on the move to mecmcp 0.7.2, and the
ledger that tracked it was removed in `369f9bb` on the move to 0.8.0.

`v0.0.1` is the first full release. Remote audit-journal forwarding is still
outstanding, live validation is partial, and the tool surface covers a minority
of the SDC API by design. Size any deployment against those limits rather than
against the version number.

## Installed layout and configuration

The installer creates the service account and these paths:

| Path | Required purpose and final mode/owner |
|---|---|
| `/etc/rustsdcmcp/sdc.json` | Live SDC configuration; `0640 root:rustsdcmcp` |
| `/etc/rustsdcmcp/credentials.env` | SDC credential environment; `0600 root:root` |
| `/etc/rustsdcmcp/tokens.json` | Digest-only bearer-token store; `0600 rustsdcmcp:rustsdcmcp` |
| `/etc/rustsdcmcp/audit-hmac.key` | Audit redaction key; `0600 rustsdcmcp:rustsdcmcp` |
| `/var/lib/rustsdcmcp/changeset-state.json` | Durable change-set state under the `0700 rustsdcmcp:rustsdcmcp` state directory |
| `/var/lib/rustsdcmcp/audit.jsonl` | JSON audit sink (`--audit-log-file`), reopened by path on `SIGHUP`; see [Audit retention and forwarding](#audit-retention-and-forwarding) |

The package supplies only `sdc.json.example`; an operator must create the live
configuration and credentials before manually starting the service. Never put
the credential into JSON or record it in command history.

## Listener and lab access

The systemd unit binds the Streamable HTTP endpoint only to
`http://127.0.0.1:30032/mcp`. Do not expose this listener directly. Reach it
through an authenticated SSH tunnel from an authorized workstation:

```console
ssh -N -L 30032:127.0.0.1:30032 root@your-deployment-host
```

`your-deployment-host` is supplied by whoever runs the deployment; it is not a
constant. Earlier revisions of this document named one, and that name stopped
resolving when the host behind it was decommissioned -- which reads like a
local DNS fault rather than a stale document, and sends people debugging the
wrong layer. Ask for the current address rather than copying one from a doc.

Point the local MCP client at `http://127.0.0.1:30032/mcp` while the tunnel is
open.

If you make the tunnel durable, use the template in
[`packaging/systemd/rustsdcmcp-tunnel.service.example`](../packaging/systemd/rustsdcmcp-tunnel.service.example)
rather than hand-rolling a unit from the command above. A unit with
`Restart=on-failure` and `RestartSec=5s` never trips systemd's default start
limit, so a tunnel pointed at a name that no longer resolves retries every five
seconds indefinitely and reports no failure anyone notices.

## Rate limits and metrics

A fresh install rate-limits the Streamable HTTP listener without any operator
action: `--max-requests-per-second-per-ip 50 --max-request-burst-per-ip 100`
and `--max-requests-per-second-per-token 20 --max-request-burst-per-token 40`.
Set the paired rate and burst flag for either axis to `0`/`0` to disable that
axis; a rate/burst pair that is only partly zero is refused at startup.

`/metrics` is **off by default** (`--enable-metrics` to turn it on). It is
never protected by an MCP bearer token — see `mecmcp-transport`'s
`docs/METRICS.md` for what it exposes and how to gate it for a non-loopback
peer. Enabling it is an operator decision made per deployment, not a default.

## Egress policy

> **The systemd egress directives are probably inert on the recommended
> deployment.** Read this section before treating them as a control.

Inbound is loopback-only, but the service holds a tenant-wide SDC credential,
so its *outbound* reach matters. The unit declares:

```
IPAddressAllow=localhost
IPAddressDeny=169.254.0.0/16 fe80::/10 fd00:ec2::254/128
IPAccounting=yes
```

### Whether it enforces at all

systemd implements `IPAddress*` with cgroup eBPF, and **a container that cannot
attach those programs makes systemd fail open**: it logs a warning and runs the
unit with no filter whatsoever. Nothing about the service's behaviour reveals
this, and `systemd-analyze security` cannot either — it scores the
*declaration*, so the unit looks hardened whether or not a single packet is
filtered.

Whether it attaches depends on the runtime, not on this package:

| Environment | `IPAddress*` attaches? |
|---|---|
| Bare metal, VM | yes |
| Privileged LXC, systemd-nspawn with BPF delegation | usually |
| **Unprivileged LXC** (what this project recommends) | **usually not** |
| Docker / Podman / Kubernetes | not applicable — no systemd inside the container |

Do not infer from the table. Probe the actual host.

The installer therefore probes actual enforcement and prints one of:

- `egress filter: ENFORCED` — the host attaches the BPF program *and* the
  installed unit declares a policy
- `egress filter: NOT ENFORCED` — the host cannot attach it; guidance follows
- `egress filter: NO POLICY` — the host could enforce, but the installed unit
  declares no `IPAddressDeny` (a preserved customized unit overrides the
  packaged one; re-install with `SDCMCP_FORCE_UNIT=1`)
- `egress filter: UNKNOWN` — the probe could not run; nothing is claimed

Both conditions matter. A host-capability check alone would report success over
a service filtering nothing.

It uses IP accounting, which rides the same BPF attachment, so a populated
counter proves the filter attached. Check it any time:

```console
systemctl show rustsdcmcp.service -p IPEgressBytes --value
```

`[no data]` means the egress directives are doing nothing. Set
`SDCMCP_REQUIRE_EGRESS_FILTER=1` to make the installer refuse anything short of
`ENFORCED` — including `UNKNOWN`, since an unmeasurable host is exactly as
unguaranteed as a non-enforcing one.

### Enforcing it where systemd cannot

Any result other than `ENFORCED` means the unit directives are **unproven**, and
the control should move outward — to whatever layer actually sees this
workload's packets. `NOT ENFORCED` and `NO POLICY` mean they are demonstrably
doing nothing; `UNKNOWN` means nothing was measured and they may well be
working. Do not treat the last as the first.

The policy does not change with the runtime:

1. deny `169.254.0.0/16` and `fd00:ec2::254` — cloud metadata, the route from a
   compromised HTTP client to a stolen credential
2. deny the local subnet **except** your DNS resolver — blocks lateral movement
   while keeping name resolution working
3. allow 443 outbound — the SDC API, whose addresses rotate

The mechanism does. Configure it with your platform's own documentation rather
than a recipe here — these are the layers, not instructions:

| Runtime | Layer that sees this workload's packets |
|---|---|
| Proxmox LXC / VM | per-guest interface firewall |
| libvirt / KVM | `nwfilter` on the guest interface |
| Kubernetes | `NetworkPolicy` egress, on a CNI that implements it |
| Cloud instance | in-guest packet filter for **both** metadata addresses, plus security groups for everything else |
| Bare metal, VM with working systemd | the unit directives; this section does not apply |

**Container runtimes are deliberately absent from that table.** Docker and
Podman place the data path differently depending on network driver, rootful
versus rootless, daemon configuration, and version — and the mapping changes
between releases. Eight attempts to state it accurately here all failed review,
including one whose only purpose was to explain that it could not be stated.
Trace your own path with `ip netns` / `nsenter` against your actual
configuration, and confirm it with the check below rather than trusting any
table, including this one.

Two properties are worth checking whatever you choose, because both are common
and both produce a control that reads as present and is not:

- **Some layers accept egress policy without enforcing it.** Container network
  attachment and some CNI implementations are the usual cases.
- **Cloud metadata often bypasses the cloud firewall.** On EC2, IMDS traffic is
  handled below the security group and NACL layer, so an egress rule there does
  not block it. This applies to the IPv6 endpoint too — `fd00:ec2::254` is ULA
  rather than link-local, so it is easy to file mentally under "ordinary routed
  traffic the firewall sees", and it is not. The control has to be in-guest, or
  IMDS disabled outright. Consult your provider's current metadata-hardening
  guidance; it changes, and getting it wrong is silent.

Whichever you pick, a rule that has not been exercised from inside the workload
is an assumption. Verify it, and re-verify after a reboot — in-kernel firewall
rules are not persistent unless you made them so.

### Verifying it, from inside the workload

An untested deny is an assumption, and this section exists because one of those
already shipped.

```console
curl --version | grep -qw IPv6 || echo 'NOTE: curl lacks IPv6; the v6 line below proves nothing'
for url in 'http://169.254.169.254/' 'http://[fd00:ec2::254]/' \
           'https://api.sdcloud.juniperclouds.net/'; do
  curl -s -o /dev/null --noproxy '*' --max-time 3 \
    -w "$url  http=%{http_code} connects=%{num_connects} curl=%{exitcode}\n" "$url"
done
```

Read `connects`, not `http`:

| Result | Meaning |
|---|---|
| `connects=0` | **blocked** — no TCP connection was established |
| `connects=1` | **reachable** — the route is open regardless of `http` |
| `curl=6`, `45`, or `2` | the probe never ran; not evidence either way |

Three things decide whether this test means anything:

- **`http=000` alone does not prove a block.** A timeout expiring *after* the
  TCP handshake also yields `000`, with `connects=1`. Read `connects`.
- **A curl without IPv6 support fails locally**, producing `connects=0` — the
  same signature as a block, having probed nothing. Hence the capability check
  above; without it the v6 line is not evidence.
- **`--noproxy '*'` is required.** With `HTTP_PROXY`/`ALL_PROXY` set, curl tests
  the proxy's egress rather than the workload's. `SdcClient` disables
  environment proxies, so the test must too.

A metadata endpoint answering `401` is **reachable**, not blocked. The SDC
endpoint answering `403` is a pass — it proves reachability; the request simply
carries no credential.

### What is denied, and what is not

`169.254.0.0/16` covers the IPv4 cloud metadata endpoint — the standard route
from a compromised HTTP client to stolen credentials — and no legitimate
resolver lives there, so it is safe to deny on any install. `fe80::/10` is IPv6
link-local.

`fd00:ec2::254/128` is denied as a single host route. IPv6 IMDS sits inside the
ULA range `fc00::/7`, so denying that whole range would cover it — but would
also break any site whose resolver is ULA-addressed. The /128 gets the metadata
endpoint without that cost.

**RFC1918 ranges are deliberately not denied by default.** This package
installs on networks whose resolver may sit in any of `10.0.0.0/8`,
`172.16.0.0/12`, or `192.168.0.0/16`; denying the resolver stops the service
resolving the SDC endpoint at all — a hard outage, not a hardening. Add them
per-site, together with an explicit allow for the resolver you actually use.

A denylist rather than an allowlist is deliberate regardless: the SDC API is a
cloud address whose IPs rotate, so `IPAddressDeny=any` plus an allowlist would
fail on the first rotation. `systemd-analyze security` reports "Service does
not define an IP address allow list" for this reason — expected, not an
oversight.

### Tightening per site

Use a drop-in rather than editing the shipped unit — the installer replaces it:

```console
sudo systemctl edit rustsdcmcp.service
```

```ini
[Service]
IPAddressAllow=203.0.113.1
IPAddressDeny=10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7
```

Substitute your own resolver address. This only has effect on a host where the
probe above reports `ENFORCED`.

systemd checks `IPAddressAllow=` **first** and grants on any match, then checks
`IPAddressDeny=`, then defaults to granting. It is allow-before-deny, *not*
longest-prefix — so the `/32` above works because it is an allow, not because
it is narrower. The practical consequence when adapting this: a broad
`IPAddressAllow=` silently defeats every narrower deny, so keep allow entries
as tight as possible.

Confirm DNS still resolves before considering the change good:

```console
sudo systemctl restart rustsdcmcp.service
sudo journalctl -u rustsdcmcp.service -n 20 --no-pager
```

A startup that fails at `verifying SDC credential tenant scope` is the symptom
of a denied resolver.

### Explicit egress proxy

The client never autodiscovers a proxy from `HTTP_PROXY`/`HTTPS_PROXY`/
`NO_PROXY` or any other environment variable — an unset `egress_proxy` means
every request goes direct. Sites that require all outbound traffic to
transit a forward proxy set it explicitly in `sdc.json`:

```json
{
  "egress_proxy": "http://proxy.example.internal:3128"
}
```

`egress_proxy` must be a plain `http://` or `https://` URL with a host; SDC's
own API address stays fixed either way (`api.sdcloud.juniperclouds.net`,
never derived from operator input), so setting a proxy changes how requests
leave the host, not which service they ultimately reach.

## Initial read-only token

Create the initial token as root, and redirect the one-time token value to a
mode-`0600` local file without displaying it. Do **not** use `runuser`: mecmcp
atomically writes in `/etc/rustsdcmcp`, preserving the existing
`rustsdcmcp`-owned `0600` destination while root has the authority needed to
perform the same-directory replacement.

```console
sudo /usr/local/bin/rustsdcmcp token add \
  --tokens-file /etc/rustsdcmcp/tokens.json \
  --device-mapping /etc/rustsdcmcp/sdc.json \
  --name lab-read \
  --devices production \
  --tools get_sdc_tenant_scope,list_sdc_devices,get_sdc_device,list_sdc_firewall_policies,get_sdc_firewall_policy,list_sdc_nat_policies,get_sdc_nat_policy,list_sdc_resources,get_sdc_resource,get_sdc_preview_status,get_sdc_deploy_status,get_sdc_preview_device_result,get_sdc_deploy_device_result,get_sdc_change_set \
  --actor-type human > /secure/local/path/rustsdcmcp-lab-read-token
```

This is an explicit 14-tool read-only grant; do not use wildcard tool scopes
and do not add a write tool to the initial lab token. Confirm afterward that
`/etc/rustsdcmcp/tokens.json` remains `0600 rustsdcmcp:rustsdcmcp`.

## Audit retention and forwarding

The package installs persistent journald storage with a 512 MiB cap and emits
redacted JSON audit events to journald. Remote journal forwarding is required
before production traffic. The approved lab deployment has a temporary
exception: it may retain the persistent local journal without remote forwarding
while it remains lab-only; review that exception before any promotion.

When `--audit-log-file` is also set (the packaged unit passes
`$STATE_DIRECTORY/audit.jsonl`), JSON events are appended to that file too.
The server keeps the file handle `mecmcp_audit::init_tracing` returns and
reopens it by path on `SIGHUP`, alongside the token store reload described in
[Token reload](#token-reload), so rotation is lossless as long as the rotator
renames the file and signals the process — the server never truncates it
itself. A ready-to-install fragment ships at
[`packaging/logrotate/rustsdcmcp-audit`](../packaging/logrotate/rustsdcmcp-audit);
install it as `/etc/logrotate.d/rustsdcmcp-audit`. It rotates by rename
(`postrotate` sends `SIGHUP` via `systemctl kill`), not `copytruncate`:
nothing written before the rename is truncated and nothing written after it
is lost, unlike `copytruncate`, which drops whatever lands between its copy
and its truncate. The SIGHUP handler installs whenever either the audit file
sink or the token store is configured — a deployment running with only
`--audit-log-file` set (no `--tokens-file`) still needs one, or SIGHUP's
default disposition (terminate) kills the process on the signal logrotate
sends it.

Built-in log rotation is out of scope by design: the server does not decide
when to rotate, it only reopens the file on `SIGHUP`. In-process size/age
rotation is not planned; retention is handled by the shipped `logrotate`
fragment.

## Startup

`rustsdcmcp` loads one JSON tenant configuration through the shared runtime's
`-f` option. It then:

1. installs the `ring` rustls provider;
2. resolves the SDC credential from `credential_env`;
3. builds an HTTPS-only client with redirects and environment proxies disabled;
4. calls `GET /api/v2/tenant/tenant-id`;
5. refuses startup unless the response matches `expected_tenant_id`;
6. loads `mecmcp-changeset` state and the optional bearer-token store;
7. starts stdio or the shared hardened Streamable HTTP listener.

No API endpoint, token, or secret is accepted from MCP tool arguments.

## Read tools

Every list tool requires an explicit positive `size` no larger than
`max_page_size`. SDC interprets `size=0` as unbounded, so the server rejects it.
Responses are streamed under `max_response_bytes`; oversized bodies fail
without returning partial JSON.

SDC HTTP 429 or 503 on a read is retried automatically, honouring
`Retry-After` when SDC sends one (capped so a hostile or unreasonable value
cannot stall a call), with jitter and a bounded number of attempts. Once
retries are exhausted, or on any other read failure, it is surfaced as
resource exhaustion for operator review — the API uses the same 429 status
for rate limiting and responses that exceed service limits, and the two call
for different remedies (back off vs. paginate/filter).

Writes are never retried: a mutation must not be silently resent into an
unknown state, so a write rate-limited by SDC fails immediately with the same
resource-exhaustion error and no automatic retry.

## Policy deployment

There is no directly callable deploy tool.

1. `prepare_sdc_policy_deploy` submits the exact preview request, polls its
   documented status to a terminal state, fetches each per-device CLI result,
   and creates a change set binding the deploy request and preview digest.
2. A different authenticated principal calls `approve_sdc_change_set` with the
   exact plan digest before its TTL expires.
3. The original owner calls `apply_sdc_change_set` with both digests.
4. `mecmcp-changeset` revalidates ownership, approval, fingerprints, and policy
   signature before the SDC deploy request is submitted.
5. The server polls the deploy job. `COMPLETED` is success;
   `PARTIAL_SUCCESS`/`FAILED` are reconciled failures. Cancellation or deadline
   after submission is persisted as indeterminate.

**A preview is a lower bound.** Before fix #66 (2026-08-12), this server
requested preview results in CLI format, which SDC renders lossily: a parent
object orphaned by a deletion can be omitted from the CLI rendering while still
appearing in the committed change. An observed case previewed one deletion and
committed two; the omitted object did not appear anywhere in the digest-bound
artifact. The server now requests XML format for preview results, which SDC
renders completely. The change-set binding behaved correctly throughout — what
it bound simply did not describe the whole change under the CLI rendering.

Write tools require an authenticated bearer token and exact tool grants.
Wildcard tool scope deliberately excludes them. Stdio and `--allow-no-auth`
are read-only.

This is worth stating concretely, because it surprises people: a token minted
with `--tools '*'` sees the read tools **only**. Every write tool must be named
when the token is minted. `mecmcp-auth` enforces this — a wildcard scope is
defined as "everything except the server's declared write tools" — so there is
no token scope that grants mutation implicitly.

### Single-operator lab mode

`--lab-mode` waives the second principal. It is off by default, and the server
warns at startup whenever it is on.

```
ExecStart=/usr/local/bin/rustsdcmcp \
    ... \
    --lab-mode
```

Step 2 above disappears; steps 1, 3, 4, and 5 are unchanged. The waiver is
applied automatically when the change set is created, so there is no waive tool
to call and the operator's flow stays prepare → apply.

What lab mode does **not** relax: the plan is still digest-bound, drift is still
detected against the state observed at prepare, and apply still revalidates
ownership, fingerprints, and the policy signature.

A waived change set is recorded as waived, never as approved:

| Field | Genuine approval | Lab-mode waiver |
|---|---|---|
| `approver` | the approving principal | `null` |
| `approval_waiver` | absent | `"lab-mode"` |
| digest | approval digest | waiver digest over `(change_set_id, plan_digest, owner, approved_at)` |

Both fields matter. `approver: null` alone means *both* "nobody has approved
this yet" and "approved without review", and an operator or SIEM has to tell
those apart. The waiver is never encoded as a sentinel string inside
`approver`, so a token happening to be named `lab-mode` cannot be confused for
one.

**Prefer two tokens to lab mode when you can.** The approving principal is the
token name, and self-approval is refused, so minting `you-prepare` and
`you-approve` gives one person the complete lifecycle with the control intact.
Lab mode is for when that ceremony has no value; it is not a convenience to
reach for on a shared or production tenant.

The approving token must be minted with `--actor-type human`
(`token add --actor-type human you-approve ...`). Since mecmcp 0.24.0,
`approve_sdc_change_set` refuses any approver whose actor type is not
`Human`, including the `Unknown` default a token minted without the flag
gets. Preparing a change set does not require the flag; only the approving
token does.

### Standard change-set flags and precedence

`--lab-mode`, `--state-file`, and `--approval-timeout-secs` are standardized
across every `mecmcp` server, so an operator who learns one does not relearn
the next. This server also stores two of those values in `sdc.json`
(`changeset_state_file`, `approval_ttl_secs`), so precedence is defined:

1. an explicitly supplied CLI value wins;
2. otherwise product configuration;
3. otherwise the built-in default.

"Explicitly supplied" means the operator typed it, not that it differs from the
default — a flag typed with the same value as the default still wins. Adopting
these flags therefore cannot silently relocate a durable state file or change
an approval lifetime on an existing deployment.

The effective values are logged at startup.

## Co-managing an SRX with SDC

### Out-of-band drift is cleared in the portal, not here

When a device is edited outside SDC it reports
`device_config_state: OUT_OF_BAND_CHANGED`. **No tool in this server clears
that, and none can** — the portal's "Resolve" action runs against the web UI's
own backend, authenticated by a browser session, and this server's API
credential is refused there. Full evidence in
[`docs/sdc-api/README.md`](sdc-api/README.md) section 12.

`prepare_sdc_policy_deploy` is not a substitute: it pushes policy and does not
reconcile the device's own edits. Device sync is not one either — it reconciles
inventory and leaves `device_config_state` untouched.

In the portal, Resolve offers two choices, and the second one edits the device:

- **Accept** imports the device's change into SDC. The device is untouched.
- **Reject** *deletes* the out-of-band change from the device so it matches SDC.



SDC deploys its own complete model of the hierarchies it owns. Device-local
config inside those hierarchies that SDC does not model is **deleted**, not
preserved. This was observed in production on 2026-08-07.

### What SDC owns

A policy deploy is not limited to policy config. An onboarded SRX whose config
was imported and then deployed through the change-control lifecycle had this
preview diff:

```
set security address-book  global address 10.10.10.0/24  10.10.10.0/24
set security policies policy-rematch
delete security dynamic-address feed-server  feed-name corp-static
delete security dynamic-address feed-server  feed-name aws-s3-us-east-1
delete security dynamic-address feed-server  feed-name curated-cdn
delete security dynamic-address address-name wilddns-corp-static
delete security dynamic-address address-name wilddns-aws-s3
delete security dynamic-address address-name wilddns-cdn
```

Apply matched the preview exactly: three of four `feed-name` entries and three
of four `address-name` objects were removed. The surviving exception —
`blocklist` / `wilddns-blocklist` — was **kept** because imported security
policies referenced it. The three deleted objects were referenced by nothing, so
SDC's imported view did not contain them, and deploying that view removed them.

The predictor is not "is it security config" but **"is it reachable from a
policy SDC imported."** Unreferenced objects under an SDC-owned hierarchy are
deleted on the first deploy.

### Workable co-management split

Based on the live test above:

| Config | Owner | Why |
|---|---|---|
| Interfaces, routing, `system`, management instance | CLI / NETCONF | Not modeled by SDC policy; SDC does not touch it |
| Security policy, NAT | SDC | What SDC is for |
| `security dynamic-address`, address book, other policy-adjacent objects | **SDC, or they get deleted** | Deleted unless referenced by an imported policy |

The trap is the third row: it looks like device-local config, and it is silently
in SDC's blast radius.

### Warning surface

The **preview diff is the only warning** and must be read before approval. This
is exactly what the prepare → approve → apply gate exists to catch, and it
worked in the test above. A deletion that appears in the preview and is approved
proceeds as previewed.

### Observed deploy mechanics

SDC commits as user `sduser` over NETCONF using `commit confirmed` with a
1-minute rollback, then confirms approximately 1 second later, tagging commits
`EMS System Commit <uuid> EMS_REQ_ID:<uuid>`. A device that goes unreachable
mid-deploy auto-reverts.

### Open question

Whether feed-server / dynamic-address config can be expressed **in** SDC so it
survives deploys, or whether it must be re-applied out-of-band after every
deploy, is unverified. Resolving it needs a tenant with the relevant SDC
feature explored; do not answer it by inference.

## Persistence and recovery

Set `changeset_state_file` to an absolute path on durable storage. If omitted,
state is in memory and planned/approved operations do not survive restart.

An indeterminate deployment means the request may have reached SDC but this
process did not observe a terminal state. Reconcile it using
`get_sdc_deploy_status`, the per-device result tool, and the SDC portal before
planning another deployment.

### Recovering from a failed deploy

A failed deploy leaves an operation that refuses every later apply on the tenant
with "the device already has an active or unreconciled operation". Clear it with
`discard_sdc_operation`, supplying the operation id and its expected
fingerprint from the change-set state. Only the operation's owner may discard
it, and the record remains visible afterwards — a discard clears the block, it
does not erase the fact that a deploy failed.

The SDC API does not expose a candidate rollback primitive for this workflow.
Rollback is therefore reported as unsupported rather than guessed.

## Token reload

On Unix, SIGHUP reloads the digest-only bearer-token file atomically. A failed
reload keeps the previous verified snapshot. This runs in the same SIGHUP
handler as the audit-log reopen described in
[Audit retention and forwarding](#audit-retention-and-forwarding), and always
after it: the audit reopen is attempted first, and a failure there does not
block the token reload.
