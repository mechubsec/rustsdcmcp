# The Security Director Cloud API — pinned surface

Everything in this file is taken from the **vendored OpenAPI 3 document**, not
from prose documentation or inference. If a fact is not in the spec, it is
listed under [Still unverified](#still-unverified) rather than guessed.

## Provenance

The public API reference at
<https://www.juniper.net/documentation/us/en/software/sd-cloud/api/> is an
**APIMatic dev portal**. Its pages are client-rendered, so fetching them
returns only the page shell — which is why the endpoint surface could not be
read from the HTML. The portal config at `static/js/portal.js` declares an
export route, and that route serves the complete spec:

```
https://www.juniper.net/documentation/us/en/software/sd-cloud/api/static/exports/security-director-cloud-apis-openapi3json.json
```

| | |
|---|---|
| Vendored as | `security-director-cloud-apis-openapi3.json` |
| Retrieved | 2026-07-25 |
| `info.title` / `info.version` | `Security Director Cloud APIs` v`1.0.0` |
| `openapi` | `3.0.0` |
| sha256 | `099d1f0f5f4ce008e0c927dbc2c948b3bfe57337e15b909733dbea21d347ecc5` |
| Size | 227 paths · 368 operations · 61 tag groups · 804 schemas |

Refresh with [`fetch-spec.sh`](fetch-spec.sh), then regenerate
[`endpoints.md`](endpoints.md) with `scripts/gen-endpoint-inventory.py`. The
fetch script validates the download before overwriting the known-good copy.

> **Redistribution.** The spec is Juniper's published artifact, vendored here
> for offline client generation while this repository is **private**. If the
> repo is ever made public, replace the vendored copy with a fetch step.

## Base URL and versioning

```
https://api.sdcloud.juniperclouds.net/
```

One server, no variables. Versioning is **per-path, not per-host** — and it is
mixed. Do not assume a single API version:

| Prefix | Groups |
|---|---|
| `/api/v1/…` | policies, devices, templates, all shared security objects |
| `/api/v2/…` | IAM (users, roles, tenant), site management, tunnels, ipsec-profile |

## Authentication

Two schemes, declared at the document root, so they apply to **every** operation
(no operation overrides its security). Both are plain headers:

| Scheme | Header | Type |
|---|---|---|
| `ApiKeyAuth` | `x-api-key` | `apiKey` in header |
| `OauthKeyAuth` | `x-oauth2-token` | `apiKey` in header |

They are alternatives — the root `security` is a list of two single-key
requirements, so **one** of them satisfies a call. Note that `x-oauth2-token`
is modeled as an opaque header value, *not* as `Authorization: Bearer …`.

From the portal's user-guide prose (not the spec): API keys are minted per user
or service account, carry per-key roles and privileges, and default to a
one-year expiry; OAuth 2.0 federates to a customer IdP (Okta, Entra ID).

`GET /api/v2/tenant/tenant-id` (`GetTokenScope`) resolves what a credential is
actually scoped to — the natural startup probe for validating configuration.

## The async job pattern

**This is the most important structural fact about the API.** Every
state-changing bulk operation is asynchronous and follows one shape:

```
POST   /api/v1/policies/{action}                        -> { "{action}_id": "..." }
GET    /api/v1/policies/{action}/{id}                   -> overall status
GET    /api/v1/policies/{action}/{id}/devices/{device}  -> per-device result
```

It holds for `preview`, `deploy`, `selective_deploy`, and `cleanup`, and the
same submit-then-poll shape recurs in Device Operations (`sync`, `reboot`,
`config/rollback`). A client that treats these as synchronous will report
success for work that has not happened yet.

## Preview → deploy is a native change-control boundary

The API already separates rendering a change from applying it:

| Stage | Batch | Single policy |
|---|---|---|
| Preview | `POST /api/v1/policies/preview` | `POST /api/v1/policies/firewall/{id}/preview` |
| Deploy | `POST /api/v1/policies/deploy` | `POST /api/v1/policies/firewall/{id}/deploy` |
| Selective deploy | `POST /api/v1/policies/selective_deploy` | `POST /api/v1/policies/firewall/{id}/selective_deploy` |
| Cleanup | `POST /api/v1/policies/cleanup` | `POST /api/v1/policies/firewall/{id}/cleanup` |
| State | — | `GET /api/v1/policies/firewall/{uuid}/state` |

NAT policies expose the identical set under `/api/v1/policies/nat/{id}/…`.

Preview request entries carry both `deploy_targets` and `undeploy_targets`, and
the spec states that for each device **undeploy targets are processed first**,
then deploy targets. A `target_type` of `DEVICE` selects the target. The batch
deploy request is a separate shape containing only `policy_id` and
`policy_type`; the implementation preserves that distinction exactly.

This maps cleanly onto `mecmcp-changeset`: preview produces the artifact to
digest and show a human, deploy is the apply step. Preview output is what the
approval digest should be computed over — **never** re-render at apply time,
or the approved artifact and the applied one can differ.

## Pagination, filtering, and result shaping

List endpoints share a query-parameter vocabulary (occurrence counts across the
spec): `from` (68), `size` (68), `filters` (58), `sortby` (54), `count` (50),
`fields` (41), `obj_uuids` (39).

- `from` — zero-based starting index, default `0`
- `size` — max results per page; **`size=0` asks the server for as many as it
  can return**, which is the single easiest way to trigger a 429 on an
  estate-sized tenant. Always set an explicit bound.
- `count=true` — returns only the total match count, no resource bodies
- `fields` — server-side projection; use it to keep responses small
- `sortby` — e.g. `sortby=(name(descending))`
- **`/api/v2/` lists page with `spec.from`/`spec.size`** (`ListTunnels`,
  `GetSiteList`). Unprefixed `from`/`size` are ignored upstream, so the list is
  bounded only by bytes. `GetIpsecProfileList` and `ListPacFiles` declare no
  page parameters at all. `ListDeviceGlobalSettings` is the one `/api/v1/` list
  that pages with `offset`/`limit`.
- **Credential fields in read responses.** `IcapServer` (`password_ascii`,
  `password_base64`) and v2 sites (`psk`, `pre_shared_key`, and `site_config` /
  `cpe_config` bodies that render device config with IKE PSKs) are redacted at
  the tool boundary by `rustsdcmcp_core::redact_secrets`.

## Errors

Every operation declares exactly the same response set: `200`, `400`, `401`,
`403`, `404`, `409`, `429`, `500`, and `default`. All non-200 bodies use one
schema (`runtimeError1`):

```json
{ "code": 0, "message": "string", "details": [ {} ] }
```

`message` is the only required field. Two codes deserve first-class handling:

- **`429`** — the spec's description covers *two distinct conditions*: rate
  limiting **and** a response payload exceeding the maximum allowed size. The
  remedy differs (back off vs. paginate/filter), so a client must not treat 429
  as retry-after-sleep unconditionally.
- **`409`** — present on every operation, which is what you would expect from
  an API where concurrent deploys can conflict.

## Surface at a glance

368 operations — 173 `GET`, 96 `POST`, 50 `DELETE`, 49 `PUT`. Largest groups:

| Group | Ops | | Group | Ops |
|---|---:|---|---|---:|
| NAT Policies | 24 | | Device Onboarding | 8 |
| Firewall Policies | 23 | | Device Image Definitions | 8 |
| Site Management | 20 | | EnhancedContentFilteringProfileSet | 8 |
| Templates | 20 | | Device Operations | 7 |
| License and Certificate Management | 14 | | Device Resources | 7 |
| IAM | 10 | | IPSSignature | 7 |

The long tail is ~35 shared-security-object groups (Address, Application,
Services, Scheduler, URLCategoryList, IpsProfile, WebFilteringProfile, …) that
are almost all a uniform 5-op CRUD shape. Full listing:
[`endpoints.md`](endpoints.md).

## What this means for the tool surface

1. **Read-only first.** 173 `GET` operations, and the object-CRUD groups are
   uniform enough that a small number of generic list/get tools can cover most
   of them without 35 bespoke tools.
2. **Mutations go through `mecmcp-changeset`.** The preview → deploy split is
   already the right shape; do not expose `deploy` as a directly callable tool.
3. **Poll, don't fire-and-forget.** Any tool wrapping an async action must
   resolve the job and surface per-device results, or it will lie about outcomes.
4. **Bound every list call.** Never emit `size=0`; always set `size` and prefer
   `fields` projections. The 429-on-payload-size behavior makes this a
   correctness issue, not just an efficiency one.
5. **Tenant scoping is real.** Bearer tokens in this server must carry a tenant
   scope, validated against `GET /api/v2/tenant/tenant-id` at startup.

### Device Resources (live-observed 2026-09-24)

Five config sections are exposed through `list_sdc_device_config`:
**interfaces**, **subinterfaces**, **zones**, **routing_instances**, and
**idp_sensors**. A sixth path, **interfaces/{interface_name}/subinterfaces**,
reads the subinterfaces of one interface by name. The `interface_name` parameter
is given in Junos form (`ge-0/0/1`) and translated internally to the API's
underscore form (`ge-0_0_1`), matching the behavior of
`GetDeviceInterfaceSubinterfaces`.

The spec's `filter` parameter is not exposed (YAGNI).

**SDC's view against the device.** On 2026-09-24 `list_sdc_device_config` was
compared, section by section, with `show configuration` and
`show interfaces terse` on the lab vSRX `vsrx-ci` (26.2R1.7) through
rustjunosmcp:

| Section | SDC returned | Device | Verdict |
|---|---|---|---|
| interfaces | 8: `ge-0/0/0`, `ge-0/0/1`, `fab0`, `fxp0`, `lo0`, `reth0`, `reth1`, `st0` | the same 8 in `show configuration interfaces`; `show interfaces terse` also lists `ge-0/0/2`–`5` | SDC models the **configuration**, not operational state. Unconfigured ports do not appear. |
| subinterfaces | 9 entries: 7 logical units (`ge-0/0/0.0`, `fxp0.0`, `lo0.0`, `reth0.0`, `reth1.0`, `st0.1`, `st0.2`) and 2 bare interface names (`ge-0/0/1`, `fab0`); every IPv4 address correct | the same units and IPv4 addresses, **plus** `inet6` on `ge-0/0/0.0` and `fxp0.0` | **IPv6 addresses are absent from SDC.** Do not use SDC to audit IPv6 addressing. |
| zones | `trust`, `untrust`, names only | the same zones, with interface bindings, host-inbound services and a screen | Names match. SDC returns no bindings, so zone membership must come from the device. |
| routing_instances | empty | none configured | Match. |
| idp_sensors | one item, empty `packet_log` sub-objects | no IDP sensor configuration | Treat as a default placeholder, not configuration. |

`interface_name` translation was confirmed live: `ge-0/0/0` returned the single
unit `ge-0/0/0.0`. `get_sdc_device_config_revision` returned
`device_config_revision` and `last_sync_revision` timestamps. Where
present, `count` was an **integer** on every device-config response, unlike the
string `count` on catalog lists (see §1 below). An empty section
(`routing_instances` here) comes back as a bare `{}` with no `count` at all, so a
typed model must not require it.

## Live-observed response shapes (2026-08-07)

The OpenAPI spec's examples are placeholder `"string"` values, so actual field
types and structures are invisible without a live tenant. A full read-tool sweep
on 2026-08-07 surfaced four shape facts that break shared or typed models:

### 1. `count` is an integer on some endpoints and a string on others

```json
list_sdc_firewall_policies -> "count": 1      (integer)
list_sdc_devices           -> "count": 1      (integer)
list_sdc_nat_policies      -> "count": "1"    (string)
list_sdc_resources         -> "count": "7"    (string, addresses)
                              "count": "241"  (string, services)
```

A shared list-envelope type with `count: u32` deserializes on firewall/devices
and **fails** on NAT and resources. Do not introduce a shared envelope without
normalizing `count` first.

### 2. NAT uses `id`, firewall uses `uuid` — and the formats differ

```json
firewall item -> "uuid": "d4a4ed24-d895-490e-a803-93f4cec26808"   (UUID)
NAT item      -> "id":   "51507252"                               (numeric string)
```

Sibling policy endpoints with different identifier field names *and* different
identifier formats. Note `get_sdc_nat_policy` is nonetheless called with
`policy_id="51507252"` and works — the tool argument is correctly generic, but
any model assuming a UUID is wrong for NAT.

### 3. An empty collection returns bare `{}`

```json
list_sdc_resources(resource=schedulers) -> {}
list_sdc_devices  (empty tenant)        -> {}
```

Not `{"items":[],"count":0}`. There are no `items` or `count` keys at all. Any
struct with required `items`/`count` fails on every empty collection — and an
empty collection is the normal state of a fresh tenant, so this would be hit on
day one.

Handle it explicitly wherever a collection is deserialized: either deserialize
as `Value` and normalize, or use `#[serde(default)]` on list fields and
`Option<_>` on `count`.

### 4. Per-device result field name differs between preview and deploy

```json
get_sdc_preview_device_result -> "config_diff":     "set security …"
get_sdc_deploy_device_result  -> "deployed_config": "set security …"
```

Same conceptual content, different key. Currently harmless because
`preview_device_result` and `deploy_device_result` return `Value` passthrough —
but it is a trap for anyone typing them later. If the device-result endpoints
are ever typed, model `config_diff` and `deployed_config` explicitly rather
than aliasing them.

Also observed: the deploy result message reads `"Selective deploy result
retrieved successfully"`, indicating SDC serviced the deploy via the
selective-deploy path.

### What is not broken

`JobStatus` and `DeviceStatusEntry` are typed and deserialized correctly against
live preview *and* deploy responses, including `preview_id`/`deploy_id` being
mutually exclusive with the unused one `null`. The shared-model choice there is
validated.

### 5. Device sync direction — confirmed 2026-08-12 (was open 2026-08-08)

`POST /api/v1/devices/sync` (`BulkSyncDevices`) can operate in one of two
directions:

1. **Import device config into SDC** — reads the device's running config and
   updates SDC's model to match it (safe)
2. **Push SDC's model to the device** — overwrites device config with SDC's
   view, deleting anything SDC does not model (hazardous)

The OpenAPI spec does not state which direction it operates in. Confirming this
requires executing a sync against a live tenant and observing whether config
appears or disappears. That test is deferred because the production tenant
already experienced one such incident: #23 documented a policy deploy that
deleted `security dynamic-address` config off a real vSRX because SDC's policy
model does not represent dynamic-address feeds.

#### Answered 2026-08-12: it imports, and it syncs *inventory*, not config

Executed against `vsrx-ci` on the live tenant, snapshot-gated, scoped to the
single device. `POST /api/v1/devices/sync` with `{"uuids":["a0f049c4-…"]}`
returned `200` and `{"sync_id":"3d5e881b-…"}`.

**Direction: import. Option 1.** The device's commit log was unchanged across
the sync — the newest entry before and after was the same operator commit, and
SDC created no commit of its own. Nothing was pushed and nothing was deleted.
This is the opposite of the deploy path's behaviour in #23.

**But it does not do what #21 wanted.** The per-device message is `"Successful
sync inventory for device: source-device"`, and the state it moves is the
inventory pair only:

| Field | Before | After |
|---|---|---|
| `device_sync_status` | `OUT_OF_SYNC` | `IN_SYNC` |
| `inventory_sync_info.overall_sync_status` | `OUT_OF_SYNC` | `IN_SYNC` |
| `device_config_state` | `OUT_OF_BAND_CHANGED` | **`OUT_OF_BAND_CHANGED`** |

`device_config_state` is untouched. `BulkSyncDevices` reconciles *inventory*,
not configuration, so it is **not** the remedy for a device that has drifted
via out-of-band CLI edits — which was the motivating problem in #21. Whatever
clears `OUT_OF_BAND_CHANGED` is a different operation, still unidentified.

**`GetSyncStatus` does not share the deploy job shape.** Two differences that
matter to anyone planning to reuse the polling code:

```json
{"status":"SUCCESS",
 "device_sync_status":[{"uuid":"…","name":"source-device",
                        "status":"SUCCESS","message":"…"}]}
```

1. The status vocabulary is `SUCCESS`/`FAILURE`, not the deploy path's
   `PENDING` / `IN_PROGRESS` / `COMPLETED` / `PARTIAL_SUCCESS` / `FAILED`.
2. The per-device array is `device_sync_status`, not the deploy path's
   structure, and its `name` carries the device's *hostname*
   (`source-device`), not the SDC device name (`srx17861259151621`).

The job also reported `SUCCESS` on the first poll, within seconds — no
intermediate state was observable, so the non-terminal vocabulary is still
unseen.

### 6. Firewall and NAT policy `{scope}` parameter values (2026-08-08)

The firewall and NAT rule endpoints include a `{scope}` path parameter. The
OpenAPI spec describes it as: **"Scope: 'global' or 'zone'."**

These are the two valid values:
- `global` — rules applying globally across the policy
- `zone` — rules scoped to specific security zones

Also confirmed: the spec misspells the firewall hierarchy path segment as
`heirarchy`, while NAT uses the correct spelling `hierarchy`:
```
/api/v1/policies/firewall/{policy_uuid}/{scope}/heirarchy    (misspelled)
/api/v1/policies/nat/{policy_id}/hierarchy                   (correct)
```

### 7. Certificate and licence reads carry no key material (2026-08-12)

Captured from the live tenant against `vsrx-ci`
(`00000000-0000-4000-8000-000000000003`). All six read endpoints returned
`200`. This answers the structural concern in #50, which was explicit that key
material had been *neither observed nor ruled out*.

**Observed: no private key, PEM body, CSR, or passphrase field appears in any
response.** Certificate reads return metadata only.

`ListCaCertificates` / `ListDeviceCaCertificates`:

```
uuid, name, device_uuid*, common_name, distinguished_name,
organization_name, public_key_algorithm, key_size, serial_number,
expiry_date, signature_algorithm, finger_print_content,
issuer_common_name, issuer_organization_name
```

`ListLocalCertificates` / `ListDeviceLocalCertificates`:

```
uuid, name, device_uuid*, distinguished_name, public_key_algorithm,
serial_number, validity_not_before, validity_not_after, key_size,
signature_algorithm, finger_print_content, auto_re_enrollment_status,
auto_re_enrollment_trigger_time, email, subject_alternate_domain_name,
ipv4_address, ipv6_address
```

`ListLicenses` / `GetLicense`:

```
uuid, name, version, state, validity_type, start_date, end_date
```

`*` — `device_uuid` is present only on the tenant-wide list, absent from the
per-device variant. The same list-versus-scoped asymmetry already documented for
devices.

`GetLicense` returns exactly the `ListLicenses` item field set. Unlike devices,
the single-object read adds nothing.

Four traps in the observed data:

1. **`validity_not_before` and `validity_not_after` use different date formats
   in the same object.** Observed: `'08- 7-2026 17:47 UTC'` against
   `'2027-09-06 18:47 UTC'` — note the day padded with a space, and the
   day-month order reversed. Do not parse these with one format.
2. `ipv4_address` and `ipv6_address` return the sentinel strings
   `'ipv4 empty'` and `'ipv6 empty'`, not `null` or `""`.
3. `key_size` and `public_key_algorithm` are *public* key metadata
   (`'2048'`, `'rsaEncryption'`). A redaction rule keyed on the substring `key`
   will match them; they are not secrets.
4. `version` and `key_size` are strings, while the envelope `count` is an
   integer here — consistent with §1.

The licence `name` (e.g. `E20210617001`) is a licence identifier, not a licence
key blob.

**This does not make a projection unnecessary.** What is verified is today's
payload, not a contract. #50's reasoning stands: with `Value` passthrough there
is no failure mode in which a field added upstream is noticed.

### 8. What a template is, and what it can express (2026-08-12)

`GET /api/v1/templates` on the live tenant returns 17 built-in templates,
`count: 17`, every one `format: "CLI"`. A template object is:

```
uuid, name, description, format, template, variablesdef
```

**`template` is a Jinja2 template that emits raw Junos `set`/`delete` lines.**
From the built-in `DNS` template:

```jinja
{%- for nameserver in nameservers_config.nameservers %}
set system name-server {{nameserver.DNS_IP_Address}}
  {%- if nameserver.routing_instance %} routing-instance {{nameserver.routing_instance}}{%- endif -%}
{% endfor %}
```

Templates render against both the new values and a `pre_config` object holding
the previous ones, which is how they replace rather than accumulate — the
built-ins emit `delete` lines for `pre_config` entries before `set` lines for
the new ones.

**Exposed since #33** as the `templates` family of the generic read catalog:
`list_sdc_resources` / `get_sdc_resource` with `resource: "templates"`. It
qualifies because `GET /api/v1/templates` supports both `from` and `fields`, so
it can be bounded like every other family — that requirement is what kept
`DeviceGlobalSettings` out.

Read-only, and structurally so: `Templates` is absent from `WritableResource`,
and the conversion between the two catalogs runs one way only. A template
applies to every device mapped to it, so a write is estate-scale rather than
device-scale.

`variablesdef` is a **JSON-encoded string nested inside the JSON response**, not
a nested object. It must be parsed twice. Each entry carries `name`,
`description`, `type` (`ipv4`, `string`, …), `required`, `mode`, and an optional
`path` for entity-scoped collections.

#### Bearing on #23's co-management boundary

The 17 built-ins are system-level: `DNS`, `NTP`, `SNMP`, `SYSLOG`, `SSH`,
`NETCONF`, `HOSTNAME`, `DOMAIN_NAME`, `BANNER`, `LOCAL_USER`, `LLDP`, `DHCP`,
`AE_DEVICE_COUNT`, `PROXY_SERVER_SECURITY`, `ROUTING_INSTANCE`, and two MNHA
templates.

- **No general interface template.** `AE_DEVICE_COUNT` sets an aggregated
  ethernet device-count and nothing else. Interface addressing is not covered.
- **No general routing template.** `ROUTING_INSTANCE` is scoped by its own
  description to PKI, Security Intelligence, and AAMW, and its body only emits
  `security pki ca-profile … routing-instance`, `services
  security-intelligence routing-instance`, and `services
  advanced-anti-malware connection routing-instance`.
- **No `security dynamic-address` template**, which is #23's concrete case.

So the *built-in* set does not express the config a policy deploy removes.

But `POST /api/v1/templates/workflow_definitions` (`UploadTemplateDefinition`)
accepts custom definitions, and since a template body is arbitrary Junos CLI, a
custom template **can** emit `set security dynamic-address …` or interface and
routing configuration. The mechanism is not restricted to the built-in
categories.

**Do not read that as a fix for #23.** Whether config placed by a template
survives a subsequent *policy* deploy is a different question about a different
pipeline, and it is unverified. The observed #23 behaviour was a policy deploy
deleting unreferenced `dynamic-address` config; nothing tested here shows that a
template origin changes that outcome. Answering it needs a custom template
deployed and then a policy deploy run over the same device.

### 9. `DEVICE_GROUP` is not a supported deploy target (2026-08-12)

Straight from the vendored spec, and it contradicts a claim in #34:

```
apiTargetType.description
  - DEVICE: Individual device (default)
  - DEVICE_GROUP: Group of devices (Not supported, future support)

Target1.properties.type.description
  DEVICE_GROUP will be supported later.
```

`TargetType::DeviceGroup` exists in `models.rs` and serializes to
`device_group`, so this repository will happily build a preview or deploy
request naming a device group — and SDC will reject it. #34 asserts the
opposite ("already exists in `models.rs` and is deployable today"), and that
assertion is what made device-group membership look like a blast-radius gap.
It is not one: you cannot deploy to a group at all yet.

The real defect is smaller and different — a target type the API does not
support is accepted locally and fails downstream instead of being refused with
a clear message. Device-group *reads* remain useful for inventory, just not for
the reason #34 gives.

`DEVICE_GROUP` **is** meaningful for templates: `apiDeviceType` uses the same
name to distinguish template targets, with no "not supported" note. Do not
generalize the deploy restriction to template operations.

### 10. Templates do not protect config from a policy deploy (2026-08-12)

The experiment #33 asked for, run against `vsrx-ci` on the live tenant.

#### Uploading a custom template

`POST /api/v1/templates/workflow_definitions` takes `multipart/form-data` with
the YAML in `definition_file`, and only `.yaml`/`.yml` is accepted. The YAML
schema is **not in the spec**; it was derived from the endpoint's own errors and
is:

```yaml
action-category: template-create   # or template-update
spec:
  name: MY_TEMPLATE
  description: "..."
  format: CLI
  body: |
    set security dynamic-address address-name example profile feed-name feed
```

`template-update` reuses the same `spec.name` and returns the same
`resource_id`.

#### An edge WAF blocks plaintext HTTP to private addresses

A template whose body contains `http://` followed by an RFC1918 address is
rejected with a bare **HTML `403 Forbidden`** — not SDC's JSON error shape — so
it is an edge proxy, not the API. Isolated by probe:

| Body contains | Result |
|---|---|
| `url http://203.0.113.206/bundle.tgz` | **403 HTML** |
| `url https://example.com/bundle.tgz` | 400 (reaches the API) |
| `server 203.0.113.206` (no scheme) | 400 (reaches the API) |
| the word `url` alone | 400 (reaches the API) |

This matters because it is exactly the shape of a `dynamic-address feed-server`
pointing at an internal feed host: that config cannot be uploaded as a template
through this API, though it can be set from the CLI.

#### The finding

A custom template **can** place `security dynamic-address` config. Verified on
the device, committed by `sduser` with `Component:Config-Template`.

A subsequent **policy deploy targets that config for deletion.** Controlled
comparison, same policy and same device:

| Device state at prepare | Deletes in the preview |
|---|---|
| Template-placed `address-name tmpl-unreferenced` present | `delete security dynamic-address address-name tmpl-unreferenced` |
| Same object removed | **none** (397-line diff, zero delete lines) |

So **template origin confers no protection**, and #23's predictor is unchanged:
what survives is reachability from a policy SDC imported, not how the config got
there. The co-management split in `operations.md` stands, and templates are
**not** a remedy for the deletion problem.

#### Confirmed by a committed apply (2026-08-12, second run)

The first run could not commit — every deploy failed while the tenant carried a
policy the device rejected at check-out (#64). After that policy was replaced
with a single any/any permit, the experiment was repeated end to end:

1. A custom template placed `feed-server expfeeder` and
   `address-name exp-unreferenced` on the device. Template deploy `SUCCESS`,
   committed by `sduser` with `Component:Config-Template`.
2. A policy deploy through this server previewed exactly one line:
   `delete security dynamic-address address-name exp-unreferenced`.
3. Apply returned `succeeded: true`, `SDC deployment ended with Completed`.
4. The device confirms the removal.

So the finding is now observed, not inferred: **a policy deploy deletes
template-placed configuration that no imported policy references.**

### 11. A deploy can commit more than its preview disclosed (2026-08-12)

Found while confirming §10, and it matters more than the finding it came from.

The preview above contained **one** delete line, naming only the address-name.
The committed change removed the feed-server as well:

```
$ show configuration | compare rollback 2
[edit security dynamic-address]
-    feed-server expfeeder {
-        url https://feeds.example.com/bundle.tgz;
-        update-interval 3600;
-        feed-name expfeed { path bundle/blocklist; }
-    }
-    address-name exp-unreferenced {
-        profile { feed-name expfeed; }
-    }
```

This is not a parsing artifact. The string `expfeeder` appears **zero times** in
the entire prepared-change artifact — the same artifact the preview digest is
computed over — while `exp-unreferenced` appears once, in a 61-character
`config_diff`.

**Why this matters more than the deletion itself.** The whole premise of the
change-control binding is that an approver approves the preview, and the digest
proves the applied change is that one. Here the approver saw one object being
removed and two were removed. The digest is intact and the binding did its job;
what was bound simply did not describe the whole change.

It also contradicts what this document previously recorded from #23 — *"Apply
matched the preview exactly"* — which was true of that observation and is not
true in general. Treat a preview as a lower bound on what a deploy will change,
not a complete statement of it, until the conditions under which it
under-reports are understood.

#### Answered 2026-08-12: the CLI rendering is lossy, and we request it

`GET /api/v1/policies/preview/{preview_id}/devices/{device_id}` takes a
`format` query parameter — `CLI` (the default) or `XML` — described as
"Output format for config_diff". This server never passes it, so it receives
the default.

The **same preview**, fetched twice:

| | `format=CLI` | `format=XML` |
|---|---|---|
| bytes | 273 | 570 |
| feed-server named | **no** | **yes** |
| address-name named | yes | yes |
| delete markers | 1 | 4 |

```xml
<configuration><security><dynamic-address>
  <feed-server operation="delete"><name>probefeeder</name></feed-server>
  <address-name operation="delete"><name>probe-unreferenced</name></address-name>
</dynamic-address></security></configuration>
```

against the CLI form's single line:

```
delete security dynamic-address address-name probe-unreferenced
```

**So SDC was never concealing the change.** Its XML rendering states both
deletions plainly. The CLI rendering omits the parent, and this server binds
its digest to that lossy rendering. The deploy that prompted §11 did exactly
what its XML preview said it would.

That narrows the defect considerably: it is not a gap in what SDC will tell us,
it is the format this client asks for. The remedy is to request `XML` for the
artifact the digest covers, keeping CLI only where a human wants to read it.

Still unverified: whether the CLI form omits parents generally, or only a
parent orphaned by the removal of its last consumer. The remedy does not depend
on the answer, since XML disclosed both here.

#### Remedied 2026-08-12: preview_device_result now requests XML

The client now passes `format=XML` when fetching per-device preview results, so
the preview digest is computed over the complete change disclosure. This
addresses issue #66.

The change necessarily alters every preview digest — the artifact bytes change
when switching from CLI to XML format — but no test, fixture, or golden digest
depended on the CLI form. The one fixture digest in
`tests/fixtures/mecmcp-0.3.6-state.json` is a placeholder unrelated to actual
preview content.

#### On the first run's failures

Both applies in the first run failed for reasons now understood. The tenant
policy was rejected by the device at check-out (#64), which had nothing to do
with templates. One template deploy additionally hit a Junos constraint —
*"Feed blocklist has already been referenced by dynamic address
wilddns-blocklist. One feed can only be referenced by one dynamic address."*

#### Operational consequence

A failed deploy leaves an operation in state `failed` in the change-set store,
and every later apply on that tenant is refused with *"the device already has an
active or unreconciled operation"*. `mecmcp-changeset` has
`discard_operation`, but this server exposes no tool for it, so there is no
supported way to clear it.

### 12. Out-of-band resolution exists, but not on this API (2026-08-13)

`device_config_state: OUT_OF_BAND_CHANGED` is returned live by
`GET /api/v1/devices`, and the string appears **zero times** in the vendored
spec. Re-fetching the upstream export produced a **byte-identical** file, so
that is a real omission rather than a stale snapshot. The field itself is
documented — `Device.device_config_state`, a bare `string` with no enum,
described as *"DeviceConfigState describes whether the device contains out of
band changes"* — so the API names the concept, reports it, and offers no
operation to act on it.

The portal clears it. Captured live from the Devices page, the action is three
calls on the **web UI's own backend**, not this API:

| Purpose | Method and path | Body |
|---|---|---|
| SDC-side intended changes (left column) | `POST /configmgmt/view-ui-changes` | `{"device_uuid":"…"}` |
| Device-side out-of-band delta (right column) | `POST /configmgmt/view-device-changes` | `{"device_uuid":"…"}` |
| Both buttons | `POST /configmgmt/resolve-oob` | `{"device_uuid":"…","accept_device_change":<bool>}` |

`accept_device_change` is the entire difference between the two buttons:

- **`true` — accept.** Import the device's change into SDC so SDC matches the
  device. The device is untouched.
- **`false` — reject.** **Delete the out-of-band change from the device** so the
  device matches SDC. The UI's own wording: *"Only the configurations updated
  from the device will be deleted."*

Note what `false` means. "Reject" does not discard SDC's opinion; it edits the
device. Anything that ever exposes this must not let those two be confused.

#### Why this server cannot use it

**Different host path, different authentication.** These are `/configmgmt/*` on
`sdcloud.juniperclouds.net`, not `/api/v1/*` on `api.sdcloud.juniperclouds.net`
— which is why searching the spec found nothing. They are outside the spec's
surface, not missing from it.

They are authenticated by the logged-in browser session. Probed with this
server's credential:

| Request | Result |
|---|---|
| `POST /configmgmt/view-device-changes` with `x-api-key` | `403` |
| the same with **no auth at all** | `403` — identical |
| `POST /api/v1/configmgmt/view-device-changes` with `x-api-key` | `404` |

The key and no key produce the same response, so the key buys nothing there.
The `404` under `/api/v1` is the useful contrast: that prefix is routed and has
no such path, while `/configmgmt/*` is a surface this credential cannot reach.

#### Consequence

Clearing out-of-band drift is **a portal action with no API equivalent**, and
that is a property of the product, not a gap in this repository. Implementing
it would mean holding a user's web session and calling undocumented BFF
endpoints that can change without notice — the wrong trade for a management
plane.

Recorded here so the next person does not repeat the search. If Juniper later
exposes an equivalent under `/api/v1` or `/api/v2`, the semantics above are the
ground truth for what the buttons do.

#### Read-side advisory: surfacing the state, not resolving it

This server cannot call the portal's resolution endpoints (above), but
`list_sdc_devices` and `get_sdc_device` do read `device_config_state` from
`GET /api/v1/devices`, so the drift this section describes is at least
visible to a caller before the "no API equivalent" limit applies to it.

Both tools attach an `oob_drift` advisory block to each device:

```json
"oob_drift": {
  "state": "out_of_band_changed",
  "raw_device_config_state": "OUT_OF_BAND_CHANGED",
  "resolution_available_here": false,
  "resolution_paths": [{"action": "portal", "where": "SDC portal → Devices → Resolve out-of-band changes", ...}],
  "not_a_remedy": ["apply_sdc_device_inventory_sync — inventory only, leaves this state untouched"]
}
```

`state` is `none` when the field is absent, `out_of_band_changed` on an exact
match, and `unknown` for every other value — including a present-but-non-string
field, which is treated the same as an unrecognized string rather than as
absent. `resolution_available_here` is a hardcoded `false`: it does not change
until this server can reach the portal's endpoints, which is the limit this
whole section exists to document. The block adds no device configuration to
the read — only the state string, a length-capped and ASCII-filtered copy of
the raw value, and the static advisory text above.

## Still unverified

Not answered by the spec; do not write code that assumes an answer:

- Rate-limit numbers, window, and whether `Retry-After` or any `X-RateLimit-*`
  response headers are sent. Every operation declares `"headers": {}`.
- Whether `x-oauth2-token` expects a raw JWT or an opaque token, and the token
  endpoint / refresh flow for the OAuth path.
- Concrete polling interval and timeout guidance. The status schema does
  enumerate `PENDING`, `IN_PROGRESS`, `COMPLETED`, `PARTIAL_SUCCESS`, and
  `FAILED`, but does not recommend how often or how long a client should poll.
- Whether `409` is safely retryable per operation.
- Region-specific base URLs. The spec declares exactly one server; whether
  other tenants land on a different host is unconfirmed.
- Real payload examples. Spec examples are placeholder `"string"` values, so
  field semantics for policy/rule bodies need a live tenant to confirm.
- **Response payload shape for the 24 generic read families** added in Phase B
  (security profiles, URL objects, proxy and ICAP servers, IPS signatures,
  identity objects, rule options, variable zones). Their collection paths,
  `uuid` keying, and `from`/`size`/`fields` support are read from the spec;
  their *responses* have not been observed, because the lab tenant holds no
  objects in any of them. Auth and dispatch are confirmed live; payload shape
  is not.
