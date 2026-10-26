# How to set up a rustsdcmcp LXC from scratch

Builds one Proxmox LXC running `rustsdcmcp`, in either **lab mode** or
**two-person** mode. Written from a rebuild performed on 2026-09-07, not from
memory: every command here was run.

Two rigs are normally built as a pair, because they test different things:

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation, recorded as `approval_waiver=lab-mode` | ordinary tool work, reads, single-operator change sets |
| **two-person** (no flag) | a second principal must approve before apply | anything that must prove the approval gate holds |

Never point a lab-mode server at production devices. It says so itself at
startup, in a `WARN`.

## 0. Before you start

You need:

- A Proxmox node, a container template, and a free VMID and IP.
- **The SDC API token and tenant configuration.** Building the container is the
  easy part; these are the part you need first. If you are rebuilding an
  existing rig, back them up first — see [Rebuilding](#rebuilding-an-existing-rig).

Check the template is present:

```bash
pveam list local | grep debian-13
# local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst
```

## 1. Get a binary that will actually run

**Do not `cargo build --release` on your workstation and copy the binary in.**
glibc is forward-incompatible: a binary linked against a newer glibc will not
start on an older one, and it fails at service start with a loader error *after*
the old binary has been replaced — an outage, not a build failure.

Take the binary from the release image, which CI builds against the right glibc.
The extraction happens in step 2 alongside the commit checkout, so the SBOM,
config files, and installer match the binary.

## 2. Assemble the install package

`scripts/build-package.sh` builds the package. Point it at the binary you just
extracted rather than letting it compile one:

```bash
cd /path/to/rustsdcmcp
mkdir -p target/release

# Pull and extract the binary from the release image
docker pull ghcr.io/mechubsec/rustsdcmcp:0.5.0
docker create --name sx ghcr.io/mechubsec/rustsdcmcp:0.5.0
docker cp sx:/usr/local/bin/rustsdcmcp target/release/rustsdcmcp
docker rm sx

# Obtain the binary's source commit from the image OCI label
source_commit=$(docker inspect ghcr.io/mechubsec/rustsdcmcp:0.5.0 \
    --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
# Or from the release tag if the image label is unavailable (peel annotated tags):
# source_commit=$(git rev-parse v0.5.0^{commit})

SDCMCP_PACKAGE_SKIP_BUILD=1 SDCMCP_BINARY_SOURCE_COMMIT="$source_commit" \
    scripts/build-package.sh
# >> Wrote dist/<commit>/rustsdcmcp_0.5.0.<date>.<commit>_amd64.tar.gz
```

**The source commit is required**: the package records it as provenance in
BUILD-INFO, and `install.sh` rejects any BUILD-INFO whose `git_commit` is not a
40-character hex value. Supplying the wrong commit produces a package labeled
with false provenance; omitting it entirely fails at package time with a clear
error.

**When the binary's commit differs from the packaging checkout**: BUILD-INFO
records both as `git_commit` (the binary) and `payload_commit` (the config,
installer, and SBOM). The SBOM describes the packaging checkout's dependency
graph, not the binary's. A release built and packaged by CI avoids this split —
it is the preferred path.

**This repo has the strictest installer in the family.** `packaging/lxc/install.sh`
validates a complete payload — `bin/rustsdcmcp`, `config/sdc.json.example`, four
`packaging/systemd/*` files, `BUILD-INFO`, `SBOM.cdx.json`, `README.md`,
`LICENSE`, `SECURITY.md`, `docs/operations.md` — and it validates **BUILD-INFO at
install time**, so a stale version or mecmcp_ref fails on the container even
though CI was green. A package assembled from the wrong commit or with stale
embedded files is rejected at install.

## 3. Create the container

`nesting=1` is **required**. systemd 257 degrades badly in an unprivileged LXC
without it.

```bash
pct create 614 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
    --hostname test-twoperson-sdc \
    --cores 1 --memory 512 --swap 512 \
    --rootfs local-lvm:4 \
    --unprivileged 1 --features nesting=1 \
    --net0 name=eth0,bridge=vmbr0,firewall=1,gw=192.0.2.1,ip=192.0.2.10/24,type=veth \
    --onboot 0 --ostype debian \
    --tags "disposable;test;twoperson"

pct start 614
```

512 MB and one core is enough. The tags matter: `disposable` is what marks a
guest as safe to destroy, and the fleet's own safety rules key on it.

For lab mode, use VMID 615 with IP `.235`, hostname `test-labmode-sdc`, and tag
`labmode` instead of `twoperson`.

## 4. Install

```bash
pct push 614 dist/<commit>/rustsdcmcp_0.5.0.*_amd64.tar.gz /tmp/pkg.tar.gz
pct exec 614 -- bash -lc 'cd /tmp && tar xzf pkg.tar.gz && cd rustsdcmcp_*/ && bash packaging/lxc/install.sh'
```

`install.sh` creates the `rustsdcmcp` service user, installs the binary and the
unit, and stops there. **The service will not start yet** — it has no
configuration, and it says so.

The installer notes `IPAddressDeny` is inert in unprivileged LXC. That is
expected and true — mention it so nobody reads it as a fault.

## 5. Configuration and credentials

Place the configuration and credential files:

```bash
pct push 614 sdc.json         /etc/rustsdcmcp/sdc.json
pct push 614 credentials.env  /etc/rustsdcmcp/credentials.env
```

Then fix ownership and modes. **Do this for every credential file at once.** The
token-command mode checks (`rustsdcmcp token add` and similar) verify their
target file is not group- or world-readable and fail one at a time if wrong —
getting this wrong costs one command retry per file. The error names the file
and the required mode:

```
mode 0644 is group- or world-accessible (owner uid 999, this process uid 999);
run: chmod 600 /var/lib/rustsdcmcp/tokens.json
```

`credentials.env` is read via systemd `EnvironmentFile` and never inspected for
mode by the service itself — the `chmod 0600` below is an operator-enforced
requirement, not a runtime-validated one. Apply it anyway to limit credential
exposure.

Set the correct mode per file:

```bash
pct exec 614 -- bash -lc '
    chown -R rustsdcmcp:rustsdcmcp /etc/rustsdcmcp
    chmod 0640 /etc/rustsdcmcp/sdc.json
    chmod 0600 /etc/rustsdcmcp/credentials.env
    install -d -o rustsdcmcp -g rustsdcmcp -m 0700 /var/lib/rustsdcmcp
    chmod 0600 /var/lib/rustsdcmcp/tokens.json
'
```

`sdc.json` is 0640 because it contains no secrets — only the tenant alias,
endpoint URL, and expected tenant ID. The credentials live in `credentials.env`.

## 6. The site drop-in

The shipped unit binds `127.0.0.1` and is deliberately conservative. Site
configuration goes in a drop-in, which keeps the shipped unit replaceable.
**The installer does NOT create `/etc/systemd/system/rustsdcmcp.service.d/`**;
`mkdir -p` it first:

```bash
pct exec 614 -- mkdir -p /etc/systemd/system/rustsdcmcp.service.d
```

`/etc/systemd/system/rustsdcmcp.service.d/override.conf`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/rustsdcmcp \
    --device-mapping /etc/rustsdcmcp/sdc.json \
    --transport streamable-http \
    --host 0.0.0.0 \
    --port 30032 \
    --allow-insecure-bind \
    --tokens-file /var/lib/rustsdcmcp/tokens.json \
    --audit-format json \
    --audit-journald \
    --audit-log-file /var/lib/rustsdcmcp/audit.jsonl \
    --audit-redact devices=hmac \
    --audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key \
    --allowed-host 192.0.2.10 \
    --allowed-host 192.0.2.10:30032 \
    --allowed-origin http://console.example.org
```

The empty `ExecStart=` is required: it clears the shipped one before setting a
new one. Why site config belongs in a drop-in: the shipped unit carries the
seccomp posture, and replacing it wholesale silently loses that.

**Two-person mode is the same file with no additional flag.** Lab mode adds
`--lab-mode` to the end. That single flag is the whole difference.

`--allow-insecure-bind` permits the plaintext listener on a non-loopback
address. A lab rig accepts this; a real deployment should use `--tls-cert` and
`--tls-key` instead and omit the insecure flag.

`--allowed-host` lists the server authorities clients dial — the HTTP Host
header, here `192.0.2.10` or `192.0.2.10:30032`. `--allowed-origin` lists the
trusted browser application origins that call this server — the Origin header,
such as `http://console.example.org` for a browser console or management UI.
These are configured independently and are usually different values. The origin
scheme must match the server's TLS configuration: this plaintext lab rig takes
`http://` origins, and an HTTPS console origin (`https://...`) requires
`--tls-cert` and `--tls-key` (browsers block HTTP calls from HTTPS pages as
mixed content). Clients sending no Origin header (curl, non-browser MCP clients)
are unaffected by the origin allowlist. A non-loopback `--host` requires at
least one `--allowed-origin` to be present, or the service refuses to start.

Then:

```bash
pct exec 614 -- systemctl daemon-reload
pct exec 614 -- systemctl enable rustsdcmcp.service
pct exec 614 -- systemctl start rustsdcmcp.service
```

**Troubleshooting**:

- **Startup fails with `non-loopback bind '0.0.0.0' requires at least one --allowed-origin`**:
  Add at least one `--allowed-origin` line to the drop-in. Use a documentation
  origin such as `http://console.example.org` if no real browser client exists
  yet (http:// for this plaintext lab rig; https:// would require --tls-cert
  and --tls-key). This is a runtime-validated requirement from `mecmcp-runtime`.

- **Request fails with 421 and `Host '<address>' is not allowed`**:
  The HTTP Host header does not match any `--allowed-host`. Add the address the
  client dialed to the `--allowed-host` list.

- **Request fails with 403 and `Origin '<origin>' is not allowed`**:
  The request's Origin header does not match any `--allowed-origin`. Add the
  calling browser application's origin (scheme + host + port, e.g.
  `http://console.example.org` for a plaintext setup, or
  `https://console.example.org:8443` with TLS) to the `--allowed-origin` list.
  The scheme must match the server's TLS configuration. This affects only
  browser clients that send an Origin header; curl and non-browser MCP clients
  are unaffected.

## 7. Mint a token

```bash
pct exec 614 -- runuser -u rustsdcmcp -- /usr/local/bin/rustsdcmcp token add \
    --tokens-file /var/lib/rustsdcmcp/tokens.json \
    --name my-client --devices 'production' --tools '*' \
    --device-mapping /etc/rustsdcmcp/sdc.json
```

The secret is printed **once** and stored hashed. Two things worth knowing:

- A running server holds its token store in memory. A newly minted or revoked
  token does nothing until the server is restarted: `systemctl restart rustsdcmcp.service`.
  The CLI warns you about this.
- `--tools '*'` is a wildcard that resolves to *read-only tools only*. Write
  tools must be named explicitly, so a wildcard token calling
  `create_sdc_change_set` gets `insufficient_scope`. That is deliberate.

## 8. Verify

Check the four things that actually matter:

```bash
# 1. it is running the version you think
pct exec 614 -- /usr/local/bin/rustsdcmcp --version

# 2. the seccomp posture comes from the SHIPPED unit, not a local patch
pct exec 614 -- systemctl show rustsdcmcp.service -p SystemCallErrorNumber --value   # 1 (EPERM)
pct exec 614 -- grep -l SystemCallErrorNumber /etc/systemd/system/rustsdcmcp.service

# 3. the filter is actually installed, read from the kernel rather than systemd
pid=$(pct exec 614 -- systemctl show -p MainPID --value rustsdcmcp.service)
pct exec 614 -- grep -E '^Seccomp' /proc/$pid/status                                 # Seccomp: 2

# 4. it is serving, and refusing unauthenticated callers
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://192.0.2.10:30032/mcp \
     -H 'content-type: application/json' -d '{}'                                     # 401
```

`401` is the success case here: the transport is up and authentication is being
enforced. A `000` means nothing is listening on that address or port.

Checking `SystemCallErrorNumber` matters. Without it a denied syscall raises
SIGSYS and kills the process mid-request instead of returning `EPERM`; that is
mecmcp#351, and reading it back from the unit is how you know the fix is present.

Also verify `Seccomp: 2` in `/proc/<pid>/status` — this proves the filter is
actually installed, not just configured. A directive can be present in the unit
and enforce nothing.

## 9. Final step: stop the rig

Test rigs here are stopped by default; started only when needed, stopped again at
completion.

```bash
pct shutdown 614
```

Use `pct shutdown`, not `pct stop`. `shutdown` asks systemd inside the container
to shut down cleanly so the service can flush its change-set state to disk. `stop`
kills the container immediately, and a process killed mid-write is how an
operation ends up non-terminal and blocks the tenant for the next caller.

## Rebuilding an existing rig

Back the credentials out **before** destroying anything. `pct mount` reads a
stopped container's filesystem without starting it:

```bash
pct mount 614
mkdir -p /root/backup-614/etc /root/backup-614/var/lib /root/backup-614/systemd
cp -a /var/lib/lxc/614/rootfs/etc/rustsdcmcp        /root/backup-614/etc/
cp -a /var/lib/lxc/614/rootfs/var/lib/rustsdcmcp    /root/backup-614/var/lib/
cp -a /var/lib/lxc/614/rootfs/etc/systemd/system/rustsdcmcp.service.d /root/backup-614/systemd/
pct config 614 > /root/backup-614/pct-config.txt
pct unmount 614
```

`pct-config.txt` is worth keeping: it is the network, resources and tags you will
want to reproduce.

Restoring `tokens.json` rather than minting fresh tokens keeps existing clients
working — the secrets are hashed and cannot be recovered, so re-minting means
reconfiguring every client that talks to this rig.

A fresh install creates an empty `/var/lib/rustsdcmcp/tokens.json`, and the
step 6 override points `--tokens-file` there. Restore the store that was **live**
on the old rig into that path, and do not restore the old drop-in's
`--tokens-file` over the new one. The old drop-in names which store was live;
file size does not, because an installer-created empty store is not zero bytes.
Releases before #162 let an empty `/var/lib` store shadow an explicitly
configured `/etc` store, which rejected every token.

Run this on the Proxmox host after the rebuilt rig's install and step 6 override
are in place:

```bash
# Which store was live? The active (uncommented) --tokens-file in the backed-up
# drop-in names it. Pre-#92 units and overrides that do not restate ExecStart name
# none, so fall back to whichever backed-up store actually holds tokens.
live=$(grep -hv '^[[:space:]]*#' /root/backup-614/systemd/rustsdcmcp.service.d/*.conf 2>/dev/null \
    | grep -o -- '--tokens-file [^ \\]*' | tail -1 | awk '{print $2}')
if [[ -z "$live" ]]; then
    for cand in /var/lib/rustsdcmcp/tokens.json /etc/rustsdcmcp/tokens.json; do
        if python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("tokens") else 1)' \
            "/root/backup-614$cand" 2>/dev/null; then
            live=$cand
            break
        fi
    done
fi
echo "restoring the live store: ${live:-NONE, so no backed-up store holds tokens and fresh ones must be minted}"

# Restore only if a live store was found. pct push and pct exec need the guest running.
if [[ -n "$live" ]]; then
    inv=
    pct start 614
    pct push 614 "/root/backup-614$live" /var/lib/rustsdcmcp/tokens.json \
        --user rustsdcmcp --group rustsdcmcp --perms 0600 &&
        pct exec 614 -- systemctl restart rustsdcmcp &&   # restart, not reload
        inv=$(pct exec 614 -- systemctl show -p InvocationID --value rustsdcmcp)
    # The unit is Type=simple and verifies the tenant before loading tokens, so
    # poll for the load record of THIS invocation, and fail loudly on timeout.
    loaded=
    for _ in $(seq 1 30); do
        if loaded=$(pct exec 614 -- journalctl _SYSTEMD_INVOCATION_ID="$inv" -o cat \
                | grep -m1 'token store loaded'); then
            echo "$loaded"
            break
        fi
        sleep 1
    done
    # `false`, not `exit`, so an interactive shell is not closed on failure.
    [[ -n "$loaded" ]] || { echo "RESTORE NOT CONFIRMED: no token-load record for invocation $inv" >&2; false; }
else
    echo "nothing to restore: mint fresh tokens as in section 7 and reconfigure clients"
fi
```

After a restore, the journal line must report the restored token count. When
nothing held tokens, follow [section 7](#7-mint-a-token) instead.
