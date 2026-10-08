#!/usr/bin/env bash
# Regression test: the installer must refuse to operate on tokens.json or
# audit-hmac.key when the existing path is not a regular file, and must
# leave whatever that path points to untouched.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)"

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

FAKE_PACKAGE="$STAGING/rustsdcmcp-test"
install -d "$FAKE_PACKAGE/bin" "$FAKE_PACKAGE/config" "$FAKE_PACKAGE/packaging/lxc" \
    "$FAKE_PACKAGE/packaging/systemd" "$FAKE_PACKAGE/docs"

cp "$PACKAGE_ROOT/packaging/lxc/install.sh" "$FAKE_PACKAGE/packaging/lxc/install.sh"
cp "$PACKAGE_ROOT/packaging/systemd/rustsdcmcp.service" "$FAKE_PACKAGE/packaging/systemd/"
cp "$PACKAGE_ROOT/packaging/systemd/rustsdcmcp.sysusers" "$FAKE_PACKAGE/packaging/systemd/"
cp "$PACKAGE_ROOT/packaging/systemd/rustsdcmcp.tmpfiles" "$FAKE_PACKAGE/packaging/systemd/"
cp "$PACKAGE_ROOT/examples/sdc.example.json" "$FAKE_PACKAGE/config/sdc.json.example"

printf '%s\n' 'example service unit for a leased tunnel' \
    >"$FAKE_PACKAGE/packaging/systemd/rustsdcmcp-tunnel.service.example"
printf '%s\n' '# fixture' >"$FAKE_PACKAGE/README.md"
printf '%s\n' '# fixture' >"$FAKE_PACKAGE/LICENSE"
printf '%s\n' '# fixture' >"$FAKE_PACKAGE/SECURITY.md"
printf '%s\n' '# fixture' >"$FAKE_PACKAGE/docs/operations.md"
printf '%s\n' '{"bomFormat":"CycloneDX","components":[]}' >"$FAKE_PACKAGE/SBOM.cdx.json"

cat >"$FAKE_PACKAGE/bin/rustsdcmcp" <<'BIN'
#!/bin/sh
if [ "$1" = "--validate-package" ]; then
    exit 0
fi
echo "fake binary"
BIN
chmod +x "$FAKE_PACKAGE/bin/rustsdcmcp" "$FAKE_PACKAGE/packaging/lxc/install.sh"

binary_sha256=$(sha256sum "$FAKE_PACKAGE/bin/rustsdcmcp" | cut -d' ' -f1)
cat >"$FAKE_PACKAGE/BUILD-INFO" <<EOF
release_status=release
version=0.1.0
git_commit=$(printf '%040d' 0)
source_date_epoch=1700000000
target=x86_64-unknown-linux-gnu
mecmcp_ref=v0.26.0
glibc_floor=2.31
rustc=unknown (fixture)
binary_sha256=$binary_sha256
EOF

INSTALL_ROOT="$STAGING/staged"
export SDCMCP_INSTALL_ROOT="$INSTALL_ROOT"
export SDCMCP_INSTALL_SKIP_USER=1
export SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1
export SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1

cd "$FAKE_PACKAGE"

STATE_DIR="$INSTALL_ROOT/var/lib/rustsdcmcp"
CONFIG_DIR="$INSTALL_ROOT/etc/rustsdcmcp"
CANARY="$STAGING/canary"
printf 'canary-untouched\n' >"$CANARY"
chmod 0644 "$CANARY"

assert_refused_and_canary_untouched() {
    local label="$1" canary_perms_before="$2" canary_perms_after
    canary_perms_after="$(stat -c '%a' "$CANARY")"
    if [[ "$canary_perms_after" != "$canary_perms_before" ]]; then
        echo "FAIL: $label: canary perms changed ($canary_perms_before -> $canary_perms_after)" >&2
        exit 1
    fi
    if [[ "$(cat "$CANARY")" != "canary-untouched" ]]; then
        echo "FAIL: $label: canary content was overwritten" >&2
        exit 1
    fi
}

# --- First install: establishes the baseline state dir/tokens.json. ---
./packaging/lxc/install.sh >/dev/null

if [[ ! -f "$STATE_DIR/tokens.json" ]]; then
    echo "FAIL: baseline install did not create $STATE_DIR/tokens.json" >&2
    exit 1
fi
if [[ ! -f "$CONFIG_DIR/audit-hmac.key" ]]; then
    echo "FAIL: baseline install did not create $CONFIG_DIR/audit-hmac.key" >&2
    exit 1
fi

# --- tokens.json: replace the real file with a path pointing at the canary. ---
rm -f "$STATE_DIR/tokens.json"
ln -s "$CANARY" "$STATE_DIR/tokens.json"
canary_before="$(stat -c '%a' "$CANARY")"

if ./packaging/lxc/install.sh >/dev/null 2>"$STAGING/tokens-refusal.log"; then
    echo "FAIL: installer did not refuse an unsafe tokens.json path" >&2
    exit 1
fi
grep -q "unsafe destination file" "$STAGING/tokens-refusal.log" \
    || { echo "FAIL: unexpected refusal message for tokens.json" >&2; cat "$STAGING/tokens-refusal.log" >&2; exit 1; }
assert_refused_and_canary_untouched "tokens.json" "$canary_before"
rm -f "$STATE_DIR/tokens.json"

# --- audit-hmac.key: replace the real file left by the baseline install. ---
rm -f "$CONFIG_DIR/audit-hmac.key"
ln -s "$CANARY" "$CONFIG_DIR/audit-hmac.key"
canary_before="$(stat -c '%a' "$CANARY")"

if ./packaging/lxc/install.sh >/dev/null 2>"$STAGING/audit-key-refusal.log"; then
    echo "FAIL: installer did not refuse an unsafe audit-hmac.key path" >&2
    exit 1
fi
grep -q "unsafe destination file" "$STAGING/audit-key-refusal.log" \
    || { echo "FAIL: unexpected refusal message for audit-hmac.key" >&2; cat "$STAGING/audit-key-refusal.log" >&2; exit 1; }
assert_refused_and_canary_untouched "audit-hmac.key" "$canary_before"

echo "PASS: installer refuses an unsafe tokens.json and audit-hmac.key path"
