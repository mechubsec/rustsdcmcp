#!/usr/bin/env bash
# The state directory the installer writes tokens.json and audit-hmac.key
# into is writable by the unprivileged service account. A compromised
# service process can pre-place a symlink at either path before the next
# install/upgrade runs as root. The installer must refuse to create, chmod,
# or chown through that symlink rather than writing through it.
#
# This runs the REAL installer from the built package, both on a path that
# never existed before (first install) and on a path that already existed
# as a regular file and was swapped for a symlink before a second install
# (upgrade) — the two points in install.sh where these files are touched.
set -euo pipefail

ARCHIVE="${1:?usage: test-symlink-hijack.sh <package.tar.gz>}"
[[ -f "$ARCHIVE" ]] || { echo "archive not found: $ARCHIVE" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

tar -xzf "$ARCHIVE" -C "$WORK"
mapfile -t roots < <(find "$WORK" -mindepth 1 -maxdepth 1 -type d -print)
[[ "${#roots[@]}" -eq 1 ]] || { echo "archive must contain one package root" >&2; exit 1; }
INSTALLER="${roots[0]}/packaging/lxc/install.sh"
[[ -x "$INSTALLER" ]] || { echo "installer not executable: $INSTALLER" >&2; exit 1; }

run_installer() {
    SDCMCP_INSTALL_ROOT="$1" \
        SDCMCP_INSTALL_SKIP_USER=1 \
        SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
        SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1 \
        "$INSTALLER" >"$2" 2>&1
}

assert_canary_untouched() {
    local canary="$1" expected="$2"
    [[ "$(cat "$canary")" == "$expected" ]] \
        || { echo "FAIL: installer wrote through a symlink, modifying $canary" >&2; exit 1; }
}

# --- Scenario 1: fresh install, path pre-occupied by a symlink before the
# installer has ever run against this root.
for target_rel in /var/lib/rustsdcmcp/tokens.json /etc/rustsdcmcp/audit-hmac.key; do
    label="fresh-$(basename -- "$target_rel")"
    stage="$WORK/$label"
    canary="$WORK/$label-canary"
    printf '%s\n' 'canary-untouched' >"$canary"
    mkdir -p "$stage$(dirname -- "$target_rel")"
    ln -s "$canary" "$stage$target_rel"

    if run_installer "$stage" "$WORK/$label.log"; then
        echo "FAIL: installer did not refuse a pre-existing symlink at $target_rel" >&2
        tail -20 "$WORK/$label.log" >&2
        exit 1
    fi
    [[ -L "$stage$target_rel" ]] \
        || { echo "FAIL: installer replaced the symlink at $target_rel instead of refusing" >&2; exit 1; }
    assert_canary_untouched "$canary" 'canary-untouched'
    echo ">> $label: installer refused, canary untouched"
done

# --- Scenario 2: upgrade. A first install creates the file normally; the
# attacker then swaps it for a symlink before the second install runs,
# exercising the chmod/chown guards rather than just the creation guard.
for target_rel in /var/lib/rustsdcmcp/tokens.json /etc/rustsdcmcp/audit-hmac.key; do
    label="upgrade-$(basename -- "$target_rel")"
    stage="$WORK/$label"
    canary="$WORK/$label-canary"
    printf '%s\n' 'canary-untouched' >"$canary"

    if ! run_installer "$stage" "$WORK/$label.first.log"; then
        echo "FAIL: first install failed for $label" >&2
        tail -20 "$WORK/$label.first.log" >&2
        exit 1
    fi
    [[ -f "$stage$target_rel" && ! -L "$stage$target_rel" ]] \
        || { echo "FAIL: first install did not create a regular file at $target_rel" >&2; exit 1; }

    rm -f "$stage$target_rel"
    ln -s "$canary" "$stage$target_rel"

    if run_installer "$stage" "$WORK/$label.second.log"; then
        echo "FAIL: second install did not refuse a hijacked $target_rel" >&2
        tail -20 "$WORK/$label.second.log" >&2
        exit 1
    fi
    [[ -L "$stage$target_rel" ]] \
        || { echo "FAIL: second install replaced the symlink at $target_rel instead of refusing" >&2; exit 1; }
    assert_canary_untouched "$canary" 'canary-untouched'
    echo ">> $label: installer refused on re-install, canary untouched"
done

echo ">> symlink hijack test passed"
