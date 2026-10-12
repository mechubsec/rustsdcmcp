#!/usr/bin/env bash
set -euo pipefail

has_single_exact_key() {
    local key=$1 expected=$2 file=$3
    awk -F= -v key="$key" -v expected="$expected" '
        $1 == key { count += 1; matches += ($0 == expected) }
        END { exit !(count == 1 && matches == 1) }
    ' "$file"
}

[[ $# -eq 1 ]] || {
    printf '%s\n' 'exactly one archive argument is required' >&2
    exit 1
}
archive=$1
if [[ ! -f "$archive" ]]; then
    printf '%s\n' "archive not found: ${archive:-<missing>}" >&2
    exit 1
fi
command -v jq >/dev/null || {
    printf '%s\n' 'jq is required for package smoke SBOM validation' >&2
    exit 1
}

archive=$(CDPATH='' cd -- "$(dirname -- "$archive")" && pwd -P)/$(basename -- "$archive")
checksum="${archive}.sha256"
if [[ ${SDCMCP_SMOKE_SKIP_CHECKSUM:-0} == 1 ]]; then
    :
elif [[ -f "$checksum" ]]; then
    (
        cd "$(dirname -- "$archive")"
        sha256sum -c "$(basename -- "$checksum")"
    )
else
    printf '%s\n' "sibling checksum not found: $checksum" >&2
    exit 1
fi
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
members_file="$work_dir/members"
types_file="$work_dir/types"
tar -tzf "$archive" >"$members_file"
tar -tvz --numeric-owner -f "$archive" >"$types_file"

[[ -s "$members_file" ]] || {
    printf '%s\n' 'archive is empty' >&2
    exit 1
}
if grep -Eq '(^/|(^|/)\.\.?(/|$)|//)' "$members_file"; then
    printf '%s\n' 'archive has unsafe member paths' >&2
    exit 1
fi
if awk 'substr($0, 1, 1) != "-" && substr($0, 1, 1) != "d" { exit 1 }' "$types_file"; then
    :
else
    printf '%s\n' 'archive contains a non-regular member or link' >&2
    exit 1
fi

mapfile -t roots < <(sed 's:/*$::' "$members_file" | awk -F/ 'NF { print $1 }' | LC_ALL=C sort -u)
[[ ${#roots[@]} -eq 1 && -n ${roots[0]} ]] || {
    printf '%s\n' 'archive must contain exactly one root' >&2
    exit 1
}
package_root=${roots[0]}
case "$package_root" in
    *[!A-Za-z0-9._-]*)
        printf '%s\n' 'archive root has unsafe characters' >&2
        exit 1
        ;;
esac

expected=(
    "$package_root"
    "$package_root/bin"
    "$package_root/config"
    "$package_root/packaging"
    "$package_root/packaging/lxc"
    "$package_root/packaging/systemd"
    "$package_root/docs"
    "$package_root/bin/rustsdcmcp"
    "$package_root/config/sdc.json.example"
    "$package_root/packaging/lxc/install.sh"
    "$package_root/packaging/systemd/rustsdcmcp.service"
    "$package_root/packaging/systemd/rustsdcmcp.sysusers"
    "$package_root/packaging/systemd/rustsdcmcp.tmpfiles"
    "$package_root/packaging/systemd/rustsdcmcp-tunnel.service.example"
    "$package_root/BUILD-INFO"
    "$package_root/SBOM.cdx.json"
    "$package_root/README.md"
    "$package_root/LICENSE"
    "$package_root/SECURITY.md"
    "$package_root/docs/operations.md"
)
declare -A allowed=()
declare -A seen=()
for member in "${expected[@]}"; do
    allowed["$member"]=1
done
while IFS= read -r member; do
    member=${member%/}
    [[ -n "$member" && ${allowed[$member]+yes} ]] || {
        printf '%s\n' "archive has unexpected member: $member" >&2
        exit 1
    }
    [[ ! ${seen[$member]+yes} ]] || {
        printf '%s\n' "archive has duplicate member: $member" >&2
        exit 1
    }
    seen["$member"]=1
done <"$members_file"
[[ ${#seen[@]} -eq ${#expected[@]} ]] || {
    printf '%s\n' 'archive payload is incomplete' >&2
    exit 1
}

build_info="$work_dir/BUILD-INFO"
tar -xOf "$archive" "$package_root/BUILD-INFO" >"$build_info"
has_single_exact_key mecmcp_ref 'mecmcp_ref=v0.27.0' "$build_info" || {
    printf '%s\n' 'archive BUILD-INFO has the wrong mecmcp ref' >&2
    exit 1
}
recorded_sha=$(sed -n 's/^binary_sha256=//p' "$build_info")
[[ "$recorded_sha" =~ ^[0-9a-f]{64}$ ]] || {
    printf '%s\n' 'archive BUILD-INFO binary_sha256 is missing or malformed' >&2
    exit 1
}
binary="$work_dir/rustsdcmcp-bin"
tar -xOf "$archive" "$package_root/bin/rustsdcmcp" >"$binary"
[[ "$recorded_sha" == "$(sha256sum "$binary" | cut -d' ' -f1)" ]] || {
    printf '%s\n' 'archive BUILD-INFO binary_sha256 does not match the shipped binary' >&2
    exit 1
}

sbom="$work_dir/SBOM.cdx.json"
tar -xOf "$archive" "$package_root/SBOM.cdx.json" >"$sbom"
jq -e '
        .bomFormat == "CycloneDX"
        and (.metadata.component.name == "rustsdcmcp")
        and (.components | type == "array" and length > 0)
        and any(.components[]; .name == "serde")
        and (
            ([
                .components[]
                | select(.name? | strings | startswith("mecmcp-"))
                | [.name, .version]
            ] | sort)
            == [
                ["mecmcp-audit", "0.27.0"],
                ["mecmcp-auth", "0.27.0"],
                ["mecmcp-changeset", "0.27.0"],
                ["mecmcp-redact", "0.27.0"],
                ["mecmcp-runtime", "0.27.0"],
                ["mecmcp-secret", "0.27.0"],
                ["mecmcp-server", "0.27.0"],
                ["mecmcp-transport", "0.27.0"]
            ]
        )
        and (tostring | contains("v0.8.0") | not)
        and (tostring | contains("70ac3d8fb5f27db3257d11aef28bd09587f085e1") | not)
    ' "$sbom" >/dev/null || {
        printf '%s\n' 'archive SBOM is not a CycloneDX JSON document' >&2
        exit 1
    }
if grep -Eq '"/(home|workspace|workspaces)/' "$sbom"; then
    printf '%s\n' 'archive SBOM contains an absolute repository or worktree path' >&2
    exit 1
fi

tar -xzf "$archive" -C "$work_dir" --no-same-owner --no-same-permissions
installer="$work_dir/$package_root/packaging/lxc/install.sh"
[[ -x "$installer" && ! -L "$installer" ]] || {
    printf '%s\n' 'packaged installer is not an executable regular file' >&2
    exit 1
}

fresh_root="$work_dir/fresh-root"
fresh_output="$work_dir/fresh-output"
SDCMCP_INSTALL_ROOT="$fresh_root" \
SDCMCP_INSTALL_SKIP_USER=1 \
SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1 \
    "$installer" >"$fresh_output"
grep -Fqx '1. Create config: install -o root -g rustsdcmcp -m 0640 /etc/rustsdcmcp/sdc.json.example /etc/rustsdcmcp/sdc.json, then edit /etc/rustsdcmcp/sdc.json.' "$fresh_output"
[[ ! -e "$fresh_root/etc/rustsdcmcp/sdc.json" ]] || {
    printf '%s\n' 'fresh install created live sdc.json' >&2
    exit 1
}
[[ ! -e "$fresh_root/etc/rustsdcmcp/credentials.env" ]] || {
    printf '%s\n' 'fresh install created credentials.env' >&2
    exit 1
}
jq -e '. == {"version": 1, "tokens": []}' "$fresh_root/var/lib/rustsdcmcp/tokens.json" >/dev/null
[[ $(stat -c %a "$fresh_root/var/lib/rustsdcmcp/tokens.json") == 600 ]] || exit 1
[[ $(stat -c %a "$fresh_root/etc/rustsdcmcp/audit-hmac.key") == 600 ]] || exit 1
[[ $(wc -c <"$fresh_root/etc/rustsdcmcp/audit-hmac.key") == 32 ]] || exit 1
[[ $(stat -c %a "$fresh_root/etc/rustsdcmcp/sdc.json.example") == 640 ]] || exit 1

stage_root="$work_dir/stage-root"
mkdir -p "$stage_root/etc/rustsdcmcp" "$stage_root/var/lib/rustsdcmcp" \
    "$stage_root/etc/systemd/system"
printf '%s\n' 'existing config' >"$stage_root/etc/rustsdcmcp/sdc.json"
printf '%s\n' 'existing credentials' >"$stage_root/etc/rustsdcmcp/credentials.env"
printf '%s\n' 'existing tokens' >"$stage_root/var/lib/rustsdcmcp/tokens.json"
printf '%s\n' 'existing audit key' >"$stage_root/etc/rustsdcmcp/audit-hmac.key"
printf '%s\n' 'existing changeset state' >"$stage_root/var/lib/rustsdcmcp/changeset-state.json"
printf '%s\n' 'custom unit' >"$stage_root/etc/systemd/system/rustsdcmcp.service"
preserved=(
    "$stage_root/etc/rustsdcmcp/sdc.json"
    "$stage_root/etc/rustsdcmcp/credentials.env"
    "$stage_root/var/lib/rustsdcmcp/tokens.json"
    "$stage_root/etc/rustsdcmcp/audit-hmac.key"
    "$stage_root/var/lib/rustsdcmcp/changeset-state.json"
    "$stage_root/etc/systemd/system/rustsdcmcp.service"
)
sha256sum "${preserved[@]}" >"$work_dir/preserved.sha256"

for _ in 1 2; do
    SDCMCP_INSTALL_ROOT="$stage_root" \
    SDCMCP_INSTALL_SKIP_USER=1 \
    SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
    SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1 \
        "$installer" >/dev/null
done
sha256sum -c "$work_dir/preserved.sha256" >/dev/null

unsafe_root="$work_dir/unsafe-root"
sentinel_dir="$work_dir/sentinels"
mkdir -p "$unsafe_root/etc/rustsdcmcp" "$unsafe_root/var/lib/rustsdcmcp" "$sentinel_dir"
printf '%s\n' token-sentinel >"$sentinel_dir/tokens"
printf '%s\n' hmac-sentinel >"$sentinel_dir/hmac"
chmod 0644 "$sentinel_dir/tokens" "$sentinel_dir/hmac"
ln -s "$sentinel_dir/tokens" "$unsafe_root/var/lib/rustsdcmcp/tokens.json"
ln -s "$sentinel_dir/hmac" "$unsafe_root/etc/rustsdcmcp/audit-hmac.key"
if SDCMCP_INSTALL_ROOT="$unsafe_root" \
    SDCMCP_INSTALL_SKIP_USER=1 \
    SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
    SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1 \
    "$installer" >/dev/null 2>&1; then
    printf '%s\n' 'installer accepted unsafe token or HMAC destination' >&2
    exit 1
fi
printf '%s\n' token-sentinel | cmp -s - "$sentinel_dir/tokens"
printf '%s\n' hmac-sentinel | cmp -s - "$sentinel_dir/hmac"
[[ $(stat -c %a "$sentinel_dir/tokens") == 644 ]] || exit 1
[[ $(stat -c %a "$sentinel_dir/hmac") == 644 ]] || exit 1

parent_unsafe_root="$work_dir/parent-unsafe-root"
parent_sentinel_dir="$work_dir/parent-sentinels"
mkdir -p "$parent_unsafe_root" "$parent_sentinel_dir"
printf '%s\n' parent-sentinel >"$parent_sentinel_dir/sentinel"
chmod 0644 "$parent_sentinel_dir/sentinel"
ln -s "$parent_sentinel_dir" "$parent_unsafe_root/var"
if SDCMCP_INSTALL_ROOT="$parent_unsafe_root" \
    SDCMCP_INSTALL_SKIP_USER=1 \
    SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
    SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1 \
    "$installer" >/dev/null 2>&1; then
    printf '%s\n' 'installer accepted an unsafe state parent directory' >&2
    exit 1
fi
printf '%s\n' parent-sentinel | cmp -s - "$parent_sentinel_dir/sentinel"
[[ $(stat -c %a "$parent_sentinel_dir/sentinel") == 644 ]] || exit 1
[[ ! -e "$parent_sentinel_dir/lib/rustsdcmcp" ]] || exit 1

skip_user_root="$work_dir/skip-user-root"
fake_bin="$work_dir/fake-bin"
mkdir -p "$skip_user_root" "$fake_bin"
printf '%s\n' '#!/usr/bin/env bash' 'exit 1' >"$fake_bin/getent"
chmod 0755 "$fake_bin/getent"
if PATH="$fake_bin:$PATH" \
    SDCMCP_INSTALL_ROOT="$skip_user_root" \
    SDCMCP_INSTALL_TEST_LIVE=1 \
    SDCMCP_INSTALL_SKIP_USER=1 \
    SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
    SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1 \
    "$installer" >/dev/null 2>&1; then
    printf '%s\n' 'installer accepted missing service identity with SKIP_USER=1' >&2
    exit 1
fi
[[ ! -e "$skip_user_root/etc/rustsdcmcp" ]] || exit 1

# The live-install test seam is stage-only.  Every host-facing operation must
# be disabled before the installer even inspects the package payload.
strict_live_fake_bin="$work_dir/strict-live-fake-bin"
mkdir -p "$strict_live_fake_bin"
for command in apt-get systemctl systemd-sysusers systemd-tmpfiles getent; do
    cat >"$strict_live_fake_bin/$command" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${0##*/}" >>"$SDCMCP_STRICT_LIVE_MARKER"
exit 0
EOF
    chmod 0755 "$strict_live_fake_bin/$command"
done
for missing_flag in SDCMCP_INSTALL_SKIP_USER SDCMCP_INSTALL_SKIP_RUNTIME_DEPS SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD; do
    strict_live_root="$work_dir/strict-live-${missing_flag##*_}"
    strict_live_marker="$work_dir/strict-live-${missing_flag##*_}.marker"
    if env \
        PATH="$strict_live_fake_bin:$PATH" \
        SDCMCP_STRICT_LIVE_MARKER="$strict_live_marker" \
        SDCMCP_INSTALL_ROOT="$strict_live_root" \
        SDCMCP_INSTALL_TEST_LIVE=1 \
        SDCMCP_INSTALL_SKIP_USER=1 \
        SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1 \
        SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
        "$missing_flag=0" \
        "$installer" >/dev/null 2>&1; then
        printf '%s\n' "installer accepted test-live mode without $missing_flag=1" >&2
        exit 1
    fi
    [[ ! -e "$strict_live_marker" ]] || {
        printf '%s\n' "test-live mode invoked a host-facing command without $missing_flag=1" >&2
        exit 1
    }
    [[ ! -e "$strict_live_root/etc/rustsdcmcp" ]] || {
        printf '%s\n' "test-live mode mutated its stage root without $missing_flag=1" >&2
        exit 1
    }
done

conflict_package="$work_dir/repeated-service-conflict"
cp -a -- "$work_dir/$package_root" "$conflict_package"
printf '%s\n' ' [Service] ' 'ReadOnlyPaths = /tmp' >>"$conflict_package/packaging/systemd/rustsdcmcp.service"
if SDCMCP_INSTALL_ROOT="$work_dir/repeated-service-root" \
    SDCMCP_INSTALL_SKIP_USER=1 \
    SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
    SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1 \
    "$conflict_package/packaging/lxc/install.sh" >/dev/null 2>&1; then
    printf '%s\n' 'installer accepted a repeated whitespace Service section conflict' >&2
    exit 1
fi

stale_journal_unsafe_root="$work_dir/stale-journal-unsafe-root"
stale_journal_sentinel_dir="$work_dir/stale-journal-sentinels"
mkdir -p "$stale_journal_unsafe_root/etc/systemd" "$stale_journal_sentinel_dir"
printf '%s\n' stale-journal-sentinel >"$stale_journal_sentinel_dir/mecmcp.conf"
chmod 0644 "$stale_journal_sentinel_dir/mecmcp.conf"
ln -s "$stale_journal_sentinel_dir" "$stale_journal_unsafe_root/etc/systemd/journald.conf.d"
if SDCMCP_INSTALL_ROOT="$stale_journal_unsafe_root" \
    SDCMCP_INSTALL_SKIP_USER=1 \
    SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
    SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1 \
    "$installer" >/dev/null 2>&1; then
    printf '%s\n' 'installer accepted unsafe stale journal path with symlinked parent' >&2
    exit 1
fi
printf '%s\n' stale-journal-sentinel | cmp -s - "$stale_journal_sentinel_dir/mecmcp.conf"
[[ $(stat -c %a "$stale_journal_sentinel_dir/mecmcp.conf") == 644 ]] || exit 1
printf '%s\n' 'package smoke passed'
