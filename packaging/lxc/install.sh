#!/usr/bin/env bash
# Install a validated rustsdcmcp package. It deliberately never enables the
# service: an operator must first install real configuration and credentials.
set -euo pipefail

die() {
    printf '%s\n' "installer validation failed: $*" >&2
    exit 1
}

has_single_exact_key() {
    local key=$1 expected=$2 file=$3
    awk -F= -v key="$key" -v expected="$expected" '
        $1 == key { count += 1; matches += ($0 == expected) }
        END { exit !(count == 1 && matches == 1) }
    ' "$file"
}

[[ ! -L "$0" ]] || die 'installer must not be invoked through a symlink'
install_root=${SDCMCP_INSTALL_ROOT:-}
skip_user=${SDCMCP_INSTALL_SKIP_USER:-0}
skip_reload=${SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD:-0}
skip_runtime_deps=${SDCMCP_INSTALL_SKIP_RUNTIME_DEPS:-0}
force_unit=${SDCMCP_FORCE_UNIT:-0}
test_live=${SDCMCP_INSTALL_TEST_LIVE:-0}

for flag in "$skip_user" "$skip_reload" "$skip_runtime_deps" "$force_unit" "$test_live"; do
    [[ "$flag" == 0 || "$flag" == 1 ]] || die 'installer flags must be 0 or 1'
done
if [[ -n "$install_root" ]]; then
    [[ "$install_root" == /* ]] || die 'SDCMCP_INSTALL_ROOT must be absolute'
    command -v realpath >/dev/null || die 'realpath is required to validate SDCMCP_INSTALL_ROOT'
    install_root=$(realpath -m -- "$install_root")
    [[ "$install_root" != / ]] || die 'SDCMCP_INSTALL_ROOT must not resolve to /'
fi
if [[ "$test_live" == 1 ]]; then
    [[ -n "$install_root" ]] || die 'SDCMCP_INSTALL_TEST_LIVE requires a stage root'
    [[ "$skip_user" == 1 ]] || die 'SDCMCP_INSTALL_TEST_LIVE requires SDCMCP_INSTALL_SKIP_USER=1'
    [[ "$skip_runtime_deps" == 1 ]] || die 'SDCMCP_INSTALL_TEST_LIVE requires SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1'
    [[ "$skip_reload" == 1 ]] || die 'SDCMCP_INSTALL_TEST_LIVE requires SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1'
fi

package_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
target_path() {
    if [[ -n "$install_root" ]]; then
        printf '%s%s\n' "$install_root" "$1"
    else
        printf '%s\n' "$1"
    fi
}

required_files=(
    bin/rustsdcmcp config/sdc.json.example packaging/lxc/install.sh
    packaging/systemd/rustsdcmcp.service packaging/systemd/rustsdcmcp.sysusers
    packaging/systemd/rustsdcmcp.tmpfiles
    packaging/systemd/rustsdcmcp-tunnel.service.example
    BUILD-INFO SBOM.cdx.json README.md LICENSE SECURITY.md docs/operations.md
)
required_dirs=(bin config packaging packaging/lxc packaging/systemd docs)

validate_layout() {
    local entry type file_count=0 dir_count=0
    declare -A files=() dirs=()
    for entry in "${required_files[@]}"; do files["$entry"]=1; done
    for entry in "${required_dirs[@]}"; do dirs["$entry"]=1; done
    [[ -d "$package_dir" && ! -L "$package_dir" ]] || die 'package root is not a real directory'
    while IFS=$'\t' read -r entry type; do
        [[ -n "$entry" ]] || die 'package contains an empty member name'
        case "$type" in
            f)
                [[ ${files[$entry]+yes} ]] || die "unexpected package file: $entry"
                ((file_count += 1))
                ;;
            d)
                [[ ${dirs[$entry]+yes} ]] || die "unexpected package directory: $entry"
                ((dir_count += 1))
                ;;
            *) die "package contains non-regular member: $entry" ;;
        esac
    done < <(find -P "$package_dir" -mindepth 1 -printf '%P\t%y\n')
    [[ $file_count -eq ${#required_files[@]} ]] || die 'package payload files are incomplete'
    [[ $dir_count -eq ${#required_dirs[@]} ]] || die 'package payload directories are incomplete'
    for entry in "${required_files[@]}"; do
        [[ -f "$package_dir/$entry" && ! -L "$package_dir/$entry" ]] || die "missing regular payload file: $entry"
    done
    [[ -x "$package_dir/bin/rustsdcmcp" ]] || die 'package binary is not executable'
}

validate_build_info() {
    local build_info="$package_dir/BUILD-INFO"
    grep -Fqx 'release_status=release' "$build_info" || die 'BUILD-INFO release status is invalid'
    grep -Fqx 'version=0.1.0' "$build_info" || die 'BUILD-INFO version is invalid'
    grep -Eq '^git_commit=[0-9a-f]{40}$' "$build_info" || die 'BUILD-INFO commit is invalid'
    grep -Eq '^source_date_epoch=[0-9]+$' "$build_info" || die 'BUILD-INFO epoch is invalid'
    grep -Fqx 'target=x86_64-unknown-linux-gnu' "$build_info" || die 'BUILD-INFO target is invalid'
    has_single_exact_key mecmcp_ref 'mecmcp_ref=v0.26.0' "$build_info" || die 'BUILD-INFO mecmcp ref is invalid'
    grep -Eq '^glibc_floor=[0-9]+(\.[0-9]+)+$' "$build_info" || die 'BUILD-INFO GLIBC floor is invalid'
    # A normal build's rustc field names the compiling toolchain; a
    # skip-build package's names none, and must say so honestly rather than
    # claim a workstation toolchain that never touched the binary.
    grep -Eq '^rustc=(rustc |unknown \()' "$build_info" || die 'BUILD-INFO rustc metadata is invalid'
    local recorded_sha
    recorded_sha=$(sed -n 's/^binary_sha256=//p' "$build_info")
    [[ "$recorded_sha" =~ ^[0-9a-f]{64}$ ]] || die 'BUILD-INFO binary_sha256 is invalid'
    [[ "$recorded_sha" == "$(sha256sum "$package_dir/bin/rustsdcmcp" | cut -d' ' -f1)" ]] \
        || die 'BUILD-INFO binary_sha256 does not match the shipped binary'
}

validate_package_json() {
    # Validation moved to the rustsdcmcp binary itself via --validate-package.
    # The binary validates both config/sdc.json.example and SBOM.cdx.json.
    "$package_dir/bin/rustsdcmcp" --validate-package "$package_dir" \
        || die 'package JSON validation failed'
}


extract_exec_start() {
    awk '
        /^[[:space:]]*\[Service\][[:space:]]*$/ { in_service = 1; next }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { in_service = 0 }
        in_service && $0 ~ /^[[:space:]]*ExecStart[[:space:]]*=/ {
            if (found++) exit 2
            line = $0
            sub(/^[[:space:]]*ExecStart[[:space:]]*=[[:space:]]*/, "", line)
            while (line ~ /\\$/) {
                sub(/\\$/, "", line)
                if (getline continuation <= 0) exit 2
                sub(/^[[:space:]]+/, "", continuation)
                line = line " " continuation
            }
            print line
        }
        END { if (found != 1) exit 2 }
    ' "$package_dir/packaging/systemd/rustsdcmcp.service"
}

service_directive_values() {
    local key=$1
    awk -v key="$key" '
        /^[[:space:]]*\[Service\][[:space:]]*$/ { in_service = 1; next }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { in_service = 0 }
        in_service {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            if (line ~ ("^" key "[[:space:]]*=")) {
                sub("^" key "[[:space:]]*=[[:space:]]*", "", line)
                sub(/[[:space:]]+$/, "", line)
                print line
            }
        }
    ' "$package_dir/packaging/systemd/rustsdcmcp.service"
}

require_service_directive() {
    local key=$1 expected=$2
    local -a values=()
    mapfile -t values < <(service_directive_values "$key")
    [[ ${#values[@]} -eq 1 && ${values[0]} == "$expected" ]] \
        || die "unit $key directives are invalid"
}

validate_service() {
    local expected exec_start
    # shellcheck disable=SC2016  # $STATE_DIRECTORY is a systemd variable, not a shell expansion
    expected='/usr/local/bin/rustsdcmcp --device-mapping /etc/rustsdcmcp/sdc.json --transport streamable-http --host 127.0.0.1 --port 30032 --tokens-file /var/lib/rustsdcmcp/tokens.json --audit-format json --audit-journald --audit-log-file $STATE_DIRECTORY/audit.jsonl --audit-redact devices=hmac --audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key'
    exec_start=$(extract_exec_start | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//') || die 'unit has invalid ExecStart'
    [[ "$exec_start" == "$expected" ]] || die 'unit ExecStart does not match the package policy'
    require_service_directive EnvironmentFile /etc/rustsdcmcp/credentials.env
    require_service_directive ReadOnlyPaths /etc/rustsdcmcp
    require_service_directive ReadWritePaths /var/lib/rustsdcmcp
}

validate_package() {
    validate_layout
    bash -n "$package_dir/packaging/lxc/install.sh"
    validate_build_info
    validate_package_json
    validate_service
    grep -Fqx 'u rustsdcmcp - "rustsdcmcp service" /var/lib/rustsdcmcp /usr/sbin/nologin' "$package_dir/packaging/systemd/rustsdcmcp.sysusers" || die 'sysusers declaration is invalid'
    grep -Fqx 'd /etc/rustsdcmcp 0750 root rustsdcmcp -' "$package_dir/packaging/systemd/rustsdcmcp.tmpfiles" || die 'config tmpfiles declaration is invalid'
    grep -Fqx 'd /var/lib/rustsdcmcp 0700 rustsdcmcp rustsdcmcp -' "$package_dir/packaging/systemd/rustsdcmcp.tmpfiles" || die 'state tmpfiles declaration is invalid'
}

# Structural and provenance checks deliberately run before apt, sysusers,
# tmpfiles, or any target mutation. SBOM validation follows jq installation.
validate_package

live_install=0
[[ -z "$install_root" || "$test_live" == 1 ]] && live_install=1

config_dir=$(target_path /etc/rustsdcmcp)
state_dir=$(target_path /var/lib/rustsdcmcp)
bin_path=$(target_path /usr/local/bin/rustsdcmcp)
sysusers_path=$(target_path /usr/lib/sysusers.d/rustsdcmcp.conf)
tmpfiles_path=$(target_path /usr/lib/tmpfiles.d/rustsdcmcp.conf)
stale_journal_path=$(target_path /etc/systemd/journald.conf.d/mecmcp.conf)
unit_path=$(target_path /etc/systemd/system/rustsdcmcp.service)
tokens_path=$(target_path /var/lib/rustsdcmcp/tokens.json)
legacy_tokens_path=$(target_path /etc/rustsdcmcp/tokens.json)
hmac_path=$(target_path /etc/rustsdcmcp/audit-hmac.key)

reject_unsafe_directory() {
    local path=$1
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -d "$path" && ! -L "$path" ]] || die "unsafe destination directory: $path"
    fi
}

reject_unsafe_file() {
    local path=$1
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -f "$path" && ! -L "$path" ]] || die "unsafe destination file: $path"
        [[ $(stat -c %h -- "$path") == 1 ]] || die "unsafe hard-linked destination file: $path"
    fi
}

reject_unsafe_parent_dirs() {
    local path=$1 parent
    parent=$(dirname -- "$path")
    while [[ "$parent" != / ]]; do
        reject_unsafe_directory "$parent"
        parent=$(dirname -- "$parent")
    done
    reject_unsafe_directory /
}

# Validate destination objects before apt, sysusers, tmpfiles, or any write.
reject_unsafe_directory "$config_dir"
reject_unsafe_directory "$state_dir"
reject_unsafe_parent_dirs "$config_dir/.parent-validation"
reject_unsafe_parent_dirs "$state_dir/.parent-validation"
managed_destinations=(
    "$bin_path" "$config_dir/sdc.json.example" "$sysusers_path" "$tmpfiles_path"
    "$unit_path" "$tokens_path" "$hmac_path"
)
for destination in "${managed_destinations[@]}"; do
    reject_unsafe_file "$destination"
    reject_unsafe_parent_dirs "$destination"
done

# Remove stale mecmcp.conf if present. This repo no longer ships it
# (rustsdcmcp#97), and rustmistmcp is removing it in parallel
# (rustmistmcp#44). The file duplicated fleet-wide audit policy and could
# silently override it. Stopping shipping alone is insufficient — the old file
# persists across upgrades. Validate the path first to prevent escape via
# symlinked parent directories.
reject_unsafe_file "$stale_journal_path"
reject_unsafe_parent_dirs "$stale_journal_path"
if [[ -f "$stale_journal_path" ]]; then
    rm -f "$stale_journal_path"
fi

if (( live_install )); then
    if [[ "$skip_user" == 1 ]]; then
        if ! getent passwd rustsdcmcp >/dev/null || ! getent group rustsdcmcp >/dev/null; then
            die 'SDCMCP_INSTALL_SKIP_USER=1 requires rustsdcmcp user and group'
        fi
    fi
    if [[ "$skip_runtime_deps" != 1 ]]; then
        [[ -f /etc/debian_version ]] || die 'live installation requires Debian'
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates
        apt-get clean
        rm -rf /var/lib/apt/lists/*
    fi
fi
if (( live_install )) && [[ "$skip_user" != 1 ]]; then
    systemd-sysusers "$package_dir/packaging/systemd/rustsdcmcp.sysusers"
fi

install -d -m 0750 "$config_dir"
install -d -m 0700 "$state_dir"
install -d -m 0755 "$(dirname -- "$bin_path")" "$(dirname -- "$sysusers_path")" \
    "$(dirname -- "$tmpfiles_path")" "$(dirname -- "$unit_path")"
install -m 0755 "$package_dir/bin/rustsdcmcp" "$bin_path"
install -m 0644 "$package_dir/packaging/systemd/rustsdcmcp.sysusers" "$sysusers_path"
install -m 0644 "$package_dir/packaging/systemd/rustsdcmcp.tmpfiles" "$tmpfiles_path"
if (( live_install )) && getent group rustsdcmcp >/dev/null; then
    install -o root -g rustsdcmcp -m 0640 "$package_dir/config/sdc.json.example" "$config_dir/sdc.json.example"
else
    install -m 0640 "$package_dir/config/sdc.json.example" "$config_dir/sdc.json.example"
fi

if (( live_install )) && [[ "$skip_user" != 1 ]]; then
    systemd-tmpfiles --create "$package_dir/packaging/systemd/rustsdcmcp.tmpfiles"
fi
# tokens.json moved from /etc/rustsdcmcp to /var/lib/rustsdcmcp (#92).
#
# Create an empty store ONLY when no legacy store exists. The runtime prefers an
# existing primary, so writing an empty file here while the live tokens are still
# at the legacy path would shadow them: the service starts and rejects every
# existing bearer token. A silent auth wipe on upgrade is worse than a refusal.
#
# The file is never copied automatically — that would leave a duplicate secret
# behind, which is what the stale-secret scan exists to flag.
#
# Re-validate immediately before use: the earlier managed_destinations check
# ran before apt/sysusers/tmpfiles, leaving a window during which this
# service-writable path could change underneath it.
reject_unsafe_file "$tokens_path"
reject_unsafe_file "$hmac_path"
if [[ ! -e "$tokens_path" ]]; then
    if [[ -e "$legacy_tokens_path" ]]; then
        printf '%s\n' ">> Not creating $tokens_path: a token store already exists at"
        printf '%s\n' ">> $legacy_tokens_path. The server reads it via the legacy fallback and warns."
        printf '%s\n' ">>"
        printf '%s\n' ">> Migrate it deliberately. The service must be RESTARTED, not reloaded:"
        printf '%s\n' ">> the token store is bound to the path resolved at startup, so a reload"
        printf '%s\n' ">> keeps reading the old file and later rotations and revocations would"
        printf '%s\n' ">> silently stop applying — revoked credentials would stay active."
        printf '%s\n' ">> Restart it through your normal procedure only if it was already"
        printf '%s\n' ">> running — this installer deliberately never enables or starts the"
        printf '%s\n' ">> service, and a unit left stopped must stay stopped."
        printf '%s\n' ">>   install -m 0600 -o rustsdcmcp -g rustsdcmcp $legacy_tokens_path $tokens_path"
        printf '%s\n' ">>   <restart the unit if it was running, then confirm its state>"
        printf '%s\n' ">>   shred -u $legacy_tokens_path   # secure erase, not rm"
    else
        tokens_tmp=$(mktemp)
        printf '%s\n' '{"version":1,"tokens":[]}' >"$tokens_tmp"
        install -m 0600 "$tokens_tmp" "$tokens_path"
        rm -f "$tokens_tmp"
    fi
fi
if [[ ! -e "$hmac_path" ]]; then
    hmac_tmp=$(mktemp)
    (umask 077 && head -c 32 /dev/urandom >"$hmac_tmp")
    install -m 0600 "$hmac_tmp" "$hmac_path"
    rm -f "$hmac_tmp"
fi
# Apply ownership/mode only to files that exist. tokens_path may be absent
# when a legacy store exists, in which case the runtime serves the legacy
# file and warns. Re-validate immediately before each chmod/chown.
reject_unsafe_file "$hmac_path"
chmod 0600 "$hmac_path"
if [[ -e "$tokens_path" ]]; then
    reject_unsafe_file "$tokens_path"
    chmod 0600 "$tokens_path"
fi
if (( live_install )); then
    reject_unsafe_file "$hmac_path"
    chown rustsdcmcp:rustsdcmcp "$hmac_path"
    if [[ -e "$tokens_path" ]]; then
        reject_unsafe_file "$tokens_path"
        chown rustsdcmcp:rustsdcmcp "$tokens_path"
    fi
fi

if [[ -e "$unit_path" ]] && ! cmp -s "$unit_path" "$package_dir/packaging/systemd/rustsdcmcp.service" && [[ "$force_unit" != 1 ]]; then
    printf '%s\n' "preserving customized unit: $unit_path"
else
    install -m 0644 "$package_dir/packaging/systemd/rustsdcmcp.service" "$unit_path"
fi
if (( live_install )) && [[ "$skip_reload" != 1 ]]; then
    systemctl daemon-reload
fi

# Prove whether systemd's IPAddress* filters actually attach here, rather than
# assuming the unit's declaration means anything. systemd implements them with
# cgroup eBPF and FAILS OPEN when it cannot load the program -- typical in an
# unprivileged LXC without host delegation -- so the unit can declare a full
# egress policy while enforcing none of it. `systemd-analyze security` reads the
# declaration and cannot tell the difference.
#
# Informational by default: a runtime that withholds BPF is a legitimate
# deployment, and the operator needs to know rather than be blocked. Set
# SDCMCP_REQUIRE_EGRESS_FILTER=1 to make a non-enforcing host fatal.
egress_probe_unknown() {
    local require=$1 reason=$2
    printf '%s\n' "egress filter: UNKNOWN ($reason)" >&2
    # Strict mode must not accept what it could not measure. An unmeasurable
    # host is exactly as unguaranteed as a non-enforcing one.
    [[ "$require" == 1 ]] \
        && die 'SDCMCP_REQUIRE_EGRESS_FILTER=1 and egress enforcement could not be determined'
    return 0
}

report_egress_enforcement() {
    local require=${SDCMCP_REQUIRE_EGRESS_FILTER:-0}
    local probe_unit="rustsdcmcp-egress-probe-$$"

    if ! command -v systemd-run >/dev/null; then
        egress_probe_unknown "$require" 'systemd-run unavailable; cannot probe'
        return $?
    fi

    # Two independent conditions have to hold, and conflating them is how the
    # previous version overstated its result:
    #   1. the host can attach the cgroup BPF program at all, and
    #   2. the *installed* unit actually declares an egress policy.
    # A transient probe only establishes (1). If the installer preserved a
    # customized unit with no IPAddressDeny, (1) alone would still have printed
    # ENFORCED and satisfied the strict flag over a service filtering nothing.
    local counters=''
    if systemd-run --quiet --collect --unit="$probe_unit" \
        --property=IPAccounting=yes --property=RemainAfterExit=yes \
        /bin/true >/dev/null 2>&1
    then
        counters=$(systemctl show "$probe_unit.service" -p IPEgressBytes --value 2>/dev/null || printf '')
        systemctl stop "$probe_unit.service" >/dev/null 2>&1 || true
        systemctl reset-failed "$probe_unit.service" >/dev/null 2>&1 || true
    else
        egress_probe_unknown "$require" 'probe unit would not start; run as root to determine'
        return $?
    fi

    if [[ -z "$counters" || "$counters" == '[no data]' ]]; then
        printf '%s\n' \
            'egress filter: NOT ENFORCED' \
            '  systemd cannot attach its cgroup BPF program here, so the IPAddressAllow/' \
            '  IPAddressDeny lines in rustsdcmcp.service have no effect. This is normal in' \
            '  an unprivileged LXC. The unit still applies every other sandbox directive.' \
            '  Move the control outward to whatever layer sees this workload'"'"'s packets --' \
            '  guest firewall, host nftables, NetworkPolicy, or cloud security group -- and' \
            '  deny 169.254.0.0/16 plus the local subnet except your resolver, allow 443 out.' \
            '  docs/operations.md, "Enforcing it where systemd cannot", has the per-runtime' \
            '  mechanism and a verification command.' >&2
        [[ "$require" == 1 ]] \
            && die 'SDCMCP_REQUIRE_EGRESS_FILTER=1 and systemd IP filtering is not enforced here'
        return 0
    fi

    # (1) holds. Now (2): does the unit that was actually installed carry a
    # policy for the kernel to enforce?
    if ! grep -Eq '^[[:space:]]*IPAddressDeny[[:space:]]*=[[:space:]]*[^[:space:]]' "$unit_path"; then
        printf '%s\n' \
            'egress filter: NO POLICY' \
            "  This host can enforce systemd IP filtering, but $unit_path declares no" \
            '  IPAddressDeny. A preserved customized unit overrides the packaged policy;' \
            '  re-install with SDCMCP_FORCE_UNIT=1 or add the directives by hand.' >&2
        [[ "$require" == 1 ]] \
            && die 'SDCMCP_REQUIRE_EGRESS_FILTER=1 and the installed unit declares no egress policy'
        return 0
    fi

    printf '%s\n' 'egress filter: ENFORCED'
    return 0
}

# Not in staged live-test mode: that seam exists to exercise the installer
# against a stage root without touching the host, and systemd-run would create
# a transient unit on the real PID 1 regardless of SDCMCP_INSTALL_ROOT.
if (( live_install )) && [[ "$test_live" != 1 ]]; then
    report_egress_enforcement
fi

printf '%s\n' \
    'Installation complete. Next steps:' \
    '1. Create config: install -o root -g rustsdcmcp -m 0640 /etc/rustsdcmcp/sdc.json.example /etc/rustsdcmcp/sdc.json, then edit /etc/rustsdcmcp/sdc.json.' \
    '2. Install /etc/rustsdcmcp/credentials.env with mode 0600; do not put credentials in JSON.' \
    '3. Mint a least-privilege token as root, then start rustsdcmcp manually after configuration.' \
    '4. Configure remote journal forwarding before handling production traffic.' \
    'MCP endpoint: http://127.0.0.1:30032/mcp'
