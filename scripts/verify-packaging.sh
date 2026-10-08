#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

fail() {
    printf '%s\n' "packaging verification failed: $*" >&2
    exit 1
}
require() {
    local needle=$1 file=$2
    grep -Fqx -- "$needle" "$file" || fail "missing '$needle' in $file"
}
require_contains() {
    local needle=$1 file=$2
    grep -Fq -- "$needle" "$file" || fail "missing '$needle' in $file"
}
require_logical_line() {
    local needle=$1 file=$2 actual
    actual=$(NEEDLE="$needle" awk '
        BEGIN { needle = ENVIRON["NEEDLE"] }
        {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            sub(/[[:space:]]+$/, "", line)
            if (line == needle) count += 1
        }
        END { print count + 0 }
    ' "$file")
    [[ "$actual" -eq 1 ]] \
        || fail "expected one executable '$needle' line in $file; found $actual"
}
logical_line_numbers() {
    local needle=$1 file=$2
    NEEDLE="$needle" awk '
        BEGIN { needle = ENVIRON["NEEDLE"] }
        {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            sub(/[[:space:]]+$/, "", line)
            if (line == needle) print NR
        }
    ' "$file"
}
has_single_exact_key() {
    local key=$1 expected=$2 file=$3
    awk -F= -v key="$key" -v expected="$expected" '
        $1 == key { count += 1; matches += ($0 == expected) }
        END { exit !(count == 1 && matches == 1) }
    ' "$file"
}
source_has_single_exact_key() {
    local key=$1 expected=$2 file=$3
    KEY="$key" EXPECTED="$expected" awk '
        BEGIN {
            key = ENVIRON["KEY"]
            expected = ENVIRON["EXPECTED"]
        }
        {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            sub(/[[:space:]]+$/, "", line)
            split(line, fields, "=")
            if (fields[1] == key) {
                count += 1
                matches += (line == expected)
            }
        }
        END { exit !(count == 1 && matches == 1) }
    ' "$file"
}

assert_build_info_key_contract() {
    local fixture
    fixture=$(mktemp)
    printf '%s\n' 'mecmcp_ref=v0.24.0' >"$fixture"
    has_single_exact_key mecmcp_ref 'mecmcp_ref=v0.24.0' "$fixture" \
        || fail 'singular expected BUILD-INFO mecmcp key was rejected'
    printf '%s\n' 'mecmcp_ref=v0.7.3' >>"$fixture"
    if has_single_exact_key mecmcp_ref 'mecmcp_ref=v0.24.0' "$fixture"; then
        fail 'conflicting BUILD-INFO mecmcp key was accepted'
    fi
    rm -f -- "$fixture"
}
assert_build_info_key_contract

upload_step_has_main_push_condition() {
    local file=$1 condition
    condition="        if: github.event_name == 'push' && github.ref == 'refs/heads/main'"
    CONDITION="$condition" awk '
        BEGIN { condition = ENVIRON["CONDITION"] }
        function finish_step() {
            if (upload_uses > 0) {
                upload_steps += 1
                if (upload_uses != 1 || upload_conditions != 1) invalid = 1
            }
        }
        /^      - / {
            finish_step()
            in_step = 1
            upload_uses = 0
            upload_conditions = 0
        }
        in_step && /^        uses: actions\/upload-artifact@/ {
            upload_uses += 1
        }
        in_step && $0 == condition {
            upload_conditions += 1
        }
        END {
            finish_step()
            exit !(upload_steps == 1 && invalid == 0)
        }
    ' "$file"
}

extract_builder_sbom_filter() {
    awk '
        BEGIN { quote = sprintf("%c", 39) }
        $0 == "jq -e " quote { capture = 1; next }
        capture && index($0, quote " \"") == 1 { exit }
        capture { print }
    ' scripts/build-package.sh
}

assert_exact_mecmcp_sbom_set() {
    local filter valid candidate index
    local -a cases=(duplicate extra mixed-registry wrong-version)
    local -a mutations=(
        '.components += [.components[] | select(.name == "mecmcp-auth")]'
        '.components += [{"name":"mecmcp-extra","version":"0.8.0"}]'
        '.components += [{"name":"mecmcp-auth","version":"0.5.0","purl":"pkg:cargo/mecmcp-auth@0.5.0"}]'
        '(.components[] | select(.name == "mecmcp-auth") | .version) = "0.5.0"'
    )
    filter=$(extract_builder_sbom_filter)
    [[ -n "$filter" ]] || fail 'could not extract builder SBOM jq filter'
    valid=$(jq -nc '{
        bomFormat: "CycloneDX",
        metadata: {component: {name: "rustsdcmcp"}},
        components: [
            {name: "serde", version: "1.0.0"},
            {name: "mecmcp-audit", version: "0.26.0"},
            {name: "mecmcp-auth", version: "0.26.0"},
            {name: "mecmcp-changeset", version: "0.26.0"},
            {name: "mecmcp-redact", version: "0.26.0"},
            {name: "mecmcp-runtime", version: "0.26.0"},
            {name: "mecmcp-secret", version: "0.26.0"},
            {name: "mecmcp-server", version: "0.26.0"},
            {name: "mecmcp-transport", version: "0.26.0"}
        ]
    }')
    jq -e "$filter" <<<"$valid" >/dev/null \
        || fail 'builder SBOM filter rejected the exact mecmcp component set'
    for index in "${!cases[@]}"; do
        candidate=$(jq -c "${mutations[$index]}" <<<"$valid")
        if jq -e "$filter" <<<"$candidate" >/dev/null; then
            fail "builder SBOM filter accepted ${cases[$index]} mecmcp components"
        fi
    done
}
assert_exact_mecmcp_sbom_set

for script in scripts/build-package.sh scripts/verify-packaging.sh \
    packaging/lxc/install.sh packaging/tests/package-smoke.sh; do
    [[ -x "$script" ]] || fail "$script must be executable"
    bash -n "$script"
done

# grep, not rg: ripgrep is not installed on the CI runner, so this check
# exited non-zero and the `if` never fired — it has been failing OPEN. A gate
# that cannot run is not a gate (mecmcp#273's lesson, applied here).
if grep -rn -E 'Command::new|std::process|tokio::process' crates --include='*.rs' \
    | grep -vE '(^|/)tests/|_test\.rs:'; then
    fail 'production Rust must not spawn processes'
fi

service=packaging/systemd/rustsdcmcp.service
installer=packaging/lxc/install.sh
ci=.github/workflows/ci.yml
tmpfiles=packaging/systemd/rustsdcmcp.tmpfiles
sysusers=packaging/systemd/rustsdcmcp.sysusers
# shellcheck disable=SC2016  # $STATE_DIRECTORY is a systemd variable, not a shell expansion
expected_exec='/usr/local/bin/rustsdcmcp --device-mapping /etc/rustsdcmcp/sdc.json --transport streamable-http --host 127.0.0.1 --port 30032 --tokens-file /var/lib/rustsdcmcp/tokens.json --audit-format json --audit-journald --audit-log-file $STATE_DIRECTORY/audit.jsonl --audit-redact devices=hmac --audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key'

assert_upload_step_policy() {
    local mutated condition
    condition="        if: github.event_name == 'push' && github.ref == 'refs/heads/main'"
    upload_step_has_main_push_condition "$ci" \
        || fail 'artifact upload step lacks its exact main-push condition'
    mutated=$(mktemp)
    CONDITION="$condition" awk '
        BEGIN { condition = ENVIRON["CONDITION"] }
        $0 == condition { next }
        $0 == "      - name: Upload package" { print condition }
        { print }
    ' "$ci" >"$mutated"
    if upload_step_has_main_push_condition "$mutated"; then
        fail 'upload policy accepted a condition attached to another YAML step'
    fi
    rm -f -- "$mutated"
}
assert_upload_step_policy

assert_installer_post_jq_validation_order() {
    local validation_line sysusers_line install_line
    local -a validation_lines=() sysusers_lines=() install_lines=()
    mapfile -t validation_lines < <(logical_line_numbers 'validate_package_json' "$installer")
    # shellcheck disable=SC2016
    mapfile -t sysusers_lines < <(logical_line_numbers \
        'systemd-sysusers "$package_dir/packaging/systemd/rustsdcmcp.sysusers"' \
        "$installer")
    # shellcheck disable=SC2016
    mapfile -t install_lines < <(logical_line_numbers \
        'install -d -m 0750 "$config_dir"' \
        "$installer")
    [[ ${#validation_lines[@]} -eq 1 && ${#sysusers_lines[@]} -eq 1 \
        && ${#install_lines[@]} -eq 1 ]] \
        || fail 'installer must have singular ordered validation and mutation calls'
    validation_line=${validation_lines[0]}
    sysusers_line=${sysusers_lines[0]}
    install_line=${install_lines[0]}
    (( validation_line < sysusers_line
        && validation_line < install_line )) \
        || fail 'installer must validate package JSON before mutation'
}
assert_installer_post_jq_validation_order

# tokens.json and audit-hmac.key live in a directory the service account can
# write to. Guard against a non-regular path reappearing there between the
# layout check and the point of use: every chmod/chown of either path must be
# immediately preceded (ignoring blank lines) by its own freshly re-run
# reject_unsafe_file call, and neither path may be created via a direct
# redirect -- only via mktemp + install(1).
# shellcheck disable=SC2016  # these are literal source fragments, not expansions
assert_installer_reguards_before_mutation() {
    local -a guard_pairs=(
        'reject_unsafe_file "$hmac_path"|chmod 0600 "$hmac_path"'
        'reject_unsafe_file "$tokens_path"|chmod 0600 "$tokens_path"'
        'reject_unsafe_file "$hmac_path"|chown rustsdcmcp:rustsdcmcp "$hmac_path"'
        'reject_unsafe_file "$tokens_path"|chown rustsdcmcp:rustsdcmcp "$tokens_path"'
    )
    local pair guard mutation mutation_line prev_line prev_text
    local -a mutation_lines=()
    for pair in "${guard_pairs[@]}"; do
        guard=${pair%%|*}
        mutation=${pair#*|}
        mapfile -t mutation_lines < <(logical_line_numbers "$mutation" "$installer")
        [[ ${#mutation_lines[@]} -ge 1 ]] || fail "missing '$mutation' in $installer"
        for mutation_line in "${mutation_lines[@]}"; do
            prev_line=$((mutation_line - 1))
            while [[ -z "$(sed -n "${prev_line}p" "$installer" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')" ]]; do
                prev_line=$((prev_line - 1))
                (( prev_line > 0 )) || fail "no preceding guard for '$mutation' in $installer"
            done
            prev_text=$(sed -n "${prev_line}p" "$installer" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            [[ "$prev_text" == "$guard" ]] \
                || fail "'$mutation' at $installer:$mutation_line is not immediately preceded by '$guard'"
        done
    done
    if grep -Fq '>"$tokens_path"' "$installer"; then
        fail 'tokens.json must be created via mktemp + install(1), not a direct redirect'
    fi
    if grep -Fq '>"$hmac_path"' "$installer"; then
        fail 'audit-hmac.key must be created via mktemp + install(1), not a direct redirect'
    fi
    require_contains 'install -m 0600 "$tokens_tmp" "$tokens_path"' "$installer"
    require_contains 'install -m 0600 "$hmac_tmp" "$hmac_path"' "$installer"
}
assert_installer_reguards_before_mutation

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
    ' "$service"
}

require_service_directive() {
    local key=$1 expected=$2
    local -a values=()
    mapfile -t values < <(service_directive_values "$key")
    [[ ${#values[@]} -eq 1 && ${values[0]} == "$expected" ]] \
        || fail "active $key directives conflict"
}

exec_start=$(awk '
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
' "$service" | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//') || fail 'unit must contain one complete ExecStart'
[[ "$exec_start" == "$expected_exec" ]] || fail 'active ExecStart conflicts with loopback/token/audit policy'
require_service_directive EnvironmentFile /etc/rustsdcmcp/credentials.env
require_service_directive ReadOnlyPaths /etc/rustsdcmcp
require_service_directive ReadWritePaths /var/lib/rustsdcmcp
require 'u rustsdcmcp - "rustsdcmcp service" /var/lib/rustsdcmcp /usr/sbin/nologin' "$sysusers"
require 'd /etc/rustsdcmcp 0750 root rustsdcmcp -' "$tmpfiles"
require 'd /var/lib/rustsdcmcp 0700 rustsdcmcp rustsdcmcp -' "$tmpfiles"
# These assertions intentionally match literal shell source fragments.
# shellcheck disable=SC2016
require_contains 'install -o root -g rustsdcmcp -m 0640 "$package_dir/config/sdc.json.example" "$config_dir/sdc.json.example"' "$installer"
# shellcheck disable=SC2016
require_contains 'install_root=$(realpath -m -- "$install_root")' "$installer"
# shellcheck disable=SC2016
require_contains '[[ "$install_root" != / ]] || die '\''SDCMCP_INSTALL_ROOT must not resolve to /'\''' "$installer"
# shellcheck disable=SC2016
require_contains 'systemd-sysusers "$package_dir/packaging/systemd/rustsdcmcp.sysusers"' "$installer"
# shellcheck disable=SC2016
require_contains 'systemd-tmpfiles --create "$package_dir/packaging/systemd/rustsdcmcp.tmpfiles"' "$installer"
require_logical_line \
    'DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates' \
    "$installer"
require_logical_line \
    'apt-get clean' \
    "$installer"
# shellcheck disable=SC2016
require_contains \
    '"$package_dir/bin/rustsdcmcp" --validate-package "$package_dir"' \
    "$installer"
require_contains 'systemctl daemon-reload' "$installer"
# grep, not rg — same fail-open bug as above.
if grep -nE 'systemctl (enable|start|restart|try-restart)' "$installer"; then
    fail 'installer must not enable or start the nonbootable service'
fi

if find packaging -type f \( -name 'sdc.json' -o -name 'credentials.env' \) -print -quit | grep -q .; then
    fail 'live config or credentials are present in packaging inputs'
fi
if ! grep -Fq 's#/var/lib/sdcmcp/changeset-state.json#/var/lib/rustsdcmcp/changeset-state.json#' scripts/build-package.sh; then
    fail 'builder does not package the canonical state path'
fi
# The builder derives this from Cargo.toml rather than repeating a literal, so
# assert the value it actually produces. That is the property this guard wants --
# a source-text match would pass while the manifest said something else, and it
# would forbid single-sourcing the ref into the generated package README.
mapfile -t builder_mecmcp_refs < <(grep -oP '^mecmcp-\S+ = \{.*\b(?:tag|rev) = "\K[^"]+' Cargo.toml | sort -u)
[[ ${#builder_mecmcp_refs[@]} -eq 1 && ${builder_mecmcp_refs[0]} == 'v0.26.0' ]] \
    || fail "Cargo.toml must pin exactly one approved mecmcp tag/rev, found: ${builder_mecmcp_refs[*]-none}"
# The operations guide is packaged by build-package.sh:110 and must stay
# consistent with the manifest and the package provenance. This is the eleventh
# file that pins the mecmcp tag exactly.
# shellcheck disable=SC2016  # backticks are literal grep pattern, not expansion
grep -Fq '— to `v0.26.0`.' docs/operations.md \
    || fail 'docs/operations.md must document the pinned mecmcp tag/rev'
# shellcheck disable=SC2016  # literal source fragment, not an expansion
grep -Fq 'mecmcp_ref=$mecmcp_ref' scripts/build-package.sh \
    || fail 'builder must emit the derived mecmcp BUILD-INFO key'
require_logical_line \
    "has_single_exact_key mecmcp_ref 'mecmcp_ref=v0.26.0' \"\$build_info\" || die 'BUILD-INFO mecmcp ref is invalid'" \
    "$installer"
require_logical_line \
    "has_single_exact_key mecmcp_ref 'mecmcp_ref=v0.26.0' \"\$build_info\" || {" \
    packaging/tests/package-smoke.sh
for build_info_consumer in "$installer" packaging/tests/package-smoke.sh; do
    # shellcheck disable=SC2016
    require_logical_line \
        '$1 == key { count += 1; matches += ($0 == expected) }' \
        "$build_info_consumer"
    require_logical_line \
        'END { exit !(count == 1 && matches == 1) }' \
        "$build_info_consumer"
done
require_logical_line \
    "printf '%s\n' \"\$build_info\" | awk -F= -v expected='mecmcp_ref=v0.26.0' '\$1 == \"mecmcp_ref\" { count += 1; matches += (\$0 == expected) } END { exit !(count == 1 && matches == 1) }'" \
    "$ci"
sbom_validators=(
    scripts/build-package.sh
    packaging/tests/package-smoke.sh
    "$ci"
)
required_mecmcp_pairs=(
    '["mecmcp-audit", "0.26.0"],'
    '["mecmcp-auth", "0.26.0"],'
    '["mecmcp-changeset", "0.26.0"],'
    '["mecmcp-redact", "0.26.0"],'
    '["mecmcp-runtime", "0.26.0"],'
    '["mecmcp-secret", "0.26.0"],'
    '["mecmcp-server", "0.26.0"],'
    '["mecmcp-transport", "0.26.0"]'
)
for validator in "${sbom_validators[@]}"; do
    require_logical_line \
        '| select(.name? | strings | startswith("mecmcp-"))' \
        "$validator"
    require_logical_line '| [.name, .version]' "$validator"
    require_logical_line '] | sort)' "$validator"
    require_logical_line '== [' "$validator"
    for pair in "${required_mecmcp_pairs[@]}"; do
        require_logical_line "$pair" "$validator"
    done
    require_logical_line \
        'and (tostring | contains("v0.8.0") | not)' \
        "$validator"
    require_logical_line \
        'and (tostring | contains("70ac3d8fb5f27db3257d11aef28bd09587f085e1") | not)' \
        "$validator"
done

assert_builder_preserves_unsafe_output_entries() {
    local fixture fake_bin commit archive checksum outside extra rejection
    fixture=$(mktemp -d)
    fake_bin="$fixture/fake-bin"
    mkdir -p "$fixture/scripts" "$fake_bin"
    cp scripts/build-package.sh "$fixture/scripts/build-package.sh"
    chmod 0755 "$fixture/scripts/build-package.sh"
    printf '%s\n' 'dist/' 'fake-bin/' 'outside/' >"$fixture/.gitignore"
    # Add a valid Cargo.toml so the version extraction passes and the test reaches
    # the symlink/unexpected-entry checks it exists to cover.
    cat >"$fixture/Cargo.toml" <<'EOF'
[workspace.package]
version = "0.1.0"
EOF
    git -C "$fixture" init -q
    git -C "$fixture" config user.email packaging-test@example.invalid
    git -C "$fixture" config user.name packaging-test
    git -C "$fixture" add .gitignore scripts/build-package.sh Cargo.toml
    git -C "$fixture" commit -qm 'test fixture'
    commit=$(git -C "$fixture" rev-parse HEAD)
    archive="$fixture/dist/$commit/rustsdcmcp_0.1.0.$(date -u -d "@$(git -C "$fixture" show -s --format=%ct HEAD)" +%Y%m%d).${commit:0:12}_amd64.tar.gz"
    checksum="${archive}.sha256"
    cat >"$fake_bin/trivy" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'Version: 0.70.0'
EOF
    cat >"$fake_bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod 0755 "$fake_bin/trivy" "$fake_bin/cargo"

    outside="$fixture/outside"
    mkdir -p "$outside" "$fixture/dist"
    printf '%s\n' sentinel-archive >"$outside/$(basename -- "$archive")"
    printf '%s\n' sentinel-checksum >"$outside/$(basename -- "$checksum")"
    ln -s "$outside" "$fixture/dist/$commit"
    rejection=$(cd "$fixture" && PATH="$fake_bin:$PATH" scripts/build-package.sh 2>&1) && \
        fail 'builder accepted a symlinked commit artifact directory'
    [[ "$rejection" == *"commit artifact directory is not a real directory"* ]] \
        || fail "builder rejected symlink with wrong reason: $rejection"
    [[ -f "$outside/$(basename -- "$archive")" && -f "$outside/$(basename -- "$checksum")" ]] \
        || fail 'builder removed artifacts through a symlinked commit directory'

    rm "$fixture/dist/$commit"
    mkdir -p "$fixture/dist/$commit"
    printf '%s\n' sentinel-archive >"$archive"
    printf '%s\n' sentinel-checksum >"$checksum"
    extra="$fixture/dist/$commit/unexpected-artifact"
    printf '%s\n' sentinel-extra >"$extra"
    rejection=$(cd "$fixture" && PATH="$fake_bin:$PATH" scripts/build-package.sh 2>&1) && \
        fail 'builder accepted an artifact directory with an extra entry'
    [[ "$rejection" == *"contains an unsafe or unexpected entry"* ]] \
        || fail "builder rejected extra entry with wrong reason: $rejection"
    [[ -f "$archive" && -f "$checksum" && -f "$extra" ]] \
        || fail 'builder removed stale artifacts before rejecting an extra entry'
    rm -rf -- "$fixture"
}
assert_builder_preserves_unsafe_output_entries

verification_root=$(mktemp -d)
trap 'rm -rf -- "$verification_root"' EXIT
install -d "$verification_root/etc/systemd/system" "$verification_root/usr/local/bin" \
    "$verification_root/usr/lib/systemd/system" "$verification_root/bin"
install -m 0644 "$service" "$verification_root/etc/systemd/system/rustsdcmcp.service"
install -m 0755 /bin/true "$verification_root/usr/local/bin/rustsdcmcp"
install -m 0755 /bin/true "$verification_root/bin/kill"
printf '%s\n' '[Unit]' >"$verification_root/usr/lib/systemd/system/sysinit.target"
systemd-analyze --root="$verification_root" verify /etc/systemd/system/rustsdcmcp.service

git_commit=$(git rev-parse HEAD)
package_date=$(date -u -d "@$(git show -s --format=%ct HEAD)" +%Y%m%d)
archive="dist/$git_commit/rustsdcmcp_0.1.0.${package_date}.${git_commit:0:12}_amd64.tar.gz"
if [[ -f "$archive" ]]; then
    packaging/tests/package-smoke.sh "$archive"
fi

# Official MCP Registry ownership label must equal server.json "name".
# The OCI identifier tracks the workspace package version so the next release
# tag and the manifest stay the same string. The package is GHCR only.
require_contains 'LABEL io.modelcontextprotocol.server.name="io.github.mechubsec/rustsdcmcp"' Dockerfile
if ! python3 - << 'PY'
import json, pathlib, re, sys
root = pathlib.Path(".")
server = json.loads((root / "server.json").read_text())
cargo = (root / "Cargo.toml").read_text()
version = re.search(r'(?m)^version = "([^"]+)"', cargo).group(1)
name = "io.github.mechubsec/rustsdcmcp"
errors = []
if server.get("name") != name:
    errors.append(f"name {server.get('name')!r} != {name}")
if server.get("version") != version:
    errors.append(f"version {server.get('version')!r} != Cargo.toml {version}")
desc = server.get("description") or ""
if not 1 <= len(desc) <= 100:
    errors.append(f"description length {len(desc)} outside 1..100")
pkgs = server.get("packages") or []
if len(pkgs) != 1:
    errors.append(f"expected one package, found {len(pkgs)}")
else:
    pkg = pkgs[0]
    expect = f"ghcr.io/mechubsec/rustsdcmcp:{version}"
    if pkg.get("identifier") != expect:
        errors.append(f"identifier {pkg.get('identifier')!r} != {expect}")
    if pkg.get("registryType") != "oci":
        errors.append("registryType is not oci")
    if (pkg.get("transport") or {}).get("type") != "stdio":
        errors.append("transport is not stdio")
    banned = {
        "--device-mapping",
        "--tokens-file",
        "--audit-hmac-key-file",
    }
    args = pkg.get("packageArguments") or []
    names = {arg.get("name") for arg in args}
    if "--transport" not in names or "--state-file" not in names:
        errors.append("package arguments must set --transport and --state-file")
    for arg in args:
        if arg.get("name") in banned:
            errors.append(f"package argument repeats entrypoint flag {arg.get('name')}")
        if arg.get("name") == "--state-file" and arg.get("value") != "/var/lib/sdcmcp/changeset-state.json":
            errors.append("state file is not the mounted change-set path")
if errors:
    print("server.json: " + "; ".join(errors), file=sys.stderr)
    sys.exit(1)
PY
then
    fail 'server.json does not match the registry contract'
fi

if [[ -x packaging/lxc/tests/test_installer_path_guard.sh ]]; then
    packaging/lxc/tests/test_installer_path_guard.sh
fi

printf '%s\n' 'packaging policy verification passed'
