#!/usr/bin/env bash

set -Eeuo pipefail
set +x
export PYTHONDONTWRITEBYTECODE=1

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
temporary=$(CDPATH='' cd -- "$temporary" && pwd -P)
trap 'rm -rf -- "$temporary"' EXIT

command -v shellcheck >/dev/null 2>&1 || {
    printf 'deployment-package-test: shellcheck is required\n' >&2
    exit 1
}
if find "$repo_root/deploy" "$repo_root/scripts" "$repo_root/docs" \
    \( -type d -name __pycache__ -o -type f \( -name '*.pyc' -o -name '*.pyo' \) \) \
    -print -quit | grep -q .; then
    printf 'deployment-package-test: Python bytecode or cache directory would enter release\n' >&2
    exit 1
fi

bash -n "$repo_root"/scripts/deploy/*.sh \
    "$repo_root/scripts/build-zallet-testnet.sh" \
    "$repo_root/scripts/test-zallet-patches.sh" \
    "$repo_root/scripts/test-deployment-package.sh"
shellcheck "$repo_root"/scripts/deploy/*.sh \
    "$repo_root/scripts/build-zallet-testnet.sh" \
    "$repo_root/scripts/test-zallet-patches.sh" \
    "$repo_root/scripts/test-deployment-package.sh"
python3 "$repo_root/scripts/deploy/test_wait_payout_ready.py"
python3 "$repo_root/scripts/deploy/test_verify_mining_firewall.py"

mkdir -p "$temporary/fake-bin"
for supported_postgres_version in 160000 160015 170000; do
    PG_TEST_VERSION=$supported_postgres_version bash -c '
        source "$1"
        runuser() { printf "%s\n" "$PG_TEST_VERSION"; }
        psql() { :; }
        require_supported_postgres_server
    ' sh "$repo_root/scripts/deploy/common.sh"
done
for rejected_postgres_version in 140024 159999 malformed '160000 170000'; do
    if PG_TEST_VERSION=$rejected_postgres_version bash -c '
        source "$1"
        runuser() { printf "%s\n" "$PG_TEST_VERSION"; }
        psql() { :; }
        require_supported_postgres_server
    ' sh "$repo_root/scripts/deploy/common.sh" >/dev/null 2>&1; then
        printf 'deployment-package-test: unsupported PostgreSQL version passed: %s\n' \
            "$rejected_postgres_version" >&2
        exit 1
    fi
done
if bash -c '
    source "$1"
    runuser() { return 1; }
    psql() { :; }
    require_supported_postgres_server
' sh "$repo_root/scripts/deploy/common.sh" >/dev/null 2>&1; then
    printf 'deployment-package-test: failed PostgreSQL version query passed\n' >&2
    exit 1
fi
# shellcheck disable=SC2016
printf '#!/bin/sh\nexit "$PGREP_TEST_STATUS"\n' >"$temporary/fake-bin/pgrep"
chmod 0555 "$temporary/fake-bin/pgrep"
current_user=$(id -un)
PATH="$temporary/fake-bin:$PATH" PGREP_TEST_STATUS=1 bash -c \
    'source "$1"; require_no_processes_for_user "$2" "test identity"' \
    sh "$repo_root/scripts/deploy/common.sh" "$current_user"
for rejected_pgrep_status in 0 2 3; do
    if PATH="$temporary/fake-bin:$PATH" PGREP_TEST_STATUS=$rejected_pgrep_status bash -c \
        'source "$1"; require_no_processes_for_user "$2" "test identity"' \
        sh "$repo_root/scripts/deploy/common.sh" "$current_user" >/dev/null 2>&1; then
        printf 'deployment-package-test: custody accepted pgrep status %s\n' \
            "$rejected_pgrep_status" >&2
        exit 1
    fi
done
mkdir -p "$temporary/authority-parent"
PATH="$temporary/fake-bin:$PATH" bash -c '
    source "$1"
    runuser() { printf untraversable; }
    require_untraversable_by_user "$2" wcash-pool "test authority parent"
' sh "$repo_root/scripts/deploy/common.sh" "$temporary/authority-parent"
for traversal_probe in traversable failed; do
    if TRAVERSAL_PROBE=$traversal_probe bash -c '
        source "$1"
        runuser() {
            if [ "$TRAVERSAL_PROBE" = failed ]; then return 1; fi
            printf traversable
        }
        require_untraversable_by_user "$2" wcash-pool "test authority parent"
    ' sh "$repo_root/scripts/deploy/common.sh" "$temporary/authority-parent" \
        >/dev/null 2>&1; then
        printf 'deployment-package-test: authority traversal gate accepted %s probe\n' \
            "$traversal_probe" >&2
        exit 1
    fi
done
cat >"$temporary/fake-bin/id" <<'SH'
#!/bin/sh
case "$1:$2" in
    -u:wcash-pool) printf '1101\n' ;;
    -g:wcash-pool) printf '1201\n' ;;
    -u:wcash-pool-migrate) printf '1107\n' ;;
    -g:wcash-pool-migrate) printf '1207\n' ;;
    -u:wcash-payout) printf '1105\n' ;;
    -g:wcash-payout) printf '1205\n' ;;
    -u:wcash-pool-projector) printf '1106\n' ;;
    -g:wcash-pool-projector) printf '1206\n' ;;
    -u:wcash-pool-backend) printf '1102\n' ;;
    -g:wcash-pool-backend) printf '1202\n' ;;
    -u:zecwec-zallet) printf '1103\n' ;;
    -g:zecwec-zallet) printf '1203\n' ;;
    -u:zecwec-zallet-recovery)
        if [ "${DUPLICATE_SERVICE_ID:-}" = uid ]; then printf '1103\n'; else printf '1104\n'; fi
        ;;
    -g:zecwec-zallet-recovery)
        if [ "${DUPLICATE_SERVICE_ID:-}" = gid ]; then printf '1203\n'; else printf '1204\n'; fi
        ;;
    *) exit 2 ;;
esac
SH
chmod 0555 "$temporary/fake-bin/id"
PATH="$temporary/fake-bin:$PATH" bash -c \
    'source "$1"; require_distinct_service_identities' \
    sh "$repo_root/scripts/deploy/common.sh"
for duplicate_service_id in uid gid; do
    if PATH="$temporary/fake-bin:$PATH" DUPLICATE_SERVICE_ID=$duplicate_service_id \
        bash -c 'source "$1"; require_distinct_service_identities' \
        sh "$repo_root/scripts/deploy/common.sh" >/dev/null 2>&1; then
        printf 'deployment-package-test: duplicate service %s passed identity gate\n' \
            "$duplicate_service_id" >&2
        exit 1
    fi
done
credential_test="$temporary/systemd-credential-test"
mkdir -p "$credential_test/bin" "$credential_test/run/credentials/test.service"
credential_file="$credential_test/run/credentials/test.service/wcash-seed"
printf 'test credential\n' >"$credential_file"
chmod 0400 "$credential_file"
cat >"$credential_test/bin/stat" <<'SH'
#!/bin/sh
case "$*" in
    *%u:%a:%h*) printf '%s\n' "${CREDENTIAL_TEST_METADATA:?}" ;;
    *) exec /usr/bin/stat "$@" ;;
esac
SH
chmod 0555 "$credential_test/bin/stat"
for accepted_metadata in "$(id -u):400:1" "$(id -u):440:1"; do
    CREDENTIALS_DIRECTORY="$credential_test/run/credentials/test.service" \
        CREDENTIAL_TEST_METADATA=$accepted_metadata \
        PATH="$credential_test/bin:$PATH" \
        bash -c 'source "$1"; require_readonly_systemd_credential "$2" wcash-seed' \
        bash "$repo_root/scripts/deploy/common.sh" "$credential_file"
done
CREDENTIALS_DIRECTORY="$credential_test/run/credentials/test.service" \
    CREDENTIAL_TEST_METADATA=0:440:1 \
    PATH="$credential_test/bin:$PATH" \
    bash -c 'source "$1"; require_readonly_systemd_credential "$2" wcash-seed 123456' \
    bash "$repo_root/scripts/deploy/common.sh" "$credential_file"
for rejected_metadata in \
    "$(id -u):600:1" \
    "$(id -u):404:1" \
    "$(id -u):400:2" \
    "987654:400:1"; do
    if CREDENTIALS_DIRECTORY="$credential_test/run/credentials/test.service" \
        CREDENTIAL_TEST_METADATA=$rejected_metadata \
        PATH="$credential_test/bin:$PATH" \
        bash -c 'source "$1"; require_readonly_systemd_credential "$2" wcash-seed' \
        bash "$repo_root/scripts/deploy/common.sh" "$credential_file" \
        >/dev/null 2>&1; then
        printf 'deployment-package-test: credential gate accepted metadata %s\n' \
            "$rejected_metadata" >&2
        exit 1
    fi
done
chmod 0600 "$credential_file"
if [[ $(id -u) != 0 ]]; then
    if CREDENTIALS_DIRECTORY="$credential_test/run/credentials/test.service" \
        CREDENTIAL_TEST_METADATA="$(id -u):400:1" \
        PATH="$credential_test/bin:$PATH" \
        bash -c 'source "$1"; require_readonly_systemd_credential "$2" wcash-seed' \
        bash "$repo_root/scripts/deploy/common.sh" "$credential_file" \
        >/dev/null 2>&1; then
        printf 'deployment-package-test: credential gate accepted a service-writable file\n' >&2
        exit 1
    fi
fi
chmod 0400 "$credential_file"
if CREDENTIALS_DIRECTORY="$credential_test/run/credentials/test.service" \
    CREDENTIAL_TEST_METADATA="$(id -u):400:1" \
    PATH="$credential_test/bin:$PATH" \
    bash -c 'source "$1"; require_readonly_systemd_credential "$2" wrong-name' \
    bash "$repo_root/scripts/deploy/common.sh" "$credential_file" \
    >/dev/null 2>&1; then
    printf 'deployment-package-test: credential gate accepted the wrong credential name\n' >&2
    exit 1
fi
cat >"$temporary/fake-bin/ss" <<'SH'
#!/bin/sh
if [ "${SS_TEST_STATUS:-0}" -ne 0 ]; then exit "$SS_TEST_STATUS"; fi
[ -z "${SS_TEST_OUTPUT:-}" ] || printf '%s\n' "$SS_TEST_OUTPUT"
SH
chmod 0555 "$temporary/fake-bin/ss"
PATH="$temporary/fake-bin:$PATH" bash -c \
    'source "$1"; require_tcp_listener_absent 28242 "test listener"' \
    sh "$repo_root/scripts/deploy/common.sh"
for listener_case in inspection-error present; do
    ss_status=0
    ss_output=
    if [[ $listener_case == inspection-error ]]; then
        ss_status=2
    else
        ss_output='LISTEN test fixture'
    fi
    if PATH="$temporary/fake-bin:$PATH" SS_TEST_STATUS=$ss_status SS_TEST_OUTPUT=$ss_output \
        bash -c 'source "$1"; require_tcp_listener_absent 28242 "test listener"' \
        sh "$repo_root/scripts/deploy/common.sh" >/dev/null 2>&1; then
        printf 'deployment-package-test: listener gate accepted %s\n' \
            "$listener_case" >&2
        exit 1
    fi
done
mkdir -p "$temporary/source-tree/deploy" "$temporary/source-tree/scripts" \
    "$temporary/source-tree/docs" "$temporary/cleanup-a" "$temporary/cleanup-b" \
    "$temporary/exact-staging"
touch "$temporary/exact-staging/mnemonic.age" "$temporary/exact-staging/mnemonic.txt"
exact_staging_entries=$(printf '%s\n' mnemonic.age mnemonic.txt | LC_ALL=C sort)
bash -c 'source "$1"; require_exact_immediate_entries "$2" "$3" "test staging"' \
    sh "$repo_root/scripts/deploy/common.sh" "$temporary/exact-staging" \
    "$exact_staging_entries"
for unexpected_staging_entry in extra-file nested-directory; do
    if [[ $unexpected_staging_entry == extra-file ]]; then
        touch "$temporary/exact-staging/extra"
    else
        mkdir "$temporary/exact-staging/nested"
    fi
    if bash -c \
        'source "$1"; require_exact_immediate_entries "$2" "$3" "test staging"' \
        sh "$repo_root/scripts/deploy/common.sh" "$temporary/exact-staging" \
        "$exact_staging_entries" >/dev/null 2>&1; then
        printf 'deployment-package-test: exact staging accepted %s\n' \
            "$unexpected_staging_entry" >&2
        exit 1
    fi
    rm -f -- "$temporary/exact-staging/extra"
    rmdir -- "$temporary/exact-staging/nested" 2>/dev/null || true
done
cat >"$temporary/fake-bin/find" <<'SH'
#!/bin/sh
if [ "${FIND_TEST_STATUS:-0}" -ne 0 ]; then exit "$FIND_TEST_STATUS"; fi
[ -z "${FIND_TEST_OUTPUT:-}" ] || printf '%s\n' "$FIND_TEST_OUTPUT"
SH
chmod 0555 "$temporary/fake-bin/find"
PATH="$temporary/fake-bin:$PATH" bash -c \
    'source "$1"; require_deployment_source_tree_safe "$2"; require_cleanup_trees_safe "$3" "$4"' \
    sh "$repo_root/scripts/deploy/common.sh" "$temporary/source-tree" \
    "$temporary/cleanup-a" "$temporary/cleanup-b"
for find_gate in \
    require_deployment_source_tree_safe \
    require_cleanup_trees_safe \
    require_exact_immediate_entries; do
    if PATH="$temporary/fake-bin:$PATH" FIND_TEST_STATUS=2 bash -c \
        'source "$1"; shift; "$@"' sh "$repo_root/scripts/deploy/common.sh" \
        "$find_gate" "$temporary/source-tree" >/dev/null 2>&1; then
        printf 'deployment-package-test: %s accepted a find traversal error\n' \
            "$find_gate" >&2
        exit 1
    fi
done

failure_cleanup_test="$temporary/failure-cleanup-test"
mkdir -p "$failure_cleanup_test/bin"
cat >"$failure_cleanup_test/bin/systemctl" <<'SH'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >"$SYSTEMCTL_FAILURE_CLEANUP_LOG"
exit "${SYSTEMCTL_FAILURE_CLEANUP_STATUS:-0}"
SH
chmod 0555 "$failure_cleanup_test/bin/systemctl"
for cleanup_status in 0 7; do
    cleanup_log="$failure_cleanup_test/$cleanup_status.log"
    PATH="$failure_cleanup_test/bin:$PATH" \
        SYSTEMCTL_FAILURE_CLEANUP_LOG=$cleanup_log \
        SYSTEMCTL_FAILURE_CLEANUP_STATUS=$cleanup_status \
        bash -c 'source "$1"; stop_testnet_runtime_after_failure' \
        bash "$repo_root/scripts/deploy/common.sh"
    [[ $(cat "$cleanup_log") == \
        "stop zecwec-testnet-pool.target wcash-pool-health.timer wcash-payout-worker.service zecwec-zallet-payout.service wcash-pool.service wcash-pool-projector.service" ]] \
        || {
            printf 'deployment-package-test: failure cleanup omitted a runtime unit\n' >&2
            exit 1
        }
done

strict_stop_test="$temporary/strict-stop-test"
mkdir -p "$strict_stop_test/bin"
cat >"$strict_stop_test/bin/systemctl" <<'SH'
#!/usr/bin/env bash
set -eu

case $1 in
    show)
        property=${2#--property=}
        case "${STRICT_STOP_SCENARIO:?}:$property" in
            missing:LoadState) printf 'not-found\n' ;;
            masked:LoadState) printf 'masked\n' ;;
            *:LoadState) printf 'loaded\n' ;;
            stuck:ActiveState) printf 'active\n' ;;
            *:ActiveState) printf 'inactive\n' ;;
            *:SubState) printf 'dead\n' ;;
            *:MainPID | *:ControlPID) printf '0\n' ;;
            *) exit 2 ;;
        esac
        ;;
    stop)
        [[ $STRICT_STOP_SCENARIO != stop-failure ]] || exit 7
        printf 'stop %s\n' "$2" >>"$STRICT_STOP_LOG"
        ;;
    reset-failed)
        [[ $STRICT_STOP_SCENARIO != reset-failure ]] || exit 8
        printf 'reset-failed %s\n' "$2" >>"$STRICT_STOP_LOG"
        ;;
    *) exit 2 ;;
esac
SH
chmod 0555 "$strict_stop_test/bin/systemctl"

run_strict_stop_scenario() {
    local scenario=$1
    local expected=$2
    local log="$strict_stop_test/$scenario.log"
    : >"$log"
    if PATH="$strict_stop_test/bin:$PATH" \
        STRICT_STOP_SCENARIO=$scenario STRICT_STOP_LOG=$log \
        bash -c 'source "$1"; stop_loaded_unit_strict test.service' \
        bash "$repo_root/scripts/deploy/common.sh" >/dev/null 2>&1; then
        [[ $expected == pass ]] || {
            printf 'deployment-package-test: strict stop accepted %s\n' "$scenario" >&2
            exit 1
        }
    else
        [[ $expected == fail ]] || {
            printf 'deployment-package-test: strict stop rejected %s\n' "$scenario" >&2
            exit 1
        }
    fi
}

run_strict_stop_scenario missing pass
[[ ! -s $strict_stop_test/missing.log ]] || {
    printf 'deployment-package-test: strict stop mutated an absent unit\n' >&2
    exit 1
}
run_strict_stop_scenario loaded pass
[[ $(cat "$strict_stop_test/loaded.log") == $'stop test.service\nreset-failed test.service' ]] || {
    printf 'deployment-package-test: strict stop omitted its stop/reset sequence\n' >&2
    exit 1
}
for rejected_stop_scenario in masked stop-failure reset-failure stuck; do
    run_strict_stop_scenario "$rejected_stop_scenario" fail
done

"$repo_root/scripts/test-zallet-patches.sh" >/dev/null
# shellcheck disable=SC2016
[[ $(grep -Fc 'require_tcp_listener_absent "$listener"' \
    "$repo_root/scripts/deploy/preflight.sh") -eq 2 ]] || {
    printf 'deployment-package-test: preflight listener checks are not fail-closed\n' >&2
    exit 1
}
# shellcheck disable=SC2016
grep -Fq 'require_cleanup_trees_safe "$staging" "$recovery_state"' \
    "$repo_root/scripts/deploy/finalize-zec-offline-custody.sh"
# shellcheck disable=SC2016
grep -Fq 'require_exact_immediate_entries "$staging" "$expected_staging_entries"' \
    "$repo_root/scripts/deploy/finalize-zec-offline-custody.sh"
# shellcheck disable=SC2016
grep -Fq 'require_deployment_source_tree_safe "$deployment_source"' \
    "$repo_root/scripts/deploy/install-release.sh"
# shellcheck disable=SC2016
grep -Fq 'require_deployment_source_tree_safe "$source_root"' \
    "$repo_root/scripts/deploy/provision-host.sh"
# shellcheck disable=SC2016
grep -Fq 'deployment_staging=$(mktemp -d /usr/local/share/.zecwec-deploy.new.XXXXXX)' \
    "$repo_root/scripts/deploy/provision-host.sh"
grep -Fq 'for directory in deploy scripts docs patches; do' \
    "$repo_root/scripts/deploy/provision-host.sh"
# shellcheck disable=SC2016
grep -Fq 'mv -T -- "$deployment_staging" "$deployment_destination"' \
    "$repo_root/scripts/deploy/provision-host.sh"
# shellcheck disable=SC2016
grep -Fq 'find "$ZECWEC_LIBEXEC" -mindepth 1 -maxdepth 1 -type l -delete' \
    "$repo_root/scripts/deploy/provision-host.sh"
grep -Fq 'patches/zallet-v0.1.0-beta.3' \
    "$repo_root/scripts/deploy/provision-host.sh"
grep -Fq 'patches/zallet-v0.1.0-beta.3' \
    "$repo_root/scripts/deploy/install-release.sh"
grep -Fq 'scripts/verify-zallet-build.py' \
    "$repo_root/scripts/deploy/install-release.sh"
grep -Fq 'deployment/patches/zallet-v0.1.0-beta.3' \
    "$repo_root/scripts/deploy/install-release.sh"
grep -Fq 'deployment/patches/zallet-v0.1.0-beta.3' \
    "$repo_root/scripts/deploy/verify-release.sh"
grep -Fq 'deployment package file inventory cannot be inspected' \
    "$repo_root/scripts/deploy/verify-release.sh"
if grep -Fq '<(find ' "$repo_root/scripts/deploy/verify-release.sh"; then
    printf 'deployment-package-test: release verification ignores a find producer status\n' >&2
    exit 1
fi
grep -Fq 'base_commit=987382f67e622915228686e9f956c6a9c9a7514c' \
    "$repo_root/scripts/build-zallet-testnet.sh"
grep -Fq 'zallet-release:' "$repo_root/.github/workflows/ci.yml"
grep -Fq 'runs-on: ubuntu-22.04' "$repo_root/.github/workflows/ci.yml"
# shellcheck disable=SC2016
[[ $(grep -Fc 'bash scripts/build-zallet-testnet.sh "$RUNNER_TEMP/zallet-release-' \
    "$repo_root/.github/workflows/ci.yml") -eq 2 ]]
grep -Fq 'python3 scripts/verify-zallet-build.py' \
    "$repo_root/.github/workflows/ci.yml"
# shellcheck disable=SC2016
grep -Fq '"$RUNNER_TEMP/zallet-release-a/ZALLET_SHA256SUM"' \
    "$repo_root/.github/workflows/ci.yml"
# shellcheck disable=SC2016
grep -Fq '"$RUNNER_TEMP/zallet-release-b/ZALLET_SHA256SUM"' \
    "$repo_root/.github/workflows/ci.yml"
grep -Fq 'cmp --silent' "$repo_root/.github/workflows/ci.yml"
grep -Fq 'toolchain=1.95.0' "$repo_root/scripts/build-zallet-testnet.sh"
grep -Fq 'protoc_version=25.9' "$repo_root/scripts/build-zallet-testnet.sh"
grep -Fq 'protoc_sha256=88f2d0c78a1072c4f84c59e9f9785b74849953e882a573188bc2d0518915b03e' \
    "$repo_root/scripts/build-zallet-testnet.sh"
# shellcheck disable=SC2016
grep -Fq 'export PROTOC="$protoc_root/bin/protoc"' \
    "$repo_root/scripts/build-zallet-testnet.sh"
# shellcheck disable=SC2016
grep -Fq 'export PROTOC_INCLUDE="$protoc_root/include"' \
    "$repo_root/scripts/build-zallet-testnet.sh"
# shellcheck disable=SC2016
grep -Fq '"$PROTOC" --version >"$temporary/protoc-version"' \
    "$repo_root/scripts/build-zallet-testnet.sh"
# shellcheck disable=SC2016
grep -Fq 'cd "$source_dir"' "$repo_root/scripts/build-zallet-testnet.sh"
grep -Fq -- '--manifest-path backends/zaino/Cargo.toml' \
    "$repo_root/scripts/build-zallet-testnet.sh"
# shellcheck disable=SC2016
grep -Fq 'export CXXFLAGS="-include cstdint $CFLAGS"' \
    "$repo_root/scripts/build-zallet-testnet.sh"
grep -Fq -- '--features rpc-cli,zcashd-import' \
    "$repo_root/scripts/build-zallet-testnet.sh"
grep -Fq 'timeout --signal=TERM --kill-after=10s 300s' \
    "$repo_root/scripts/build-zallet-testnet.sh"
# shellcheck disable=SC2016
grep -Fq 'for candidate in "$target_dir"/debug/deps/zallet_core-*; do' \
    "$repo_root/scripts/build-zallet-testnet.sh"
# shellcheck disable=SC2016
grep -Fq '[[ ${#zallet_core_test_harnesses[@]} -eq 1 ]]' \
    "$repo_root/scripts/build-zallet-testnet.sh"
# shellcheck disable=SC2016
grep -Fq '[[ -f $candidate && ! -L $candidate && -x $candidate ]]' \
    "$repo_root/scripts/build-zallet-testnet.sh"
grep -Fq 'for _stress_iteration in {1..200}; do' \
    "$repo_root/scripts/build-zallet-testnet.sh"
# shellcheck disable=SC2016
grep -Fq 'cd "$source_dir/zallet-core"' \
    "$repo_root/scripts/build-zallet-testnet.sh"
# shellcheck disable=SC2016
grep -Fq '"$zallet_core_test_harness" components::sync::tests --test-threads=1' \
    "$repo_root/scripts/build-zallet-testnet.sh"
grep -Fq 'components::sync::tests::wallet_sync_error_shuts_down_the_spawned_batch_decryptor' \
    "$repo_root/scripts/build-zallet-testnet.sh"
grep -Fq 'const MIN_WALLET_POOL_SIZE: usize = 8;' \
    "$repo_root/patches/zallet-v0.1.0-beta.3/0001-reserve-wallet-database-capacity.patch"
grep -Fq 'config.timeouts.wait = Some(WALLET_POOL_WAIT_TIMEOUT);' \
    "$repo_root/patches/zallet-v0.1.0-beta.3/0001-reserve-wallet-database-capacity.patch"
grep -Fq '.runtime(deadpool::Runtime::Tokio1)' \
    "$repo_root/patches/zallet-v0.1.0-beta.3/0001-reserve-wallet-database-capacity.patch"
grep -Fq 'denied_build_constants.extend([CARGO_MANIFEST_DIR, CARGO_TREE]);' \
    "$repo_root/patches/zallet-v0.1.0-beta.3/0003-remove-nonreproducible-shadow-paths.patch"
grep -Fq 'tokio::time::timeout(Duration::from_secs(30), async {' \
    "$repo_root/patches/zallet-v0.1.0-beta.3/0004-observe-batch-decryptor-shutdown.patch"
grep -Fq 'async fn spawn_observed<C, F>' \
    "$repo_root/patches/zallet-v0.1.0-beta.3/0004-observe-batch-decryptor-shutdown.patch"
grep -Fq 'observe_batch_task(batch_decryptor_task.abort_handle());' \
    "$repo_root/patches/zallet-v0.1.0-beta.3/0004-observe-batch-decryptor-shutdown.patch"
grep -Fq 'while !batch_task_abort.is_finished()' \
    "$repo_root/patches/zallet-v0.1.0-beta.3/0004-observe-batch-decryptor-shutdown.patch"
grep -Fq 'generated shadow metadata contains its build path' \
    "$repo_root/scripts/build-zallet-testnet.sh"
# shellcheck disable=SC2016
grep -Fq 'for patch in "${patches[@]}"; do' \
    "$repo_root/scripts/build-zallet-testnet.sh"
if grep -Fq 'glob("*.patch")' "$repo_root/scripts/build-zallet-testnet.sh"; then
    printf 'deployment-package-test: Zallet provenance glob is not the applied patch set\n' >&2
    exit 1
fi
# shellcheck disable=SC2016
grep -Fq 'staging=$(mktemp -d "$output_parent/.zallet-build.XXXXXX")' \
    "$repo_root/scripts/build-zallet-testnet.sh"
# shellcheck disable=SC2016
grep -Fq 'trap '\''rm -rf -- "$temporary" "$staging"'\'' EXIT' \
    "$repo_root/scripts/build-zallet-testnet.sh"
# shellcheck disable=SC2016
grep -Fq 'mv -T -- "$staging" "$output"' \
    "$repo_root/scripts/build-zallet-testnet.sh"
grep -Fx -- '    --deadline 1080' \
    "$repo_root/scripts/deploy/wait-zallet-ready.sh" >/dev/null
# shellcheck disable=SC2016
grep -Fq '$script_dir/zallet_rpc_health.py' \
    "$repo_root/scripts/deploy/wait-zallet-ready.sh"
if grep -Fq '/usr/local/libexec' "$repo_root/scripts/deploy/wait-zallet-ready.sh"; then
    printf 'deployment-package-test: Zallet readiness escaped its immutable release\n' >&2
    exit 1
fi
PYTHONPYCACHEPREFIX="$temporary/pycache" python3 -m py_compile \
    "$repo_root"/scripts/deploy/*.py \
    "$repo_root/scripts/verify-zallet-build.py" \
    "$repo_root/scripts/test-zec-wallet-recovery.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$repo_root/scripts/test-zec-wallet-recovery.py" >/dev/null
PYTHONDONTWRITEBYTECODE=1 python3 "$repo_root/scripts/test-import-zallet-mnemonic.py" >/dev/null
PYTHONDONTWRITEBYTECODE=1 python3 "$repo_root/scripts/test-zec-import-completion.py" >/dev/null
for helper in \
    finalize-zec-offline-custody.sh \
    import-zallet-mnemonic.py \
    seal-zec-initial-zero.sh \
    verify-zec-import-completion.py; do
    [[ -x $repo_root/scripts/deploy/$helper ]] || {
        printf 'deployment-package-test: required ceremony helper is not executable: %s\n' \
            "$helper" >&2
        exit 1
    }
done
[[ -x $repo_root/scripts/deploy/verify-zec-wallet-recovery.py ]] || {
    printf 'deployment-package-test: ZEC wallet recovery verifier is not executable\n' >&2
    exit 1
}
grep -Fq 'capture-original' "$repo_root/scripts/deploy/verify-zec-wallet-recovery.py"
grep -Fq 'capture-recovered' "$repo_root/scripts/deploy/verify-zec-wallet-recovery.py"
grep -Fq -- '--ack-fresh-isolated-mnemonic-recovery' \
    "$repo_root/scripts/deploy/verify-zec-wallet-recovery.py"
grep -Fq 'operator_acknowledged_fresh_isolated_mnemonic_recovery' \
    "$repo_root/scripts/deploy/verify-zec-wallet-recovery.py"
grep -Fq 'validate-zec-testnet-orchard' \
    "$repo_root/scripts/deploy/verify-zec-wallet-recovery.py"
if grep -Fq 'fresh_isolated_mnemonic_recovery_verified' \
    "$repo_root/scripts/deploy/verify-zec-wallet-recovery.py"; then
    printf 'deployment-package-test: ZEC recovery overclaims machine verification\n' >&2
    exit 1
fi
PYTHONDONTWRITEBYTECODE=1 python3 - "$repo_root/scripts/deploy/zallet_rpc_health.py" <<'PY'
import http.client
import importlib.util
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("zallet_rpc_health", source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class IncompleteRpcResponse:
    def __init__(self, *_args, **_kwargs):
        pass

    def request(self, *_args, **_kwargs):
        raise http.client.IncompleteRead(b"", 1)

    def close(self):
        pass

module.http.client.HTTPConnection = IncompleteRpcResponse
assert module.probe("127.0.0.1", 1, "user:test-value", 0.1) is False

tip = {
    "blockhash": "01" * 32,
    "height": 4_341_450,
}
ready = {
    "node_tip": tip,
    "wallet_tip": dict(tip),
    "fully_synced_height": tip["height"],
    "locked": False,
}
assert module.wallet_status_is_ready(ready) is True
accountless = dict(ready)
accountless.pop("fully_synced_height")
assert module.wallet_status_is_ready(accountless) is True
for field, value in [
    ("locked", True),
    ("sync_work_remaining", {"unscanned_blocks": 1}),
    ("sync_work_remaining", None),
    ("fully_synced_height", tip["height"] - 1),
    ("fully_synced_height", None),
    ("fully_synced_height", True),
    ("fully_synced_height", str(tip["height"])),
]:
    invalid = dict(ready)
    invalid[field] = value
    assert module.wallet_status_is_ready(invalid) is False
for field, value in [("height", tip["height"] - 1), ("blockhash", "11" * 32)]:
    invalid = dict(ready)
    invalid["wallet_tip"] = dict(tip)
    invalid["wallet_tip"][field] = value
    assert module.wallet_status_is_ready(invalid) is False
for blockhash in ["0" * 64, "AA" * 32, "gg" * 32]:
    invalid = dict(ready)
    invalid["node_tip"] = {"blockhash": blockhash, "height": tip["height"]}
    invalid["wallet_tip"] = dict(invalid["node_tip"])
    assert module.wallet_status_is_ready(invalid) is False
for height in [False, 0, -1, 0x1_0000_0000]:
    invalid = dict(ready)
    invalid["node_tip"] = {"blockhash": tip["blockhash"], "height": height}
    invalid["wallet_tip"] = dict(invalid["node_tip"])
    invalid["fully_synced_height"] = height
    assert module.wallet_status_is_ready(invalid) is False

class StaticRpcResponse:
    status = 200

    def __init__(self, payload):
        self.payload = payload

    def read(self, _limit):
        return json.dumps(self.payload).encode("utf-8")

class StaticRpcConnection:
    payload = None

    def __init__(self, *_args, **_kwargs):
        pass

    def request(self, *_args, **_kwargs):
        pass

    def getresponse(self):
        return StaticRpcResponse(self.payload)

    def close(self):
        pass

module.http.client.HTTPConnection = StaticRpcConnection
StaticRpcConnection.payload = {
    "id": "zecwec-readiness",
    "error": None,
    "result": ready,
}
assert module.probe("127.0.0.1", 28232, "user:test-value", 0.1) is True
for malformed in [
    [],
    {"id": "wrong-id", "error": None, "result": ready},
    {"id": "zecwec-readiness", "error": {"code": -1}, "result": ready},
]:
    StaticRpcConnection.payload = malformed
    assert module.probe("127.0.0.1", 28232, "user:test-value", 0.1) is False
PY
cargo build --locked --quiet --manifest-path "$repo_root/Cargo.toml" \
    --package wcash-poold --bin wcash-poold

mkdir -p "$temporary/release" "$temporary/output"
for binary in wcash-poold wcash-merge-miner wcash-wallet zallet; do
    cp /bin/sh "$temporary/release/$binary"
    chmod 0555 "$temporary/release/$binary"
done
python3 - \
    "$temporary/release" \
    "$repo_root/patches/zallet-v0.1.0-beta.3" <<'PY'
import hashlib
import json
import pathlib
import sys

release = pathlib.Path(sys.argv[1])
patch_dir = pathlib.Path(sys.argv[2])
binary_sha256 = hashlib.sha256((release / "zallet").read_bytes()).hexdigest()
patch_names = [
    "0001-reserve-wallet-database-capacity.patch",
    "0002-signal-data-requests-after-chain-writes.patch",
    "0003-remove-nonreproducible-shadow-paths.patch",
    "0004-observe-batch-decryptor-shutdown.patch",
    "zewif-zcashd-0.1.0-rc.5-relocatable-db-dump.patch",
]
record = {
    "schema_version": 1,
    "upstream": "https://github.com/zcash/zallet",
    "base_commit": "987382f67e622915228686e9f956c6a9c9a7514c",
    "binary": "zallet-zaino renamed to zallet",
    "features": ["rpc-cli", "zcashd-import"],
    "rustc": "rustc 1.95.0 (test fixture)",
    "cargo": "cargo 1.95.0 (test fixture)",
    "protoc": {
        "version": "libprotoc 25.9",
        "release": "25.9",
        "archive_sha256": "88f2d0c78a1072c4f84c59e9f9785b74849953e882a573188bc2d0518915b03e",
    },
    "source_date_epoch": 1787546182,
    "source_patch_sha256": "2bb4146e3c581d847ed943ac537564edf5a36eb971548a7f20ffaa838f1cdd5b",
    "binary_sha256": binary_sha256,
    "cargo_lock": {
        "path": "backends/zaino/Cargo.lock",
        "sha256": "3915e0b4907510b8f76b9deebba1840a7ec233c2a265bc5e0e9fe52e21b682d2",
    },
    "patched_dependencies": [
        {
            "name": "zewif-zcashd",
            "version": "0.1.0-rc.5",
            "archive": "https://static.crates.io/crates/zewif-zcashd/zewif-zcashd-0.1.0-rc.5.crate",
            "archive_sha256": "b67252cc55aad73afc6d608f29d14711d86e2b06bffcb76585aba31ee6310901",
        }
    ],
    "patches": [
        {
            "name": name,
            "sha256": hashlib.sha256((patch_dir / name).read_bytes()).hexdigest(),
        }
        for name in patch_names
    ],
}
(release / "ZALLET_SHA256SUM").write_text(
    f"{binary_sha256}  zallet\n", encoding="ascii"
)
(release / "PROVENANCE.json").write_text(
    json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
python3 "$repo_root/scripts/verify-zallet-build.py" \
    "$temporary/release" "$repo_root/patches/zallet-v0.1.0-beta.3" >/dev/null
cp "$temporary/release/PROVENANCE.json" "$temporary/provenance.good"
python3 - "$temporary/release/PROVENANCE.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
record = json.loads(path.read_text(encoding="utf-8"))
record["binary_sha256"] = "0" * 64
path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "$repo_root/scripts/verify-zallet-build.py" \
    "$temporary/release" "$repo_root/patches/zallet-v0.1.0-beta.3" \
    >/dev/null 2>&1; then
    printf 'deployment-package-test: invalid Zallet provenance was accepted\n' >&2
    exit 1
fi
mv "$temporary/provenance.good" "$temporary/release/PROVENANCE.json"
(
    cd "$temporary/release"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum wcash-poold wcash-merge-miner wcash-wallet zallet \
            PROVENANCE.json ZALLET_SHA256SUM >SHA256SUMS
    else
        shasum -a 256 wcash-poold wcash-merge-miner wcash-wallet zallet \
            PROVENANCE.json ZALLET_SHA256SUM >SHA256SUMS
    fi
)

python3 - \
    "$repo_root/deploy/config/deployment.env.example" \
    "$temporary/deployment.env" \
    "$temporary/authority.json" <<'PY'
import json
import pathlib
import sys

source, output, authority = map(pathlib.Path, sys.argv[1:])
wcash_display = bytes(range(1, 33)).hex()
zcash_display = bytes(range(33, 65)).hex()
uuids = {
    "DEPLOYMENT_ID": "11111111-1111-4111-8111-111111111111",
    "POOL_INSTANCE": "22222222-2222-4222-8222-222222222222",
    "WCASH_SIGNER_ACCOUNT": "33333333-3333-4333-8333-333333333333",
    "ZCASH_SIGNER_ACCOUNT": "44444444-4444-4444-8444-444444444444",
}
hex_values = {
    "WCASH_GENESIS_DISPLAY": wcash_display,
    "WCASH_GENESIS_WIRE": bytes.fromhex(wcash_display)[::-1].hex(),
    "ZCASH_GENESIS_DISPLAY": zcash_display,
    "ZCASH_GENESIS_WIRE": bytes.fromhex(zcash_display)[::-1].hex(),
    "WCASH_PAYOUT_COMMITMENT_WIRE": bytes(range(65, 97)).hex(),
    "ZCASH_PAYOUT_COMMITMENT_WIRE": bytes(range(97, 129)).hex(),
    "INITIAL_SHARE_TARGET_BE": bytes(range(1, 33)).hex(),
    "EASIEST_SHARE_TARGET_BE": bytes(range(129, 161)).hex(),
}
integer_values = {
    "ZCASH_SIGNER_ACCOUNT_INDEX": "0",
}
lines = []
for raw in source.read_text(encoding="utf-8").splitlines():
    if "=" not in raw or raw.lstrip().startswith("#"):
        lines.append(raw)
        continue
    key, value = raw.split("=", 1)
    if key in uuids:
        value = uuids[key]
    elif key in hex_values:
        value = hex_values[key]
    elif key in integer_values:
        value = integer_values[key]
    lines.append(f"{key}={value}")
rendered = "\n".join(lines) + "\n"
for raw in rendered.splitlines():
    if "=" in raw and not raw.lstrip().startswith("#"):
        _, value = raw.split("=", 1)
        if "CHANGE_ME" in value:
            raise SystemExit("fixture did not replace every required value")
output.write_text(rendered, encoding="utf-8")
authority.write_text(
    json.dumps(
        {
            "command": "pool-backend-init",
            "result": "initialized",
            "backend_instance": "55555555-5555-4555-8555-555555555555",
            "journal_stream": "66666666-6666-4666-8666-666666666666",
            "event_seq": 0,
            "chain_id": 1464025427,
            "listener_workers": 4,
            "wcash_genesis": bytes.fromhex(wcash_display)[::-1].hex(),
            "zcash_genesis": bytes.fromhex(zcash_display)[::-1].hex(),
            "wcash_payout_commitment": bytes(range(65, 97)).hex(),
            "zcash_payout_commitment": bytes(range(97, 129)).hex(),
            "share_target_ceiling": bytes(range(129, 161)).hex(),
            "share_target_ceiling_byte_order": "big_endian",
        }
    )
    + "\n",
    encoding="utf-8",
)
PY

python3 "$repo_root/scripts/deploy/render_deployment.py" finalize \
    --settings "$temporary/deployment.env" \
    --authority "$temporary/authority.json" \
    --source-root "$repo_root" \
    --release-root "$temporary/release" \
    --output "$temporary/output" \
    --pool-uid 12345 \
    --payout-uid 12346

python3 - "$temporary/output" <<'PY'
import json
import pathlib
import re
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
runtime = tomllib.loads((root / "pool.runtime.toml").read_text(encoding="utf-8"))
migrate = tomllib.loads((root / "pool.migrate.toml").read_text(encoding="utf-8"))
preflight = tomllib.loads((root / "pool.preflight.toml").read_text(encoding="utf-8"))
projector = tomllib.loads((root / "pool.projector.toml").read_text(encoding="utf-8"))
payout = tomllib.loads((root / "pool.payout.toml").read_text(encoding="utf-8"))
zallet = tomllib.loads((root / "zallet.toml").read_text(encoding="utf-8"))
zallet_payout = tomllib.loads((root / "zallet-payout.toml").read_text(encoding="utf-8"))
zallet_recovery = tomllib.loads(
    (root / "zallet-recovery.toml").read_text(encoding="utf-8")
)
manifest = json.loads((root / "render-manifest.json").read_text(encoding="utf-8"))
release_policy = (root / "release.env").read_text(encoding="utf-8")

assert runtime["network"] == "testnet"
assert runtime["wcash_wallet_uid"] == 0
assert runtime["payout_mode"] == "deferred"
assert runtime["nonce_reservation"] == 65536
assert runtime["backend_instance"] == "55555555-5555-4555-8555-555555555555"
assert runtime["journal_stream"] == "66666666-6666-4666-8666-666666666666"
assert runtime["database_url_file"] == "/run/credentials/wcash-pool.service/database-url"
assert runtime["wcash_node_rpc"] == "127.0.0.1:38232"
assert runtime["wcash_node_cookie_file"] == "/run/credentials/wcash-pool.service/wcash-node-cookie"
assert migrate["database_url_file"] == "/run/credentials/wcash-pool-migrate.service/database-url"
assert preflight["database_url_file"] == "/run/credentials/wcash-pool-preflight.service/database-url"
assert preflight["wcash_node_cookie_file"] == "/run/credentials/wcash-pool-preflight.service/wcash-node-cookie"
assert projector["database_url_file"] == (
    "/run/credentials/wcash-pool-projector.service/database-url"
)
assert runtime["wcash_wallet_program"] == str(root.parent / "release" / "wcash-wallet")
for policy in (runtime, migrate, preflight, projector):
    assert policy["payout_mode"] == "deferred"
    for payout_only in (
        "wcash_wallet_database",
        "wcash_lightwalletd_endpoint",
        "wcash_wallet_sync_batch_size",
        "wcash_wallet_sync_timeout_seconds",
        "wcash_wallet_seed_file",
        "wcash_seed_uid",
        "wcash_signer_journal_directory",
        "wcash_signer_account",
        "zallet_configuration",
        "zallet_rpc",
        "zallet_cookie_file",
        "zcash_signer_journal_directory",
        "zcash_signer_account",
        "zcash_signer_account_index",
    ):
        assert payout_only not in policy
assert payout["payout_mode"] == "automatic"
assert payout["database_url_file"] == (
    "/run/credentials/wcash-payout-worker.service/database-url"
)
assert payout["wcash_wallet_seed_file"] == (
    "/run/credentials/wcash-payout-worker.service/wcash-seed"
)
assert payout["wcash_seed_uid"] == 12346
assert payout["wcash_wallet_database"] == "/var/lib/wcash-payout/wcash-wallet.sqlite"
assert payout["wcash_signer_journal_directory"] == "/var/lib/wcash-payout/wec-payout-journal"
assert payout["zcash_signer_journal_directory"] == "/var/lib/wcash-payout/zec-payout-journal"
assert payout["zallet_configuration"] == (
    "/run/credentials/wcash-payout-worker.service/zallet-config"
)
assert zallet["consensus"]["network"] == "test"
assert zallet["builder"] == {"limits": {}}
assert zallet["external"]["broadcast"] is False
assert zallet["features"]["as_of_version"] == "0.1.0-beta.3"
assert zallet["rpc"]["bind"] == ["127.0.0.1:28232"]
assert zallet_payout["external"]["broadcast"] is False
assert zallet_payout["keystore"]["encryption_identity"] == (
    "/run/credentials/zecwec-zallet-payout.service/encryption-identity"
)
assert zallet_payout["rpc"]["bind"] == ["127.0.0.1:28232"]
assert zallet_recovery["consensus"]["network"] == "test"
assert zallet_recovery["external"]["broadcast"] is False
assert zallet_recovery["features"]["as_of_version"] == "0.1.0-beta.3"
assert zallet_recovery["rpc"]["bind"] == ["127.0.0.1:28242"]
assert zallet_recovery["indexer"]["validator_cookie_path"] == (
    "/run/credentials/zecwec-zallet-recovery.service/validator-cookie"
)
assert manifest["network"] == "testnet"
assert manifest["release_root"] == str(root.parent / "release")
assert manifest["deployment_schema"] == 2
assert "ZECWEC_DEPLOYMENT_SCHEMA=2\n" in release_policy

for path in root.rglob("*"):
    if path.is_file():
        text = path.read_text(encoding="utf-8")
        assert "CHANGE_ME" not in text
        assert "BOOTSTRAP_DISCOVERY_REQUIRED" not in text
        assert re.search(r"@[A-Z][A-Z0-9_]*@", text) is None

pool_unit = (root / "systemd/wcash-pool.service").read_text(encoding="utf-8")
projector_unit = (root / "systemd/wcash-pool-projector.service").read_text(encoding="utf-8")
migrate_unit = (root / "systemd/wcash-pool-migrate.service").read_text(encoding="utf-8")
backend_unit = (root / "systemd/wcash-pool-backend.service").read_text(encoding="utf-8")
assert "User=wcash-pool\n" in pool_unit
assert "SupplementaryGroups=wcash-pool-socket" in pool_unit
assert "LoadCredential=database-url:" in pool_unit
assert "LoadCredential=wcash-node-cookie:" in pool_unit
assert "LoadCredential=zallet-" not in pool_unit
assert (
    "Conflicts=zecwec-zallet.service zecwec-zallet-recovery.service "
    "wcash-pool-wallet-init.service "
    "wcash-pool-zec-authority-bootstrap.service"
) in pool_unit
assert (
    "After=network-online.target postgresql.service wcash-pool-migrate.service "
    "wcash-pool-backend.service wcash-pool-projector.service "
    "wcash-pool-custody-gate.service "
    "zecwec-zallet.service zecwec-zallet-recovery.service "
    "wcash-pool-wallet-init.service "
    "wcash-pool-zec-authority-bootstrap.service"
) in pool_unit
assert "Requires=" in pool_unit and "wcash-pool-custody-gate.service" in pool_unit
assert "Requires=" in pool_unit and "wcash-pool-projector.service" in pool_unit
assert "BindsTo=" in pool_unit and "wcash-pool-projector.service" in pool_unit
for forbidden_credential in ("wcash-seed", "zallet-cookie", "signer-journal"):
    assert f"LoadCredential={forbidden_credential}" not in pool_unit
assert "InaccessiblePaths=" in pool_unit
assert "/opt/wcash/current" not in pool_unit
assert str(root.parent / "release") in pool_unit
assert "User=wcash-pool-projector\n" in projector_unit
assert "Group=wcash-pool-projector\n" in projector_unit
assert "SupplementaryGroups=wcash-pool-socket\n" in projector_unit
assert (
    "LoadCredential=database-url:/etc/wcash-pool/credentials/database-url-projector"
    in projector_unit
)
assert (
    "ExecStart=" + str(root.parent / "release" / "wcash-poold") + " projector"
    in projector_unit
)
assert " projector --config /etc/wcash-pool/pool.projector.toml" in projector_unit
assert "SocketBindDeny=any" in projector_unit
assert "ListenStream=" not in projector_unit
for forbidden_credential in (
    "wcash-seed",
    "wcash-node-cookie",
    "zcash-node-cookie",
    "zallet-cookie",
    "portal-token-pepper",
    "portal-totp-key",
):
    assert f"LoadCredential={forbidden_credential}" not in projector_unit
assert "User=wcash-pool-migrate\n" in migrate_unit
assert "Group=wcash-pool-migrate\n" in migrate_unit
assert migrate_unit.count("LoadCredential=") == 1
assert "LoadCredential=database-url:" in migrate_unit
assert "LoadCredential=portal-" not in migrate_unit
assert "SocketBindDeny=any" in migrate_unit
assert "wcash-poold config-check" not in migrate_unit
assert (
    "grant-runtime.sh /run/credentials/wcash-pool-migrate.service/database-url "
    "zecwec_pool_migrator zecwec_pool_runtime zecwec_pool_projector "
    "zecwec_pool_payout"
) in migrate_unit
assert "User=wcash-pool-backend\n" in backend_unit
assert "Group=wcash-pool-socket\n" in backend_unit
assert "SupplementaryGroups=wcash-pool-backend\n" in backend_unit
assert "LoadCredential=wcash-payout-ivk:" in backend_unit
assert "LoadCredential=wcash-wallet-authority:/var/lib/wcash-payout/wcash-wallet-authority.json" in backend_unit
assert "LoadCredential=zec-authority-config:/etc/wcash-pool/zec-authority.testnet.toml" in backend_unit
assert "LoadCredential=zec-initial-zero-result:/var/lib/zecwec-custody/zec-collector-initial-zero.json" in backend_unit
assert "LoadCredential=zec-initial-zero-attestation:/var/lib/zecwec-custody/zec-collector-initial-zero.attestation" in backend_unit
assert "zec-authority-bootstrap.sh verify" in backend_unit

preflight_unit = (root / "systemd/wcash-pool-preflight.service").read_text(encoding="utf-8")
zallet_unit = (root / "systemd/zecwec-zallet.service").read_text(encoding="utf-8")
backend_init_unit = (root / "systemd/wcash-pool-backend-init.service").read_text(encoding="utf-8")
health_unit = (root / "systemd/wcash-pool-health.service").read_text(encoding="utf-8")
assert "User=root\n" in health_unit
assert (
    "CapabilityBoundingSet=CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH"
    in health_unit
)
assert "ReadWritePaths=/etc/ufw /run/ufw.lock /run/xtables.lock" in health_unit
assert "SupplementaryGroups=wcash-pool-backend\n" in backend_init_unit
executable_condition_units = {
    "wcash-pool-backend-init.service",
    "wcash-pool-backend.service",
    "wcash-pool-migrate.service",
    "wcash-pool-projector.service",
    "wcash-pool-preflight.service",
    "wcash-pool-wallet-init.service",
    "wcash-payout-worker.service",
    "wcash-pool-zec-authority-bootstrap.service",
    "wcash-pool.service",
    "zecwec-zallet.service",
    "zecwec-zallet-payout.service",
}
found_executable_conditions = set()
for service in (root / "systemd").glob("*.service"):
    rendered_service = service.read_text(encoding="utf-8")
    assert "ConditionPathIsExecutable=" not in rendered_service
    if "ConditionFileIsExecutable=" in rendered_service:
        assert rendered_service.count("ConditionFileIsExecutable=") == 1
        found_executable_conditions.add(service.name)
assert found_executable_conditions == executable_condition_units
assert "pool.preflight.toml" in preflight_unit
assert "LoadCredential=zallet-" not in preflight_unit
assert "zecwec-zallet.service" not in preflight_unit
assert "wcash-pool-wallet-init.service" not in preflight_unit
assert "InaccessiblePaths=" in preflight_unit
assert "wcash-pool-wallet-init.service" not in backend_init_unit
assert "wcash-pool-zec-authority-bootstrap.service" not in backend_init_unit
assert "/run/credentials/wcash-pool-preflight.service" not in pool_unit
assert "TimeoutStopSec=1920s" in pool_unit
assert "KillMode=mixed" in pool_unit
assert "TimeoutStartSec=1800s" in pool_unit
assert "TimeoutStartSec=1800s" in preflight_unit
assert "TimeoutStartSec=1200s" in zallet_unit
assert "ConditionFileIsExecutable=" in zallet_unit
assert "ConditionPathIsExecutable=" not in zallet_unit
assert "WantedBy=zecwec-testnet-pool.target" not in zallet_unit

# Every local systemd Before=/After= edge must be acyclic. In particular, the
# mutually exclusive recovery ceremony is ordered before the runtime only from
# the runtime side; mirroring that edge would make target startup impossible.
systemd_units = {
    path.name.removesuffix(".in"): path
    for path in (root / "systemd").glob("*.in")
    if path.name.endswith((".service.in", ".target.in", ".socket.in", ".path.in", ".timer.in"))
}
ordering = {unit: set() for unit in systemd_units}
for unit, path in systemd_units.items():
    section = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("["):
            section = line
            continue
        if section != "[Unit]" or not line.startswith(("After=", "Before=")):
            continue
        relation, values = line.split("=", 1)
        for other in values.split():
            if other not in systemd_units:
                continue
            if relation == "After":
                ordering[unit].add(other)
            else:
                ordering[other].add(unit)

visited = set()
active = set()
def assert_acyclic(unit):
    if unit in active:
        raise AssertionError(f"systemd ordering cycle reaches {unit}")
    if unit in visited:
        return
    active.add(unit)
    for dependency in ordering[unit]:
        assert_acyclic(dependency)
    active.remove(unit)
    visited.add(unit)

for systemd_unit in systemd_units:
    assert_acyclic(systemd_unit)

custody_gate_unit = (root / "systemd/wcash-pool-custody-gate.service").read_text(
    encoding="utf-8"
)
assert "User=root\n" in custody_gate_unit
assert "verify-offline-custody.sh /etc/wcash-pool/deployment.env" in custody_gate_unit
assert "verify-release.sh wcash-poold" in custody_gate_unit
assert "verify-release.sh deployment-package" in custody_gate_unit
assert (
    "CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH"
    in custody_gate_unit
)
assert all(
    "CAP_DAC_OVERRIDE" not in line
    for line in custody_gate_unit.splitlines()
    if line.startswith("CapabilityBoundingSet=")
)
assert "Conflicts=zecwec-zallet.service" in custody_gate_unit
assert (
    "After=zecwec-zallet.service zecwec-zallet-recovery.service "
    "wcash-pool-wallet-init.service "
    "wcash-pool-zec-authority-bootstrap.service"
) in custody_gate_unit
assert "After=zecwec-zallet.service zecwec-zallet-payout.service" not in custody_gate_unit
assert "After=wcash-payout-worker.service" not in custody_gate_unit
assert "ConditionPathExists=" not in custody_gate_unit
assert "ConditionFileIsExecutable=" not in custody_gate_unit

zallet_recovery_unit = (
    root / "systemd/zecwec-zallet-recovery.service"
).read_text(encoding="utf-8")
assert (
    "After=network-online.target zcash-validator-testnet.service zecwec-zallet.service"
    in zallet_recovery_unit
)
zallet_recovery_after = next(
    line for line in zallet_recovery_unit.splitlines() if line.startswith("After=")
)
assert "wcash-pool-projector.service" not in zallet_recovery_after
assert "wcash-pool.service" not in zallet_recovery_after
assert "wcash-pool-zec-authority-bootstrap.service" not in zallet_recovery_after

for mining_unit in (
    pool_unit,
    projector_unit,
    preflight_unit,
    backend_unit,
    backend_init_unit,
    migrate_unit,
):
    assert "LoadCredential=wcash-seed" not in mining_unit
    assert "LoadCredential=zallet-cookie" not in mining_unit

wallet_init_unit = (root / "systemd/wcash-pool-wallet-init.service").read_text(encoding="utf-8")
assert "User=wcash-payout\n" in wallet_init_unit
assert "LoadCredential=wcash-seed:" in wallet_init_unit
assert "EnvironmentFile=/etc/wcash-pool/wcash-wallet-bootstrap.env" in wallet_init_unit
assert "TimeoutStartSec=1200s" in wallet_init_unit
wallet_bootstrap = (root / "wcash-wallet-bootstrap.env").read_text(encoding="utf-8")
assert "WCASH_WALLET_BIRTHDAY=1" in wallet_bootstrap
assert "WCASH_WALLET_AUTHORITY=/var/lib/wcash-payout/wcash-wallet-authority.json" in wallet_bootstrap
payout_unit = (root / "systemd/wcash-payout-worker.service").read_text(encoding="utf-8")
assert "Type=notify\n" in payout_unit
assert "NotifyAccess=main\n" in payout_unit
assert "TimeoutStartSec=4200s\n" in payout_unit
assert "User=wcash-payout\n" in payout_unit
assert "SupplementaryGroups=wcash-pool-socket\n" in payout_unit
assert "payout-config-check --config /etc/wcash-pool/pool.payout.toml" in payout_unit
assert "wcash-poold preflight --config /etc/wcash-pool/pool.payout.toml" not in payout_unit
assert "LoadCredential=database-url:/etc/wcash-pool/credentials/database-url-payout" in payout_unit
assert "LoadCredential=wcash-seed:/var/lib/wcash-pool-secrets/wcash-seed" in payout_unit
assert "LoadCredential=portal-" not in payout_unit
for inaccessible in (
    "/var/lib/wcash-pool",
    "/var/lib/wcash-pool-secrets/wcash-seed",
    "/etc/wcash-pool/credentials/zallet-encryption-identity",
    "/etc/wcash-pool/credentials/portal-token-pepper",
    "/etc/wcash-pool/credentials/portal-totp-key",
    "/var/lib/zecwec-custody",
):
    assert inaccessible in payout_unit
assert "ExecStart=" + str(root.parent / "release" / "wcash-poold") + " payout-worker" in payout_unit
zallet_payout_unit = (root / "systemd/zecwec-zallet-payout.service").read_text(encoding="utf-8")
assert "LoadCredential=encryption-identity:" in zallet_payout_unit
assert "WantedBy=zecwec-testnet-pool.target" in zallet_payout_unit
assert "StartLimitIntervalSec=300" in payout_unit
assert "StartLimitBurst=3" in payout_unit
target_unit = (root / "systemd/zecwec-testnet-pool.target").read_text(encoding="utf-8")
startup_unit = (root / "systemd/zecwec-testnet-pool-start.service").read_text(
    encoding="utf-8"
)
health_timer = (root / "systemd/wcash-pool-health.timer").read_text(encoding="utf-8")
health_service = (root / "systemd/wcash-pool-health.service").read_text(encoding="utf-8")
assert (
    "CapabilityBoundingSet=CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH"
    in health_service
)
assert all(
    "CAP_DAC_OVERRIDE" not in line
    for line in health_service.splitlines()
    if line.startswith("CapabilityBoundingSet=")
)
cookie_refresh_path = (root / "systemd/zecwec-cookie-refresh.path").read_text(
    encoding="utf-8"
)
assert (
    "Upholds=wcash-pool-projector.service wcash-pool.service "
    "wcash-payout-worker.service zecwec-zallet-payout.service"
) in target_unit
assert "wcash-pool-health.timer" not in target_unit
assert "WantedBy=multi-user.target" not in target_unit
assert "WantedBy=timers.target" not in health_timer
assert "PartOf=zecwec-testnet-pool.target" in cookie_refresh_path
assert "Type=oneshot" in startup_unit
assert "User=root\n" in startup_unit
assert "After=network-online.target nginx.service postgresql.service" in startup_unit
assert "Wants=network-online.target nginx.service" in startup_unit
assert "Requires=nginx.service" not in startup_unit
assert "start-testnet-pool.sh /etc/wcash-pool/deployment.env /etc/wcash-pool/miner-cidrs" in startup_unit
assert "TimeoutStartSec=7200s" in startup_unit
assert "WantedBy=multi-user.target" in startup_unit

# Model the post-start failure domain instead of trusting a health timer: a
# BindsTo edge propagates an inactive dependency to its owner, and a PartOf edge
# propagates the target stop to each runtime member. Both payout authorities
# must therefore reach the one process that owns the Stratum and portal sockets.
runtime_units = {
    name: (root / "systemd" / name).read_text(encoding="utf-8")
    for name in (
        "zecwec-testnet-pool.target",
        "wcash-pool.service",
        "wcash-pool-projector.service",
        "wcash-payout-worker.service",
        "zecwec-zallet-payout.service",
    )
}
target_name = "zecwec-testnet-pool.target"
critical_members = set(runtime_units) - {target_name}
target_binds = next(line for line in target_unit.splitlines() if line.startswith("BindsTo="))
assert set(target_binds.removeprefix("BindsTo=").split()) == critical_members
for member in critical_members:
    assert f"PartOf={target_name}" in runtime_units[member]

stop_edges = {name: set() for name in runtime_units}
for owner, text in runtime_units.items():
    for line in text.splitlines():
        if line.startswith("BindsTo="):
            for dependency in line.removeprefix("BindsTo=").split():
                if dependency in stop_edges:
                    stop_edges[dependency].add(owner)
        elif line.startswith("PartOf="):
            for whole in line.removeprefix("PartOf=").split():
                if whole in stop_edges:
                    stop_edges[whole].add(owner)

def stopped_after(unit):
    stopped = {unit}
    pending = [unit]
    while pending:
        current = pending.pop()
        for affected in stop_edges[current]:
            if affected not in stopped:
                stopped.add(affected)
                pending.append(affected)
    return stopped

pool_config = tomllib.loads((root / "pool.runtime.toml").read_text(encoding="utf-8"))
assert pool_config["stratum_listen"] == "0.0.0.0:3333"
assert pool_config["portal_listen"] == "127.0.0.1:8080"
assert "wcash-poold serve --config /etc/wcash-pool/pool.runtime.toml" in pool_unit
for failed_authority in ("wcash-payout-worker.service", "zecwec-zallet-payout.service"):
    assert "wcash-pool.service" in stopped_after(failed_authority), (
        f"{failed_authority} failure leaves Stratum or portal running"
    )
zec_authority = tomllib.loads((root / "zec-authority.testnet.toml").read_text(encoding="utf-8"))
assert zec_authority["network"] == "testnet"
assert zec_authority["zcash_genesis_wire"] == bytes.fromhex(bytes(range(33, 65)).hex())[::-1].hex()
assert zec_authority["collector_payout_commitment"] == bytes(range(97, 129)).hex()
assert zec_authority["collector_account"] == "44444444-4444-4444-8444-444444444444"
assert zec_authority["collector_account_index"] == 0
assert zec_authority["required_confirmations"] == 100
assert zec_authority["zallet_cookie_file"] == "/run/credentials/wcash-pool-zec-authority-bootstrap.service/zallet-cookie"
assert zec_authority["zcash_node_cookie_file"] == "/run/credentials/wcash-pool-zec-authority-bootstrap.service/zcash-node-cookie"
zec_authority_unit = (root / "systemd/wcash-pool-zec-authority-bootstrap.service").read_text(encoding="utf-8")
assert "SupplementaryGroups=wcash-pool-backend\n" in zec_authority_unit
assert "Before=wcash-pool-backend-init.service" not in zec_authority_unit
assert "wcash-poold zec-authority-check" not in zec_authority_unit
assert "zec-authority-bootstrap.sh reconcile" in zec_authority_unit
assert "BindsTo=zecwec-zallet.service" not in zec_authority_unit
assert (
    "Conflicts=wcash-pool-projector.service wcash-pool.service "
    "zecwec-zallet-recovery.service"
) in zec_authority_unit

backend_environment = (root / "backend.env").read_text(encoding="utf-8")
assert "WCASH_SHARE_TARGET=" + bytes(range(129, 161)).hex() in backend_environment
assert "WCASH_AUTHORITY_SHARE_TARGET_BE=" + bytes(range(129, 161)).hex() in backend_environment
assert "WCASH_AUTHORITY_SIGNER_ACCOUNT=33333333-3333-4333-8333-333333333333" in backend_environment
assert "ZCASH_AUTHORITY_SIGNER_ACCOUNT=" not in backend_environment
assert "ZCASH_AUTHORITY_SIGNER_ACCOUNT_INDEX=" not in backend_environment
assert "WCASH_SHARE_JOURNAL=/var/lib/wcash-pool-backend/share-journal-protocol-v2.jsonl" in backend_environment
assert "WCASH_POOL_BACKEND_IDENTITY=/var/lib/wcash-pool-backend/backend-identity-protocol-v2.json" in backend_environment
assert "WCASH_POOL_BACKEND_JOURNAL=/var/lib/wcash-pool-backend/backend-journal-protocol-v2.jsonl" in backend_environment

stratum = (root / "nginx/zecwec-testnet-stratum.conf").read_text(encoding="utf-8")
assert "listen 3443 ssl;" in stratum
assert "server 127.0.0.1:3333;" in stratum

portal = (root / "nginx/zecwec-testnet-portal.conf").read_text(encoding="utf-8")
assert portal.count("ssl_verify_client on;") == 2
assert portal.count("listen 443 ssl http2;") == 2
assert portal.count("listen [::]:443 ssl http2;") == 2
assert "http2 on;" not in portal
assert portal.count("ssl_client_certificate /etc/wcash-pool/tls/cloudflare-origin-pull-ca.pem;") == 2
assert "proxy_set_header X-Forwarded-For $http_cf_connecting_ip;" in portal
assert "limit_req_zone $zecwec_credential_client zone=zecwec_portal_credentials:10m rate=6r/m;" in portal
assert "limit_req zone=zecwec_portal_credentials burst=4 nodelay;" in portal
assert "limit_req_status 429;" in portal
assert '\"POST:/api/v1/workers\" $http_cf_connecting_ip;' in portal
assert "return 444;" in portal
PY

PYTHONDONTWRITEBYTECODE=1 python3 - "$repo_root/scripts/deploy/grant-runtime.sh" <<'PY'
import pathlib
import sys

grants = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
assert "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES" not in grants
assert "GRANT UPDATE (last_event_seq, updated_at) ON TABLE backend_cursors" in grants
assert "GRANT UPDATE (state, active_observation_event_seq, active_maturity_event_seq)" in grants
assert "GRANT UPDATE (sealed_at, sealed_entry_count)" in grants
assert "public.configure_payout_destination_v1(" in grants
assert "public.activate_due_payout_destinations_v1(UUID,TEXT)" in grants
assert "public.freeze_chain_payouts_v1(UUID,TEXT,BIGINT,TEXT)" in grants
assert "public.lock_backend_projection_v1(UUID)" in grants
assert "public.lock_chain_safety_v1(UUID,TEXT)" in grants
cursor_signature = (
    "public.advance_confirmed_payout_watch_cursor_v1(\n"
    "    UUID,TEXT,BIGINT,UUID,UUID\n)"
)
assert grants.count(cursor_signature) == 2
assert (
    f"REVOKE ALL ON FUNCTION {cursor_signature} "
    'FROM :"public_role", :"projector_role", :"payout_role";'
) in grants
assert (
    f"GRANT EXECUTE ON FUNCTION {cursor_signature} TO :\"payout_role\";"
) in grants
payout_select_start = grants.index(
    "GRANT SELECT ON TABLE\n    deployments,\n    backend_cursors,\n    chain_policies,"
)
payout_select_end = grants.index('TO :"payout_role";', payout_select_start)
assert "payout_watch_cursors," in grants[payout_select_start:payout_select_end]
assert "GRANT SELECT (deployment_id, event_seq, payload_sha256)" in grants
assert 'ON TABLE backend_events TO :"payout_role";' in grants
assert 'ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public' in grants
assert 'ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"\n' in grants
assert "REVOKE ALL PRIVILEGES ON TABLES" in grants
assert "REVOKE ALL PRIVILEGES ON SEQUENCES" in grants
assert "REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC" in grants
assert "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC" in grants
assert "GRANT UPDATE ON TABLE\n    chain_safety_state" not in grants
assert "GRANT UPDATE ON TABLE\n    payout_destinations" not in grants
PY

# Model a clean host: every literal install(1) owner/group used by the renderer
# must be created by provision-host before rendering can begin. This catches a
# package that only succeeds on a developer host with an unrelated stale group.
PYTHONDONTWRITEBYTECODE=1 python3 - \
    "$repo_root/scripts/deploy/render-deployment.sh" \
    "$repo_root/scripts/deploy/provision-host.sh" <<'PY'
import pathlib
import re
import sys

renderer = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").replace("\\\n", " ")
provisioner = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
owners = set()
groups = set()
for line in renderer.splitlines():
    if not re.match(r"^\s*install\s", line):
        continue
    for kind, identity in re.findall(
        r"(?:^|\s)-(o|g)\s+([a-z][a-z0-9-]*)", line
    ):
        (owners if kind == "o" else groups).add(identity)
for owner in owners - {"root"}:
    assert f"id -u {owner} " in provisioner, f"renderer owner is not provisioned: {owner}"
for group in groups - {"root"}:
    assert f"getent group {group} " in provisioner, f"renderer group is not provisioned: {group}"
PY

# shellcheck disable=SC2016
grep -Fq 'install -o root -g wcash-pool-projector -m 0640 "$staging/pool.projector.toml"' \
    "$repo_root/scripts/deploy/render-deployment.sh"
# shellcheck disable=SC2016
grep -Fq 'install -o root -g wcash-pool-migrate -m 0640 "$staging/pool.migrate.toml"' \
    "$repo_root/scripts/deploy/render-deployment.sh"
# shellcheck disable=SC2016
grep -Fq 'install -o root -g wcash-payout -m 0640 "$staging/wcash-wallet-bootstrap.env"' \
    "$repo_root/scripts/deploy/render-deployment.sh"
# shellcheck disable=SC2016
grep -Fq 'install -o root -g zecwec-zallet -m 0640 "$staging/zallet.toml"' \
    "$repo_root/scripts/deploy/render-deployment.sh"
# shellcheck disable=SC2016
grep -Fq 'install -o root -g zecwec-zallet -m 0640 "$staging/zallet-payout.toml"' \
    "$repo_root/scripts/deploy/render-deployment.sh"
grep -Fq 'systemctl disable zecwec-testnet-pool-start.service' \
    "$repo_root/scripts/deploy/render-deployment.sh"
grep -Fq 'root:zecwec-zallet:640:1' "$repo_root/scripts/deploy/common.sh"
# shellcheck disable=SC2016
grep -Fq 'runuser --user zecwec-zallet -- /usr/bin/test -r "$zallet_config"' \
    "$repo_root/scripts/deploy/common.sh"
# shellcheck disable=SC2016
grep -Fq 'runuser --user zecwec-zallet -- /usr/bin/test -r "$zallet_payout_config"' \
    "$repo_root/scripts/deploy/common.sh"
grep -Fq 'stage-portal)' "$repo_root/scripts/deploy/enable-nginx-edge.sh"
grep -Fq -- '--ack-cloudflare-access' "$repo_root/scripts/deploy/enable-nginx-edge.sh"
grep -Fq 'Cloudflare Access did not deny the anonymous staging probe' \
    "$repo_root/scripts/deploy/enable-nginx-edge.sh"
# shellcheck disable=SC2016
grep -Fq 'require_direct_origin_mtls_rejection "$portal_host" 127.0.0.1' \
    "$repo_root/scripts/deploy/enable-nginx-edge.sh"
grep -Fq 'public_status != 200' "$repo_root/scripts/deploy/enable-nginx-edge.sh"
grep -Fq 'public_body != '\''{"status":"ok"}'\''' \
    "$repo_root/scripts/deploy/enable-nginx-edge.sh"
grep -Fq 'reconcile)' "$repo_root/scripts/deploy/enable-nginx-edge.sh"
grep -Fq 'portal_state=/etc/wcash-pool/portal-edge-mode' \
    "$repo_root/scripts/deploy/enable-nginx-edge.sh"
# shellcheck disable=SC2016
grep -Fq 'effective_mode=$(cat -- "$portal_state")' \
    "$repo_root/scripts/deploy/enable-nginx-edge.sh"

cat >"$temporary/fake-bin/curl" <<'SH'
#!/usr/bin/env bash
set -eu
output=
while (($#)); do
    case "$1" in
        --output) output=$2; shift 2 ;;
        --write-out) shift 2 ;;
        *) shift ;;
    esac
done
[[ -n $output ]]
printf '%s' "${CURL_TEST_BODY:-}" >"$output"
printf '%s' "${CURL_TEST_ERROR:-}" >&2
printf '%s\n%s\n' "${CURL_TEST_HTTP_STATUS:-000}" "${CURL_TEST_VERIFY_RESULT:-0}"
exit "${CURL_TEST_EXIT_STATUS:-0}"
SH
chmod 0555 "$temporary/fake-bin/curl"
for accepted_origin_rejection in tls-alert nginx-http-400; do
    curl_exit=0
    curl_http=400
    curl_body='No required SSL certificate was sent'
    curl_error=
    if [[ $accepted_origin_rejection == tls-alert ]]; then
        curl_exit=56
        curl_http=000
        curl_body=
        curl_error='OpenSSL SSL_read: tlsv13 alert certificate required'
    fi
    PATH="$temporary/fake-bin:$PATH" \
        CURL_TEST_EXIT_STATUS=$curl_exit \
        CURL_TEST_HTTP_STATUS=$curl_http \
        CURL_TEST_VERIFY_RESULT=0 \
        CURL_TEST_BODY=$curl_body \
        CURL_TEST_ERROR=$curl_error \
        bash -c 'source "$1"; require_direct_origin_mtls_rejection pool.example 127.0.0.1' \
        bash "$repo_root/scripts/deploy/common.sh"
done
for rejected_origin_probe in accepted generic-tls-failure untrusted-server; do
    curl_exit=0
    curl_http=200
    curl_verify=0
    curl_error=
    case $rejected_origin_probe in
        generic-tls-failure)
            curl_exit=35
            curl_http=000
            curl_error='OpenSSL SSL_connect: connection reset by peer'
            ;;
        untrusted-server)
            curl_exit=60
            curl_http=000
            curl_verify=20
            curl_error='SSL certificate problem: unable to get local issuer certificate'
            ;;
    esac
    if PATH="$temporary/fake-bin:$PATH" \
        CURL_TEST_EXIT_STATUS=$curl_exit \
        CURL_TEST_HTTP_STATUS=$curl_http \
        CURL_TEST_VERIFY_RESULT=$curl_verify \
        CURL_TEST_ERROR=$curl_error \
        bash -c 'source "$1"; require_direct_origin_mtls_rejection pool.example 127.0.0.1' \
        bash "$repo_root/scripts/deploy/common.sh" >/dev/null 2>&1; then
        printf 'deployment-package-test: direct origin probe accepted %s\n' \
            "$rejected_origin_probe" >&2
        exit 1
    fi
done

# Exercise the mining-certificate and live-listener gates deterministically.
# The deployment host performs the real OpenSSL verification against its
# system trust store; this fake records the security-relevant arguments and
# lets each failure boundary be tested without a private key fixture.
tls_fake_bin="$temporary/tls-fake-bin"
mkdir -p "$tls_fake_bin"
cat >"$tls_fake_bin/openssl" <<'SH'
#!/usr/bin/env bash
set -eu

printf '%s\n' "$*" >>"${TLS_TEST_LOG:?}"
command_name=${1:-}
shift || true
case "$command_name" in
    x509)
        input=
        output=
        operation=copy
        while (($#)); do
            case "$1" in
                -in) input=$2; shift 2 ;;
                -out) output=$2; shift 2 ;;
                -outform) shift 2 ;;
                -checkhost) operation=host; shift 2 ;;
                -checkend) operation=expiry; shift 2 ;;
                -pubkey) operation=public-key; shift ;;
                *) shift ;;
            esac
        done
        case "$operation" in
            copy)
                value=leaf
                if [[ ${TLS_TEST_LIVE_MISMATCH:-0} == 1 \
                    && $input == *served-leaf.pem ]]; then
                    value=different-leaf
                fi
                printf '%s\n' "$value" >"$output"
                ;;
            host) exit "${TLS_TEST_HOST_STATUS:-0}" ;;
            expiry) exit "${TLS_TEST_EXPIRY_STATUS:-0}" ;;
            public-key) printf '%s\n' public-key ;;
        esac
        ;;
    pkey)
        printf '%s\n' "${TLS_TEST_PRIVATE_PUBLIC_KEY:-public-key}"
        ;;
    verify)
        exit "${TLS_TEST_VERIFY_STATUS:-0}"
        ;;
    s_client)
        printf '%s\n' handshake
        exit "${TLS_TEST_LISTENER_STATUS:-0}"
        ;;
    *) exit 64 ;;
esac
SH
cat >"$tls_fake_bin/timeout" <<'SH'
#!/usr/bin/env bash
set -eu

while [[ ${1:-} == --* ]]; do
    shift
done
[[ ${1:-} =~ ^[0-9]+s$ ]]
shift
exec "$@"
SH
chmod 0555 "$tls_fake_bin/openssl" "$tls_fake_bin/timeout"
tls_test_log="$temporary/tls-gate.log"
tls_test_cert="$temporary/tls-certificate.pem"
tls_test_key="$temporary/tls-private-key.pem"
printf 'fixture\n' >"$tls_test_cert"
printf 'fixture\n' >"$tls_test_key"
PATH="$tls_fake_bin:$PATH" TLS_TEST_LOG="$tls_test_log" \
    bash -c 'source "$1"; require_public_tls_certificate "$2" "$3" "$4"' \
    bash "$repo_root/scripts/deploy/common.sh" \
    "$tls_test_cert" "$tls_test_key" testnet-mine.zecwec.com
PATH="$tls_fake_bin:$PATH" TLS_TEST_LOG="$tls_test_log" \
    bash -c 'source "$1"; require_public_tls_listener "$2" "$3" "$4" "$5"' \
    bash "$repo_root/scripts/deploy/common.sh" \
    testnet-mine.zecwec.com 3443 127.0.0.1 "$tls_test_cert"
for rejected_tls_gate in wrong-host expiring mismatched-key untrusted-chain; do
    host_status=0
    expiry_status=0
    private_public_key=public-key
    verify_status=0
    case "$rejected_tls_gate" in
        wrong-host) host_status=1 ;;
        expiring) expiry_status=1 ;;
        mismatched-key) private_public_key=different-key ;;
        untrusted-chain) verify_status=1 ;;
    esac
    if PATH="$tls_fake_bin:$PATH" TLS_TEST_LOG="$tls_test_log" \
        TLS_TEST_HOST_STATUS=$host_status \
        TLS_TEST_EXPIRY_STATUS=$expiry_status \
        TLS_TEST_PRIVATE_PUBLIC_KEY=$private_public_key \
        TLS_TEST_VERIFY_STATUS=$verify_status \
        bash -c 'source "$1"; require_public_tls_certificate "$2" "$3" "$4"' \
        bash "$repo_root/scripts/deploy/common.sh" \
        "$tls_test_cert" "$tls_test_key" testnet-mine.zecwec.com \
        >/dev/null 2>&1; then
        printf 'deployment-package-test: mining TLS gate accepted %s\n' \
            "$rejected_tls_gate" >&2
        exit 1
    fi
done
for rejected_listener in failed expiring mismatched-certificate; do
    listener_status=0
    expiry_status=0
    live_mismatch=0
    case "$rejected_listener" in
        failed) listener_status=1 ;;
        expiring) expiry_status=1 ;;
        mismatched-certificate) live_mismatch=1 ;;
    esac
    if PATH="$tls_fake_bin:$PATH" TLS_TEST_LOG="$tls_test_log" \
        TLS_TEST_LISTENER_STATUS=$listener_status \
        TLS_TEST_EXPIRY_STATUS=$expiry_status \
        TLS_TEST_LIVE_MISMATCH=$live_mismatch \
        bash -c 'source "$1"; require_public_tls_listener "$2" "$3" "$4" "$5"' \
        bash "$repo_root/scripts/deploy/common.sh" \
        testnet-mine.zecwec.com 3443 127.0.0.1 "$tls_test_cert" \
        >/dev/null 2>&1; then
        printf 'deployment-package-test: mining TLS gate accepted %s live endpoint\n' \
            "$rejected_listener" >&2
        exit 1
    fi
done
grep -Fq 'x509 -in' "$tls_test_log"
grep -Fq -- '-checkhost testnet-mine.zecwec.com' "$tls_test_log"
grep -Fq -- '-checkend 604800' "$tls_test_log"
grep -Fq -- '-verify_hostname testnet-mine.zecwec.com -CApath /etc/ssl/certs' \
    "$tls_test_log"
grep -Fq -- 's_client -connect 127.0.0.1:3443 -servername testnet-mine.zecwec.com -showcerts' \
    "$tls_test_log"

PYTHONDONTWRITEBYTECODE=1 python3 - \
    "$repo_root/scripts/deploy/enable-nginx-edge.sh" \
    "$repo_root/scripts/deploy/health-check.sh" <<'PY'
import pathlib
import sys

edge, health = (pathlib.Path(path).read_text(encoding="utf-8") for path in sys.argv[1:])
certificate_gate = edge.index("require_public_tls_certificate")
stream_enable = edge.index('ln -s -- "$stream_source" "$stream_link"')
nginx_reload = edge.index("if ! systemctl reload nginx.service", stream_enable)
listener_gate = edge.index("if ! require_public_tls_listener")
assert certificate_gate < stream_enable < nginx_reload < listener_gate
assert 'rm -f -- "$stream_link"' in edge[listener_gate:]
assert "require_public_tls_listener" in health
assert (
    'systemctl is-active --quiet nginx.service || die "nginx TLS edge is not active"'
    in health
)
PY
grep -Fq '"payout_execution": "enabled"' \
    "$repo_root/scripts/deploy/health-check.sh"
grep -Fq 'require_hot_testnet_payout_custody' \
    "$repo_root/scripts/deploy/preflight.sh"
grep -Fq 'require_hot_testnet_payout_custody' \
    "$repo_root/scripts/deploy/health-check.sh"
grep -Fq 'zec-wallet-original.rpc.json' "$repo_root/scripts/deploy/common.sh"
grep -Fq 'zec-wallet-recovered.rpc.json' "$repo_root/scripts/deploy/common.sh"
grep -Fq 'zec-wallet-recovery.attestation.json' "$repo_root/scripts/deploy/common.sh"
# shellcheck disable=SC2016
grep -Fq 'python3 "$zec_recovery_verifier" verify' \
    "$repo_root/scripts/deploy/common.sh"
# shellcheck disable=SC2016
grep -Fq 'native_validator=$release_root/wcash-poold' \
    "$repo_root/scripts/deploy/common.sh"
grep -Fq 'root:root:400:1)' \
    "$repo_root/scripts/deploy/provision-host.sh"
grep -Fq 'wcash-payout:wcash-payout:600:1 | root:wcash-payout:440:1)' \
    "$repo_root/scripts/deploy/initialize-wcash-wallet.sh"
grep -Fq 'wcash-payout:wcash-payout:600:1 | root:wcash-payout:440:1)' \
    "$repo_root/scripts/deploy/seal-wcash-custody.sh"
# shellcheck disable=SC2016
grep -Fq 'chown root:wcash-payout -- "$authority"' \
    "$repo_root/scripts/deploy/seal-wcash-custody.sh"
# shellcheck disable=SC2016
grep -Fq 'chmod 0440 -- "$authority"' \
    "$repo_root/scripts/deploy/seal-wcash-custody.sh"
grep -Fq 'root:wcash-payout:440:1' \
    "$repo_root/scripts/deploy/common.sh"
grep -Fq 'wcash-payout:wcash-payout:700' \
    "$repo_root/scripts/deploy/common.sh"
grep -Fq 'for isolated_identity in wcash-pool wcash-pool-projector wcash-pool-backend' \
    "$repo_root/scripts/deploy/common.sh"
# shellcheck disable=SC2016
grep -Fq 'require_untraversable_by_user "$authority_parent" "$isolated_identity"' \
    "$repo_root/scripts/deploy/common.sh"
grep -Fq -- '--ack-independent-offline-backup-recovery' \
    "$repo_root/scripts/deploy/seal-wcash-custody.sh"
grep -Fq 'stop_custody_units_for_sealing' \
    "$repo_root/scripts/deploy/seal-wcash-custody.sh"
grep -Fq 'require_no_processes_for_user wcash-pool-projector "accounting projector identity"' \
    "$repo_root/scripts/deploy/seal-wcash-custody.sh"
grep -Fq 'runuser --user' \
    "$repo_root/scripts/deploy/common.sh"
grep -Fq 'usermod --gid wcash-pool --groups wcash-pool-socket wcash-pool' \
    "$repo_root/scripts/deploy/provision-host.sh"
grep -Fq "usermod --gid zecwec-zallet --groups '' zecwec-zallet" \
    "$repo_root/scripts/deploy/provision-host.sh"
grep -Fq 'require_distinct_service_identities' \
    "$repo_root/scripts/deploy/provision-host.sh"
grep -Fq 'REVOKE ALL PRIVILEGES ON TABLES FROM %I' \
    "$repo_root/scripts/deploy/provision-postgres.sh"
grep -Fq 'REVOKE ALL PRIVILEGES ON SEQUENCES FROM %I' \
    "$repo_root/scripts/deploy/provision-postgres.sh"
grep -Fq 'REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC' \
    "$repo_root/scripts/deploy/provision-postgres.sh"
grep -Fq "'ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC'" \
    "$repo_root/scripts/deploy/provision-postgres.sh"
grep -Fq 'FROM pg_auth_members membership' \
    "$repo_root/scripts/deploy/provision-postgres.sh"
grep -Fq "format('REVOKE %I FROM %I', granted_role.rolname, member_role.rolname)" \
    "$repo_root/scripts/deploy/provision-postgres.sh"
grep -Fq "readonly ZECWEC_MINIMUM_POSTGRES_VERSION_NUM=160000" \
    "$repo_root/scripts/deploy/common.sh"
grep -Fq -- "--command='SHOW server_version_num'" \
    "$repo_root/scripts/deploy/common.sh"
for postgres_gate_script in provision-postgres.sh preflight.sh; do
    grep -Fq 'require_supported_postgres_server' \
        "$repo_root/scripts/deploy/$postgres_gate_script"
done
provision_version_line=$(grep -n '^require_supported_postgres_server$' \
    "$repo_root/scripts/deploy/provision-postgres.sh")
provision_version_line=${provision_version_line%%:*}
provision_mutation_line=$(grep -n '^install -d -o root -g root -m 0700' \
    "$repo_root/scripts/deploy/provision-postgres.sh")
provision_mutation_line=${provision_mutation_line%%:*}
preflight_version_line=$(grep -n '^require_supported_postgres_server$' \
    "$repo_root/scripts/deploy/preflight.sh")
preflight_version_line=${preflight_version_line%%:*}
preflight_mutation_line=$(grep -n '^systemctl stop zecwec-testnet-pool.target' \
    "$repo_root/scripts/deploy/preflight.sh")
preflight_mutation_line=${preflight_mutation_line%%:*}
if ((provision_version_line >= provision_mutation_line \
    || preflight_version_line >= preflight_mutation_line)); then
    printf 'deployment-package-test: PostgreSQL version gate runs after a deployment mutation\n' >&2
    exit 1
fi
if grep -Fq '@ZALLET_STATE_DIR@/.cookie' \
    "$repo_root/deploy/systemd/zecwec-cookie-refresh.path.in"; then
    printf 'deployment-package-test: deferred cookie path retained Zallet coupling\n' >&2
    exit 1
fi
if grep -Eq 'systemctl (start|restart) zecwec-zallet' \
    "$repo_root/scripts/deploy/preflight.sh"; then
    printf 'deployment-package-test: preflight can start a key-bearing Zallet\n' >&2
    exit 1
fi
PYTHONDONTWRITEBYTECODE=1 python3 - "$repo_root/scripts/deploy/preflight.sh" <<'PY'
import pathlib
import sys

preflight = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
assert "trap stop_preflight_authorities EXIT" in preflight
assert "wcash-pool-backend.service >/dev/null 2>&1 || true" in preflight
snapshot = preflight.index('"$script_dir/refresh-runtime-credentials.sh" snapshot')
projector_stop = preflight.rindex("systemctl stop wcash-pool-projector.service")
projector_inactive = preflight.rindex(
    "require_loaded_unit_fully_inactive wcash-pool-projector.service"
)
backend_stop = preflight.rindex("systemctl stop wcash-pool-backend.service")
backend_inactive = preflight.rindex(
    "require_loaded_unit_fully_inactive wcash-pool-backend.service"
)
assert snapshot < projector_stop < projector_inactive < backend_stop < backend_inactive
assert backend_inactive < preflight.index("trap - EXIT")
PY
grep -Fq 'systemctl start zecwec-zallet-payout.service' \
    "$repo_root/scripts/deploy/refresh-runtime-credentials.sh"
grep -Fq 'systemctl stop wcash-pool-health.timer' \
    "$repo_root/scripts/deploy/refresh-runtime-credentials.sh"
grep -Fq 'wait_payout_ready.py' \
    "$repo_root/scripts/deploy/refresh-runtime-credentials.sh"
grep -Fq 'systemctl start wcash-pool-health.timer' \
    "$repo_root/scripts/deploy/refresh-runtime-credentials.sh"
grep -Fq 'trap refresh_failed ERR' \
    "$repo_root/scripts/deploy/refresh-runtime-credentials.sh"
grep -Fq 'stop_testnet_runtime_after_failure' \
    "$repo_root/scripts/deploy/refresh-runtime-credentials.sh"
grep -Fq 'wait_payout_ready.py' "$repo_root/scripts/deploy/start-testnet-pool.sh"
# shellcheck disable=SC2016
grep -Fq '"http://$portal/readyz" 4200' \
    "$repo_root/scripts/deploy/start-testnet-pool.sh"
grep -Fq 'systemctl enable zecwec-testnet-pool-start.service' \
    "$repo_root/scripts/deploy/start-testnet-pool.sh"
grep -Fq 'systemctl start wcash-pool-health.timer' \
    "$repo_root/scripts/deploy/start-testnet-pool.sh"
PYTHONDONTWRITEBYTECODE=1 python3 - \
    "$repo_root/scripts/deploy/start-testnet-pool.sh" \
    "$repo_root/scripts/deploy/common.sh" \
    "$repo_root/scripts/deploy/restrict-mining-firewall.sh" <<'PY'
import pathlib
import sys

start, common, firewall = (
    pathlib.Path(path).read_text(encoding="utf-8") for path in sys.argv[1:]
)
close = start.index('restrict-mining-firewall.sh" close')
preflight = start.index('preflight.sh"')
runtime = start.index("systemctl start zecwec-testnet-pool.target")
ready = start.index('wait_payout_ready.py')
apply = start.index('restrict-mining-firewall.sh" apply')
edge = start.index('enable-nginx-edge.sh" reconcile')
health = start.index('health-check.sh" --settings')
assert close < preflight < runtime < ready < apply < edge < health
assert 'restrict-mining-firewall.sh" close' in common
assert "mode == apply || $mode == close" in firewall
assert "a mining allow rule remains after closing port" in firewall
closed_guard = firewall.index("install_mining_guard 4 closed")
ufw_mutation = firewall.index('ufw --force delete "$number"')
open_guard = firewall.index("install_mining_guard 4 open")
assert closed_guard < ufw_mutation < open_guard
assert firewall.count("install_mining_guard 4 closed") == 2
assert firewall.count("install_mining_guard 6 closed") == 2
assert firewall.count("install_mining_guard 4 open") == 1
assert firewall.count("install_mining_guard 6 open") == 1
assert '"$firewall" --wait 5 -t filter -I INPUT 1 -j "$staging"' in firewall
assert 'readonly guard_chain=ZECWEC-MINING-GUARD' in firewall
PY
grep -Fq 'trap health_check_exit EXIT' \
    "$repo_root/scripts/deploy/health-check.sh"
grep -Fq 'stop_testnet_runtime_after_failure' \
    "$repo_root/scripts/deploy/health-check.sh"
grep -Fq 'systemctl start zecwec-testnet-pool.target' \
    "$repo_root/scripts/deploy/rollback-release.sh"
grep -Fq 'zecwec-testnet-pool-start.service' \
    "$repo_root/scripts/deploy/rollback-release.sh"
grep -Fq 'zecwec-cookie-refresh.service' \
    "$repo_root/scripts/deploy/rollback-release.sh"
# shellcheck disable=SC2016
grep -Fq 'stop_loaded_unit_strict "$unit"' \
    "$repo_root/scripts/deploy/rollback-release.sh"
grep -Fq 'wait_payout_ready.py' "$repo_root/scripts/deploy/rollback-release.sh"
# shellcheck disable=SC2016
grep -Fq '"http://$portal/readyz" 4200' \
    "$repo_root/scripts/deploy/rollback-release.sh"
grep -Fq -- '--ack-forward-schema-compatible' \
    "$repo_root/scripts/deploy/activate-release.sh"
# shellcheck disable=SC2016
grep -Fq 'ZECWEC_RELEASE_TRANSITION=activation exec "$script_dir/rollback-release.sh"' \
    "$repo_root/scripts/deploy/activate-release.sh"
# shellcheck disable=SC2016
grep -Fq 'transition=${ZECWEC_RELEASE_TRANSITION:-rollback}' \
    "$repo_root/scripts/deploy/rollback-release.sh"
grep -Fq 'activated verified release' \
    "$repo_root/scripts/deploy/rollback-release.sh"
PYTHONDONTWRITEBYTECODE=1 python3 - \
    "$repo_root/scripts/deploy/activate-release.sh" \
    "$repo_root/scripts/deploy/rollback-release.sh" \
    "$repo_root/scripts/deploy/install-release.sh" \
    "$repo_root/scripts/deploy/verify-release.sh" \
    "$repo_root/scripts/deploy/health-check.sh" <<'PY'
import pathlib
import sys

activation, rollback, installer, verifier, health = (
    pathlib.Path(path).read_text(encoding="utf-8") for path in sys.argv[1:]
)
assert 'exec "$script_dir/rollback-release.sh"' in activation
assert "systemctl " not in activation
assert activation.index("[[ $# -eq 5") < activation.index(
    'exec "$script_dir/rollback-release.sh"'
)
barrier = '$(cat -- "$target_schema") == 2'
assert barrier in rollback
assert rollback.index(barrier) < rollback.index("stop_loaded_unit_strict")
assert 'ZECWEC_RELEASE_PATH=$target "$script_dir/verify-release.sh"' in rollback
assert '"$target/deployment/scripts/deploy/verify-release.sh"' not in rollback
tls_gate = rollback.index("require_public_tls_certificate")
firewall_close = rollback.index('restrict-mining-firewall.sh" close')
runtime_stop = rollback.index("stop_loaded_unit_strict")
assert tls_gate < firewall_close < runtime_stop
assert "printf '2\\n'" in installer
assert '$(cat -- "$package/DEPLOYMENT-SCHEMA") == 2' in verifier
assert 'ZECWEC_DEPLOYMENT_SCHEMA) == 2' in health
assert health.index("trap health_check_exit EXIT") < health.index("require_command curl")
assert health.index("stop_testnet_runtime_after_failure") < health.rindex("trap - EXIT")
PY
for release_command in activate-release.sh rollback-release.sh; do
    grep -Fq "$release_command" "$repo_root/docs/zecwec-testnet-deployment.md" || {
        printf 'deployment-package-test: runbook omits %s\n' "$release_command" >&2
        exit 1
    }
done
# shellcheck disable=SC2016
for bootstrap_contract in \
    'First security-epoch-2 bootstrap' \
    'ZECWEC_RELEASE_PATH="$ZECWEC_BOOTSTRAP_RELEASE"' \
    'never substitute' \
    'Creating `backend-authority-protocol-v2.json` alone is not' \
    'activate the pinned release' \
    'at least seven days remaining'; do
    grep -Fq "$bootstrap_contract" \
        "$repo_root/docs/zecwec-testnet-deployment.md" || {
        printf 'deployment-package-test: runbook omits launch contract: %s\n' \
            "$bootstrap_contract" >&2
        exit 1
    }
done
for documented_step in \
    import-zallet-mnemonic.py \
    zecwec-zallet-recovery.service \
    seal-zec-initial-zero.sh \
    finalize-zec-offline-custody.sh \
    ack-testnet-off-host-backup-and-recovery; do
    grep -Fq "$documented_step" \
        "$repo_root/docs/zecwec-testnet-deployment.md" || {
        printf 'deployment-package-test: runbook omits ceremony step %s\n' \
            "$documented_step" >&2
        exit 1
    }
done
grep -Fq 'irreversible removal' "$repo_root/deploy/README.md" || {
    printf 'deployment-package-test: runbook omits irreversible cleanup warning\n' >&2
    exit 1
}

custody_systemctl_test="$temporary/custody-systemctl-test"
mkdir -p "$custody_systemctl_test/bin"
cat >"$custody_systemctl_test/bin/systemctl" <<'SH'
#!/usr/bin/env bash
set -eu

case $1 in
    show)
        property=${2#--property=}
        unit=$4
        case "$SYSTEMCTL_SCENARIO:$unit:$property" in
            *:zecwec-testnet-pool-start.service:LoadState) printf 'not-found\n' ;;
            *:wcash-pool-health.timer:LoadState) printf 'not-found\n' ;;
            *:zecwec-cookie-refresh.path:LoadState) printf 'not-found\n' ;;
            *:zecwec-cookie-refresh.service:LoadState) printf 'not-found\n' ;;
            *:zecwec-testnet-pool.target:LoadState) printf 'not-found\n' ;;
            *:wcash-payout-worker.service:LoadState) printf 'not-found\n' ;;
            *:wcash-pool-projector.service:LoadState) printf 'not-found\n' ;;
            expected:wcash-pool.service:LoadState) printf 'not-found\n' ;;
            expected:wcash-pool-wallet-init.service:LoadState) printf 'loaded\n' ;;
            missing-wallet:wcash-pool.service:LoadState) printf 'not-found\n' ;;
            missing-wallet:wcash-pool-wallet-init.service:LoadState) printf 'not-found\n' ;;
            masked-pool:wcash-pool.service:LoadState) printf 'masked\n' ;;
            masked-pool:wcash-pool-wallet-init.service:LoadState) printf 'loaded\n' ;;
            stop-failure:wcash-pool.service:LoadState) printf 'not-found\n' ;;
            stop-failure:wcash-pool-wallet-init.service:LoadState) printf 'loaded\n' ;;
            nonzero-pid:wcash-pool.service:LoadState) printf 'not-found\n' ;;
            nonzero-pid:wcash-pool-wallet-init.service:LoadState) printf 'loaded\n' ;;
            *:zecwec-testnet-pool.target:ActiveState \
                | *:wcash-pool.service:ActiveState \
                | *:wcash-pool-projector.service:ActiveState \
                | *:wcash-payout-worker.service:ActiveState \
                | *:wcash-pool-wallet-init.service:ActiveState)
                printf 'inactive\n'
                ;;
            *:zecwec-testnet-pool.target:SubState \
                | *:wcash-pool.service:SubState \
                | *:wcash-pool-projector.service:SubState \
                | *:wcash-payout-worker.service:SubState \
                | *:wcash-pool-wallet-init.service:SubState)
                printf 'dead\n'
                ;;
            nonzero-pid:wcash-pool-wallet-init.service:MainPID) printf '17\n' ;;
            *:zecwec-testnet-pool.target:MainPID \
                | *:wcash-pool.service:MainPID \
                | *:wcash-pool-projector.service:MainPID \
                | *:wcash-payout-worker.service:MainPID \
                | *:wcash-pool-wallet-init.service:MainPID)
                printf '0\n'
                ;;
            *:zecwec-testnet-pool.target:ControlPID \
                | *:wcash-pool.service:ControlPID \
                | *:wcash-pool-projector.service:ControlPID \
                | *:wcash-payout-worker.service:ControlPID \
                | *:wcash-pool-wallet-init.service:ControlPID)
                printf '0\n'
                ;;
            *) exit 2 ;;
        esac
        ;;
    stop)
        [[ $SYSTEMCTL_SCENARIO != stop-failure ]] || exit 1
        printf '%s\n' "$2" >>"$SYSTEMCTL_STOP_LOG"
        ;;
    *) exit 2 ;;
esac
SH
chmod 0755 "$custody_systemctl_test/bin/systemctl"

run_custody_systemctl_scenario() {
    local scenario=$1
    local expected=$2
    local stop_log="$custody_systemctl_test/$scenario.stops"
    : >"$stop_log"
    if PATH="$custody_systemctl_test/bin:$PATH" \
        SYSTEMCTL_SCENARIO=$scenario \
        SYSTEMCTL_STOP_LOG=$stop_log \
        bash -c \
            'source "$1"; source "$2"; stop_custody_units_for_sealing' \
            bash \
            "$repo_root/scripts/deploy/common.sh" \
            "$repo_root/scripts/deploy/custody-unit-state.sh" \
            >/dev/null 2>&1; then
        [[ $expected == pass ]] || {
            printf 'deployment-package-test: custody systemd scenario %s passed unexpectedly\n' \
                "$scenario" >&2
            exit 1
        }
    else
        [[ $expected == fail ]] || {
            printf 'deployment-package-test: custody systemd scenario %s failed unexpectedly\n' \
                "$scenario" >&2
            exit 1
        }
    fi
}

run_custody_systemctl_scenario expected pass
[[ $(cat "$custody_systemctl_test/expected.stops") == wcash-pool-wallet-init.service ]] \
    || {
        printf 'deployment-package-test: custody seal did not stop exactly the loaded wallet unit\n' >&2
        exit 1
    }
for scenario in missing-wallet masked-pool stop-failure nonzero-pid; do
    run_custody_systemctl_scenario "$scenario" fail
done

zec_seal_systemctl_test="$temporary/zec-seal-systemctl-test"
mkdir -p "$zec_seal_systemctl_test/bin"
cat >"$zec_seal_systemctl_test/bin/systemctl" <<'SH'
#!/usr/bin/env bash
set -eu

case $1 in
    stop)
        printf '%s\n' "$2" >>"$SYSTEMCTL_STOP_LOG"
        ;;
    show)
        property=${2#--property=}
        unit=$4
        case "$SYSTEMCTL_SCENARIO:$unit:$property" in
            active-backend:wcash-pool-backend.service:MainPID) printf '17\n' ;;
            *:*:LoadState) printf 'loaded\n' ;;
            *:*:ActiveState) printf 'inactive\n' ;;
            *:*:SubState) printf 'dead\n' ;;
            *:*:MainPID | *:*:ControlPID) printf '0\n' ;;
            *) exit 2 ;;
        esac
        ;;
    *) exit 2 ;;
esac
SH
chmod 0755 "$zec_seal_systemctl_test/bin/systemctl"
cat >"$zec_seal_systemctl_test/bin/id" <<'SH'
#!/usr/bin/env bash
set -eu
if [[ ${1:-} == -u && ${2:-} == wcash-pool-backend ]]; then
    printf '12345\n'
else
    exec /usr/bin/id "$@"
fi
SH
chmod 0755 "$zec_seal_systemctl_test/bin/id"

run_zec_seal_systemctl_scenario() {
    local scenario=$1
    local expected=$2
    local stop_log="$zec_seal_systemctl_test/$scenario.stops"
    : >"$stop_log"
    if PATH="$zec_seal_systemctl_test/bin:$temporary/fake-bin:$PATH" \
        SYSTEMCTL_SCENARIO=$scenario \
        SYSTEMCTL_STOP_LOG=$stop_log \
        PGREP_TEST_STATUS=1 \
        bash -c 'source "$1"; stop_backend_units_for_zec_sealing' \
        bash "$repo_root/scripts/deploy/common.sh" >/dev/null 2>&1; then
        [[ $expected == pass ]] || {
            printf 'deployment-package-test: ZEC seal systemd scenario %s passed unexpectedly\n' \
                "$scenario" >&2
            exit 1
        }
    else
        [[ $expected == fail ]] || {
            printf 'deployment-package-test: ZEC seal systemd scenario %s failed unexpectedly\n' \
                "$scenario" >&2
            exit 1
        }
    fi
}

run_zec_seal_systemctl_scenario expected pass
zec_stopped_units=$(wc -l <"$zec_seal_systemctl_test/expected.stops")
((zec_stopped_units == 14)) || {
    printf 'deployment-package-test: ZEC seal stopped %s backend-capable units, expected 14\n' \
        "$zec_stopped_units" >&2
    exit 1
}
run_zec_seal_systemctl_scenario active-backend fail
if PATH="$zec_seal_systemctl_test/bin:$temporary/fake-bin:$PATH" \
    SYSTEMCTL_SCENARIO=expected \
    SYSTEMCTL_STOP_LOG="$zec_seal_systemctl_test/rogue.stops" \
    PGREP_TEST_STATUS=0 \
    bash -c 'source "$1"; stop_backend_units_for_zec_sealing' \
    bash "$repo_root/scripts/deploy/common.sh" >/dev/null 2>&1; then
    printf 'deployment-package-test: ZEC seal accepted a rogue backend-UID process\n' >&2
    exit 1
fi

unit_state_test="$temporary/unit-state-test"
mkdir -p "$unit_state_test/bin"
cat >"$unit_state_test/bin/systemctl" <<'SH'
#!/usr/bin/env bash
set -eu
[[ $1 == show ]] || exit 2
[[ ${UNIT_STATE_SCENARIO:-} != error ]] || exit 2
property=${2#--property=}
case "$UNIT_STATE_SCENARIO:$property" in
    missing:LoadState) printf 'not-found\n' ;;
    masked:LoadState) printf 'masked\n' ;;
    *:LoadState) printf 'loaded\n' ;;
    activating:ActiveState) printf 'activating\n' ;;
    *:ActiveState) printf 'inactive\n' ;;
    *:SubState) printf 'dead\n' ;;
    nonzero-pid:MainPID) printf '17\n' ;;
    *:MainPID | *:ControlPID) printf '0\n' ;;
    *) exit 2 ;;
esac
SH
chmod 0755 "$unit_state_test/bin/systemctl"
run_unit_state_scenario() {
    local scenario=$1
    local expected=$2
    if PATH="$unit_state_test/bin:$PATH" UNIT_STATE_SCENARIO=$scenario \
        bash -c 'source "$1"; require_loaded_unit_fully_inactive "$2"' \
        bash "$repo_root/scripts/deploy/common.sh" zecwec-zallet.service \
        >/dev/null 2>&1; then
        [[ $expected == pass ]] || {
            printf 'deployment-package-test: unit state scenario %s passed unexpectedly\n' \
                "$scenario" >&2
            exit 1
        }
    else
        [[ $expected == fail ]] || {
            printf 'deployment-package-test: unit state scenario %s failed unexpectedly\n' \
                "$scenario" >&2
            exit 1
        }
    fi
}
run_unit_state_scenario expected pass
for scenario in missing masked error activating nonzero-pid; do
    run_unit_state_scenario "$scenario" fail
done

dropin_test="$temporary/dropin-test"
mkdir -p "$dropin_test/bin"
cat >"$dropin_test/bin/systemctl" <<'SH'
#!/usr/bin/env bash
set -eu
[[ $1 == show && $2 == --property=DropInPaths && $3 == --value ]] || exit 2
[[ ${DROPIN_TEST_SCENARIO:-} != error ]] || exit 2
if [[ ${DROPIN_TEST_SCENARIO:-} == present ]]; then
    printf '/etc/systemd/system/test.service.d/override.conf\n'
fi
SH
chmod 0555 "$dropin_test/bin/systemctl"
PATH="$dropin_test/bin:$PATH" DROPIN_TEST_SCENARIO=empty \
    bash -c 'source "$1"; require_unit_without_dropins test.service' \
    bash "$repo_root/scripts/deploy/common.sh"
for rejected_dropin_scenario in present error; do
    if PATH="$dropin_test/bin:$PATH" DROPIN_TEST_SCENARIO=$rejected_dropin_scenario \
        bash -c 'source "$1"; require_unit_without_dropins test.service' \
        bash "$repo_root/scripts/deploy/common.sh" >/dev/null 2>&1; then
        printf 'deployment-package-test: unmanaged drop-in scenario passed: %s\n' \
            "$rejected_dropin_scenario" >&2
        exit 1
    fi
done
# shellcheck disable=SC2016
grep -Fq 'require_unit_without_dropins "$(basename -- "$unit")"' \
    "$repo_root/scripts/deploy/render-deployment.sh"
grep -Fq 'DropInPaths' "$repo_root/scripts/deploy/disable-legacy-pool.sh"

mkdir -p "$temporary/config-check-credentials"
chmod 0700 "$temporary/config-check-credentials"
printf 'postgresql://pool@/zecwec\n' >"$temporary/config-check-credentials/database-url"
printf '%032d' 0 | tr 0 a >"$temporary/config-check-credentials/portal-pepper"
printf '%032d' 0 | tr 0 b >"$temporary/config-check-credentials/portal-totp"
chmod 0600 "$temporary/config-check-credentials"/*
python3 - \
    "$temporary/output/pool.runtime.toml" \
    "$temporary/config-check.toml" \
    "$temporary/config-check-credentials" <<'PY'
import pathlib
import sys

source, output, credentials = map(pathlib.Path, sys.argv[1:])
text = source.read_text(encoding="utf-8")
replacements = {
    "/run/credentials/wcash-pool.service/database-url": str(credentials / "database-url"),
    "/run/credentials/wcash-pool.service/portal-token-pepper": str(credentials / "portal-pepper"),
    "/run/credentials/wcash-pool.service/portal-totp-key": str(credentials / "portal-totp"),
}
for old, new in replacements.items():
    if text.count(old) != 1:
        raise SystemExit(f"rendered config did not contain one exact credential path: {old}")
    text = text.replace(old, new)
output.write_text(text, encoding="utf-8")
output.chmod(0o600)
PY
"$repo_root/target/debug/wcash-poold" config-check \
    --config "$temporary/config-check.toml" \
    | grep -Fqx '{"valid":true,"network":"testnet"}' \
    || {
        printf 'deployment-package-test: real Rust config-check rejected rendered policy\n' >&2
        exit 1
    }

python3 - "$temporary/deployment.env" "$temporary/discovery.env" <<'PY'
import pathlib
import sys

source, output = map(pathlib.Path, sys.argv[1:])
text = source.read_text(encoding="utf-8")
keys = {
    "WCASH_SIGNER_ACCOUNT",
    "ZCASH_SIGNER_ACCOUNT",
    "WCASH_PAYOUT_COMMITMENT_WIRE",
    "ZCASH_PAYOUT_COMMITMENT_WIRE",
    "ZCASH_SIGNER_ACCOUNT_INDEX",
}
lines = []
for line in text.splitlines():
    key = line.split("=", 1)[0]
    if key in keys:
        line = f"{key}=BOOTSTRAP_DISCOVERY_REQUIRED"
    lines.append(line)
output.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
python3 "$repo_root/scripts/deploy/render_deployment.py" wallet-bootstrap \
    --settings "$temporary/discovery.env" \
    --source-root "$repo_root" \
    --release-root "$temporary/release" \
    --output "$temporary/wallet-bootstrap-output" \
    --pool-uid 12345 \
    --payout-uid 12346
[[ ! -e $temporary/wallet-bootstrap-output/backend.env \
    && ! -e $temporary/wallet-bootstrap-output/zec-authority.testnet.toml \
    && ! -e $temporary/wallet-bootstrap-output/pool.runtime.toml \
    && ! -e $temporary/wallet-bootstrap-output/systemd/wcash-pool.service \
    && ! -e $temporary/wallet-bootstrap-output/systemd/wcash-pool-zec-authority-bootstrap.service ]] \
    || {
        printf 'deployment-package-test: wallet discovery rendered runtime authority\n' >&2
        exit 1
    }
grep -Fq 'WCASH_EXPECTED_SIGNER_ACCOUNT=BOOTSTRAP_DISCOVERY_REQUIRED' \
    "$temporary/wallet-bootstrap-output/wcash-wallet-bootstrap.env"

wallet_protocol_fixture="$temporary/wallet-protocol-v2"
mkdir -p "$wallet_protocol_fixture"
wallet_account=33333333-3333-4333-8333-333333333333
wallet_genesis=0271b5b0a10b2838f43cccdec9ca2f72aa72a7c103830082bac8f82f47f0593a
wallet_commitment=4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60
python3 - \
    "$wallet_protocol_fixture" \
    "$wallet_account" \
    "$wallet_genesis" \
    "$wallet_commitment" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
account, genesis, commitment = sys.argv[2:]
root.joinpath("init.json").write_text(
    json.dumps(
        {
            "account_id": account,
            "birthday_height": 1,
            "address": "wutest1realistic-ironwood-collector-fixture",
            "transparent_coinbase_address": "wttest1realistic-coinbase-fixture",
            "created": True,
        }
    )
    + "\n",
    encoding="utf-8",
)
root.joinpath("identity-v2.json").write_text(
    json.dumps(
        {
            "protocol_version": 2,
            "network": "testnet",
            "genesis_hash": genesis,
            "branch_id": "b3cfd27e",
            "account_id": account,
            "collector_payout_commitment": commitment,
            "fund_source": "ironwood",
            "synchronized": True,
        }
    )
    + "\n",
    encoding="utf-8",
)
value_fields = {
    "ironwood_total_zat",
    "ironwood_spendable_zat",
    "ironwood_locked_zat",
    "ironwood_pending_change_zat",
    "ironwood_pending_spendability_zat",
    "sapling_total_zat",
    "orchard_total_zat",
    "transparent_total_zat",
    "transparent_coinbase_total_zat",
    "transparent_coinbase_spendable_zat",
    "transparent_coinbase_pending_zat",
    "transparent_regular_total_zat",
}
account_balance = {field: 0 for field in value_fields}
account_balance["account_id"] = account
root.joinpath("balance.json").write_text(
    json.dumps(
        {
            "chain_tip_height": 48,
            "fully_scanned_height": 48,
            "synchronized": True,
            "accounts": [account_balance],
        }
    )
    + "\n",
    encoding="utf-8",
)

identity_bool = json.loads(root.joinpath("identity-v2.json").read_text(encoding="utf-8"))
identity_bool["protocol_version"] = True
root.joinpath("identity-bool-protocol.json").write_text(
    json.dumps(identity_bool) + "\n", encoding="utf-8"
)

init_bool = json.loads(root.joinpath("init.json").read_text(encoding="utf-8"))
init_bool["birthday_height"] = True
root.joinpath("init-bool-birthday.json").write_text(
    json.dumps(init_bool) + "\n", encoding="utf-8"
)

balance_bool_tip = json.loads(root.joinpath("balance.json").read_text(encoding="utf-8"))
balance_bool_tip["chain_tip_height"] = True
root.joinpath("balance-bool-tip.json").write_text(
    json.dumps(balance_bool_tip) + "\n", encoding="utf-8"
)

balance_bool_scan = json.loads(root.joinpath("balance.json").read_text(encoding="utf-8"))
balance_bool_scan["fully_scanned_height"] = True
root.joinpath("balance-bool-scan.json").write_text(
    json.dumps(balance_bool_scan) + "\n", encoding="utf-8"
)

balance_bool_value = json.loads(root.joinpath("balance.json").read_text(encoding="utf-8"))
balance_bool_value["accounts"][0]["ironwood_total_zat"] = False
root.joinpath("balance-bool-value.json").write_text(
    json.dumps(balance_bool_value) + "\n", encoding="utf-8"
)
PY

wallet_validator="$repo_root/scripts/deploy/validate-wcash-wallet-bootstrap.py"
python3 "$wallet_validator" \
    "$wallet_protocol_fixture/init.json" \
    "$wallet_protocol_fixture/balance.json" \
    "$wallet_protocol_fixture/identity-v2.json" \
    "$wallet_protocol_fixture/authority-v2.json" \
    1 \
    "$wallet_genesis" \
    "$wallet_account" \
    "$wallet_commitment" \
    >"$wallet_protocol_fixture/authority-output.json"
cmp -s \
    "$wallet_protocol_fixture/authority-v2.json" \
    "$wallet_protocol_fixture/authority-output.json" \
    || {
        printf 'deployment-package-test: wallet protocol-v2 authority output is unstable\n' >&2
        exit 1
    }

recovery_verifier="$repo_root/scripts/deploy/verify-wcash-wallet-recovery.py"
python3 "$recovery_verifier" seal \
    "$wallet_protocol_fixture/authority-v2.json" \
    "$wallet_protocol_fixture/init.json" \
    "$wallet_protocol_fixture/identity-v2.json" \
    "$wallet_protocol_fixture/recovery-attestation.json"
python3 "$recovery_verifier" verify \
    "$wallet_protocol_fixture/authority-v2.json" \
    "$wallet_protocol_fixture/recovery-attestation.json"
python3 - \
    "$wallet_protocol_fixture/init.json" \
    "$wallet_protocol_fixture/identity-v2.json" \
    "$wallet_protocol_fixture/recovery-init-fresh-account.json" \
    "$wallet_protocol_fixture/recovery-identity-fresh-account.json" <<'PY'
import json
import pathlib
import sys

init_source, identity_source, init_output, identity_output = map(
    pathlib.Path, sys.argv[1:]
)
recovered_account = "12345678-1234-4234-8234-123456789abc"
initialized = json.loads(init_source.read_text(encoding="utf-8"))
identity = json.loads(identity_source.read_text(encoding="utf-8"))
initialized["account_id"] = recovered_account
identity["account_id"] = recovered_account
init_output.write_text(json.dumps(initialized) + "\n", encoding="utf-8")
identity_output.write_text(json.dumps(identity) + "\n", encoding="utf-8")
PY
python3 "$recovery_verifier" seal \
    "$wallet_protocol_fixture/authority-v2.json" \
    "$wallet_protocol_fixture/recovery-init-fresh-account.json" \
    "$wallet_protocol_fixture/recovery-identity-fresh-account.json" \
    "$wallet_protocol_fixture/recovery-attestation-fresh-account.json"
cmp -s \
    "$wallet_protocol_fixture/recovery-attestation.json" \
    "$wallet_protocol_fixture/recovery-attestation-fresh-account.json" \
    || {
        printf 'deployment-package-test: database-local recovery account changed the collector attestation\n' >&2
        exit 1
    }
python3 - \
    "$wallet_protocol_fixture/recovery-identity-fresh-account.json" \
    "$wallet_protocol_fixture/recovery-identity-mismatched-account.json" <<'PY'
import json
import pathlib
import sys

source, output = map(pathlib.Path, sys.argv[1:])
value = json.loads(source.read_text(encoding="utf-8"))
value["account_id"] = "87654321-4321-4321-8321-cba987654321"
output.write_text(json.dumps(value) + "\n", encoding="utf-8")
PY
if python3 "$recovery_verifier" seal \
    "$wallet_protocol_fixture/authority-v2.json" \
    "$wallet_protocol_fixture/recovery-init-fresh-account.json" \
    "$wallet_protocol_fixture/recovery-identity-mismatched-account.json" \
    "$wallet_protocol_fixture/rejected-account-mismatch-attestation.json" \
    >/dev/null 2>&1; then
    printf 'deployment-package-test: recovery accepted inconsistent database-local accounts\n' >&2
    exit 1
fi
python3 - \
    "$wallet_protocol_fixture/recovery-init-fresh-account.json" \
    "$wallet_protocol_fixture/recovery-init-zero-account.json" <<'PY'
import json
import pathlib
import sys

source, output = map(pathlib.Path, sys.argv[1:])
value = json.loads(source.read_text(encoding="utf-8"))
value["account_id"] = "00000000-0000-0000-0000-000000000000"
output.write_text(json.dumps(value) + "\n", encoding="utf-8")
PY
if python3 "$recovery_verifier" seal \
    "$wallet_protocol_fixture/authority-v2.json" \
    "$wallet_protocol_fixture/recovery-init-zero-account.json" \
    "$wallet_protocol_fixture/recovery-identity-fresh-account.json" \
    "$wallet_protocol_fixture/rejected-zero-account-attestation.json" \
    >/dev/null 2>&1; then
    printf 'deployment-package-test: recovery accepted a zero database-local account\n' >&2
    exit 1
fi
python3 - \
    "$wallet_protocol_fixture/init.json" \
    "$wallet_protocol_fixture/recovery-init-not-fresh.json" <<'PY'
import json
import pathlib
import sys

source, output = map(pathlib.Path, sys.argv[1:])
value = json.loads(source.read_text(encoding="utf-8"))
value["created"] = False
output.write_text(json.dumps(value) + "\n", encoding="utf-8")
PY
if python3 "$recovery_verifier" seal \
    "$wallet_protocol_fixture/authority-v2.json" \
    "$wallet_protocol_fixture/recovery-init-not-fresh.json" \
    "$wallet_protocol_fixture/identity-v2.json" \
    "$wallet_protocol_fixture/rejected-recovery-attestation.json" \
    >/dev/null 2>&1; then
    printf 'deployment-package-test: recovery accepted a reused wallet database\n' >&2
    exit 1
fi
[[ ! -e $wallet_protocol_fixture/rejected-recovery-attestation.json ]] || {
    printf 'deployment-package-test: rejected recovery wrote an attestation\n' >&2
    exit 1
}
python3 - \
    "$wallet_protocol_fixture/identity-v2.json" \
    "$wallet_protocol_fixture/recovery-identity-bool-version.json" <<'PY'
import json
import pathlib
import sys

source, output = map(pathlib.Path, sys.argv[1:])
value = json.loads(source.read_text(encoding="utf-8"))
value["protocol_version"] = True
output.write_text(json.dumps(value) + "\n", encoding="utf-8")
PY
if python3 "$recovery_verifier" seal \
    "$wallet_protocol_fixture/authority-v2.json" \
    "$wallet_protocol_fixture/init.json" \
    "$wallet_protocol_fixture/recovery-identity-bool-version.json" \
    "$wallet_protocol_fixture/rejected-bool-recovery-attestation.json" \
    >/dev/null 2>&1; then
    printf 'deployment-package-test: recovery accepted a boolean protocol version\n' >&2
    exit 1
fi

assert_wallet_protocol_rejected() {
    local label=$1
    local init=$2
    local balance=$3
    local identity=$4
    local rejected_authority="$wallet_protocol_fixture/authority-rejected-$label.json"
    if python3 "$wallet_validator" \
        "$init" \
        "$balance" \
        "$identity" \
        "$rejected_authority" \
        1 \
        "$wallet_genesis" \
        "$wallet_account" \
        "$wallet_commitment" >/dev/null 2>&1; then
        printf 'deployment-package-test: wallet bootstrap accepted malformed %s output\n' \
            "$label" >&2
        exit 1
    fi
    [[ ! -e $rejected_authority ]] || {
        printf 'deployment-package-test: rejected wallet output wrote authority state\n' >&2
        exit 1
    }
}

assert_wallet_protocol_rejected \
    bool-protocol \
    "$wallet_protocol_fixture/init.json" \
    "$wallet_protocol_fixture/balance.json" \
    "$wallet_protocol_fixture/identity-bool-protocol.json"
assert_wallet_protocol_rejected \
    bool-birthday \
    "$wallet_protocol_fixture/init-bool-birthday.json" \
    "$wallet_protocol_fixture/balance.json" \
    "$wallet_protocol_fixture/identity-v2.json"
assert_wallet_protocol_rejected \
    bool-tip \
    "$wallet_protocol_fixture/init.json" \
    "$wallet_protocol_fixture/balance-bool-tip.json" \
    "$wallet_protocol_fixture/identity-v2.json"
assert_wallet_protocol_rejected \
    bool-scan \
    "$wallet_protocol_fixture/init.json" \
    "$wallet_protocol_fixture/balance-bool-scan.json" \
    "$wallet_protocol_fixture/identity-v2.json"
assert_wallet_protocol_rejected \
    bool-balance \
    "$wallet_protocol_fixture/init.json" \
    "$wallet_protocol_fixture/balance-bool-value.json" \
    "$wallet_protocol_fixture/identity-v2.json"

for rejected_version in 1 4294967295; do
    rejected_identity="$wallet_protocol_fixture/identity-v$rejected_version.json"
    python3 - \
        "$wallet_protocol_fixture/identity-v2.json" \
        "$rejected_identity" \
        "$rejected_version" <<'PY'
import json
import pathlib
import sys

source, output = map(pathlib.Path, sys.argv[1:3])
identity = json.loads(source.read_text(encoding="utf-8"))
identity["protocol_version"] = int(sys.argv[3], 10)
output.write_text(json.dumps(identity) + "\n", encoding="utf-8")
PY
    assert_wallet_protocol_rejected \
        "protocol-$rejected_version" \
        "$wallet_protocol_fixture/init.json" \
        "$wallet_protocol_fixture/balance.json" \
        "$rejected_identity"
done

if python3 "$repo_root/scripts/deploy/render_deployment.py" bootstrap \
    --settings "$temporary/discovery.env" \
    --source-root "$repo_root" \
    --release-root "$temporary/release" \
    --output "$temporary/rejected-discovery-bootstrap" \
    --pool-uid 12345 \
    --payout-uid 12346 >/dev/null 2>&1; then
    printf 'deployment-package-test: authority bootstrap accepted discovery sentinels\n' >&2
    exit 1
fi

python3 "$repo_root/scripts/deploy/render_deployment.py" bootstrap \
    --settings "$temporary/deployment.env" \
    --source-root "$repo_root" \
    --release-root "$temporary/release" \
    --output "$temporary/ironwood-output" \
    --pool-uid 12345 \
    --payout-uid 12346
grep -Fq 'LoadCredential=wcash-payout-ivk:' \
    "$temporary/ironwood-output/systemd/wcash-pool-backend.service" \
    || {
        printf 'deployment-package-test: Ironwood render omitted its IVK credential\n' >&2
        exit 1
    }

sed 's/^WCASH_PAYOUT_MODE=ironwood$/WCASH_PAYOUT_MODE=transparent/' \
    "$temporary/deployment.env" >"$temporary/transparent.env"
if python3 "$repo_root/scripts/deploy/render_deployment.py" bootstrap \
    --settings "$temporary/transparent.env" \
    --source-root "$repo_root" \
    --release-root "$temporary/release" \
    --output "$temporary/transparent-output" \
    --pool-uid 12345 \
    --payout-uid 12346 >/dev/null 2>&1; then
    printf 'deployment-package-test: renderer accepted a transparent launch collector\n' >&2
    exit 1
fi

cp "$temporary/deployment.env" "$temporary/bad.env"
python3 - "$temporary/bad.env" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace(
    "WCASH_GENESIS_WIRE=201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201",
    "WCASH_GENESIS_WIRE=" + "99" * 32,
)
path.write_text(text, encoding="utf-8")
PY
if python3 "$repo_root/scripts/deploy/render_deployment.py" bootstrap \
    --settings "$temporary/bad.env" \
    --source-root "$repo_root" \
    --release-root "$temporary/release" \
    --output "$temporary/rejected" \
    --pool-uid 12345 \
    --payout-uid 12346 >/dev/null 2>&1; then
    printf 'deployment-package-test: renderer accepted mismatched genesis byte order\n' >&2
    exit 1
fi

python3 - "$temporary/authority.json" "$temporary/bad-authority.json" <<'PY'
import json
import pathlib
import sys

source, output = map(pathlib.Path, sys.argv[1:])
authority = json.loads(source.read_text(encoding="utf-8"))
authority["share_target_ceiling"] = bytes(range(128, 160)).hex()
output.write_text(json.dumps(authority) + "\n", encoding="utf-8")
PY
if python3 "$repo_root/scripts/deploy/render_deployment.py" finalize \
    --settings "$temporary/deployment.env" \
    --authority "$temporary/bad-authority.json" \
    --source-root "$repo_root" \
    --release-root "$temporary/release" \
    --output "$temporary/rejected-authority" \
    --pool-uid 12345 \
    --payout-uid 12346 >/dev/null 2>&1; then
    printf 'deployment-package-test: renderer accepted a mismatched target authority\n' >&2
    exit 1
fi

ln -s "$temporary/release" "$temporary/release-link"
if python3 "$repo_root/scripts/deploy/render_deployment.py" bootstrap \
    --settings "$temporary/deployment.env" \
    --source-root "$repo_root" \
    --release-root "$temporary/release-link" \
    --output "$temporary/rejected-symlink-release" \
    --pool-uid 12345 \
    --payout-uid 12346 >/dev/null 2>&1; then
    printf 'deployment-package-test: renderer accepted a symlink release root\n' >&2
    exit 1
fi

if rg -n '76\.13\.10\.156|187\.7\.23\.198|/Users/mykyta|BEGIN OPENSSH PRIVATE KEY' \
    "$repo_root/deploy" "$repo_root/scripts/deploy" "$repo_root/docs/zecwec-testnet-deployment.md"; then
    printf 'deployment-package-test: sensitive host-specific material detected\n' >&2
    exit 1
fi

if rg -n '[[:blank:]]+$' \
    "$repo_root/deploy" \
    "$repo_root/scripts/deploy" \
    "$repo_root/scripts/test-deployment-package.sh" \
    "$repo_root/docs/zecwec-testnet-deployment.md"; then
    printf 'deployment-package-test: trailing whitespace detected\n' >&2
    exit 1
fi

git -C "$repo_root" diff --check -- deploy scripts/deploy scripts/test-deployment-package.sh docs/zecwec-testnet-deployment.md
printf 'deployment-package-test: all checks passed\n'
