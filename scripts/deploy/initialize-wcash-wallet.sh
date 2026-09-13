#!/usr/bin/env bash

set -Eeuo pipefail
set +x
umask 077

die() {
    printf 'initialize-wcash-wallet: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 0 ]] || die "this service accepts configuration only from its rendered environment"

required_environment=(
    WCASH_RELEASE_ROOT
    WCASH_WALLET_DATABASE
    WCASH_LIGHTWALLETD_ENDPOINT
    WEC_SEED_FILE
    WCASH_WALLET_BIRTHDAY
    WCASH_WALLET_SYNC_BATCH_SIZE
    WCASH_WALLET_SYNC_TIMEOUT_SECONDS
    WCASH_EXPECTED_GENESIS_DISPLAY
    WCASH_EXPECTED_SIGNER_ACCOUNT
    WCASH_EXPECTED_PAYOUT_COMMITMENT
    WCASH_WALLET_AUTHORITY
    RUNTIME_DIRECTORY
)
for variable in "${required_environment[@]}"; do
    [[ -n ${!variable:-} ]] || die "required service setting is missing: $variable"
done

command -v flock >/dev/null 2>&1 || die "flock is unavailable"
command -v python3 >/dev/null 2>&1 || die "python3 is unavailable"
command -v realpath >/dev/null 2>&1 || die "realpath is unavailable"
command -v systemctl >/dev/null 2>&1 || die "systemctl is unavailable"
command -v timeout >/dev/null 2>&1 || die "timeout is unavailable"

pool_state=$(systemctl show --property=ActiveState --value wcash-pool.service) \
    || die "could not establish public pool service state"
[[ $pool_state != active && $pool_state != reloading ]] \
    || die "public pool must be stopped before wallet initialization"
projector_state=$(systemctl show --property=ActiveState --value wcash-pool-projector.service) \
    || die "could not establish accounting projector service state"
[[ $projector_state != active && $projector_state != reloading ]] \
    || die "accounting projector must be stopped before wallet initialization"
payout_state=$(systemctl show --property=ActiveState --value wcash-payout-worker.service) \
    || die "could not establish payout worker service state"
[[ $payout_state != active && $payout_state != reloading ]] \
    || die "payout worker must be stopped before wallet initialization"

[[ $WCASH_RELEASE_ROOT =~ ^/opt/wcash/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ \
    && -d $WCASH_RELEASE_ROOT && ! -L $WCASH_RELEASE_ROOT \
    && $(realpath -e -- "$WCASH_RELEASE_ROOT") == "$WCASH_RELEASE_ROOT" ]] \
    || die "release root is not one immutable version directory"
[[ $WCASH_WALLET_DATABASE == /var/lib/wcash-payout/wcash-wallet.sqlite ]] \
    || die "wallet database path does not match the reviewed deployment"
[[ $WCASH_WALLET_AUTHORITY == /var/lib/wcash-payout/wcash-wallet-authority.json ]] \
    || die "wallet authority path does not match the reviewed deployment"
[[ $WEC_SEED_FILE == /run/credentials/wcash-pool-wallet-init.service/wcash-seed ]] \
    || die "seed path is not the private systemd credential mount"
[[ $WCASH_LIGHTWALLETD_ENDPOINT =~ ^http://127\.0\.0\.1:[0-9]{1,5}$ ]] \
    || die "compact-block endpoint must be literal IPv4 loopback"
[[ $WCASH_WALLET_BIRTHDAY =~ ^[1-9][0-9]{0,9}$ \
    && $WCASH_WALLET_BIRTHDAY -le 4294967295 ]] \
    || die "wallet birthday is invalid"
[[ $WCASH_WALLET_SYNC_BATCH_SIZE =~ ^([1-9]|1[0-6])$ ]] \
    || die "wallet sync batch size is invalid"
[[ $WCASH_WALLET_SYNC_TIMEOUT_SECONDS =~ ^[1-9][0-9]{1,2}$ \
    && $WCASH_WALLET_SYNC_TIMEOUT_SECONDS -ge 30 \
    && $WCASH_WALLET_SYNC_TIMEOUT_SECONDS -le 900 ]] \
    || die "wallet sync timeout is invalid"
[[ $WCASH_EXPECTED_GENESIS_DISPLAY =~ ^[0-9a-f]{64}$ \
    && $WCASH_EXPECTED_GENESIS_DISPLAY != "$(printf '0%.0s' {1..64})" ]] \
    || die "expected Wcash genesis is invalid"

readonly discovery=BOOTSTRAP_DISCOVERY_REQUIRED
if [[ $WCASH_EXPECTED_SIGNER_ACCOUNT != "$discovery" ]]; then
    [[ $WCASH_EXPECTED_SIGNER_ACCOUNT =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
        || die "expected Wcash signer account is invalid"
fi
if [[ $WCASH_EXPECTED_PAYOUT_COMMITMENT != "$discovery" ]]; then
    [[ $WCASH_EXPECTED_PAYOUT_COMMITMENT =~ ^[0-9a-f]{64}$ \
        && $WCASH_EXPECTED_PAYOUT_COMMITMENT != "$(printf '0%.0s' {1..64})" ]] \
        || die "expected Wcash payout commitment is invalid"
fi

service_uid=$(id -u)
[[ $service_uid != 0 ]] || die "wallet initialization must not run as root"
[[ -f $WEC_SEED_FILE && ! -L $WEC_SEED_FILE ]] || die "protected seed is unavailable"
[[ $(stat -c '%u:%a:%h' -- "$WEC_SEED_FILE") == "$service_uid:600:1" ]] \
    || die "protected seed ownership, mode, or link count is invalid"
seed_size=$(stat -c '%s' -- "$WEC_SEED_FILE")
((seed_size >= 64 && seed_size <= 505)) || die "protected seed size is invalid"

database_parent=$(dirname -- "$WCASH_WALLET_DATABASE")
[[ -d $database_parent && ! -L $database_parent \
    && $(realpath -e -- "$database_parent") == "$database_parent" ]] \
    || die "wallet database parent is unsafe"
if [[ -e $WCASH_WALLET_DATABASE || -L $WCASH_WALLET_DATABASE ]]; then
    [[ -f $WCASH_WALLET_DATABASE && ! -L $WCASH_WALLET_DATABASE ]] \
        || die "existing wallet database is unsafe"
    [[ $(stat -c '%u:%h' -- "$WCASH_WALLET_DATABASE") == "$service_uid:1" ]] \
        || die "existing wallet database ownership or link count is unsafe"
fi
if [[ -e $WCASH_WALLET_AUTHORITY || -L $WCASH_WALLET_AUTHORITY ]]; then
    [[ -f $WCASH_WALLET_AUTHORITY && ! -L $WCASH_WALLET_AUTHORITY ]] \
        || die "existing wallet authority is unsafe"
    case $(stat -c '%U:%G:%a:%h' -- "$WCASH_WALLET_AUTHORITY") in
        wcash-payout:wcash-payout:600:1 | root:wcash-payout:440:1) ;;
        *) die "existing wallet authority ownership, mode, or link count is unsafe" ;;
    esac
fi

lock_file="$RUNTIME_DIRECTORY/wcash-wallet.lock"
exec 9>"$lock_file"
flock -n 9 || die "another wallet initialization or synchronization is active"

binary="$WCASH_RELEASE_ROOT/wcash-wallet"
[[ -x $binary && ! -L $binary && $(stat -c '%u:%a:%h' -- "$binary") == 0:555:1 ]] \
    || die "pinned wallet executable is unsafe"

init_output="$RUNTIME_DIRECTORY/init.json"
sync_output="$RUNTIME_DIRECTORY/sync.json"
balance_output="$RUNTIME_DIRECTORY/balance.json"
identity_output="$RUNTIME_DIRECTORY/identity.json"
trap 'rm -f -- "$init_output" "$sync_output" "$balance_output" "$identity_output"' EXIT

"$binary" \
    --network testnet \
    --db "$WCASH_WALLET_DATABASE" \
    --lightwalletd "$WCASH_LIGHTWALLETD_ENDPOINT" \
    init --birthday "$WCASH_WALLET_BIRTHDAY" \
    <"$WEC_SEED_FILE" >"$init_output"

timeout --signal=TERM --kill-after=30s "${WCASH_WALLET_SYNC_TIMEOUT_SECONDS}s" \
    "$binary" \
    --network testnet \
    --db "$WCASH_WALLET_DATABASE" \
    --lightwalletd "$WCASH_LIGHTWALLETD_ENDPOINT" \
    sync --batch-size "$WCASH_WALLET_SYNC_BATCH_SIZE" \
    >"$sync_output" \
    || die "wallet synchronization failed or exceeded its reviewed time bound"

"$binary" --network testnet --db "$WCASH_WALLET_DATABASE" balance >"$balance_output"
"$binary" --network testnet --db "$WCASH_WALLET_DATABASE" payout-identity >"$identity_output"

validator="$WCASH_RELEASE_ROOT/deployment/scripts/deploy/validate-wcash-wallet-bootstrap.py"
[[ -f $validator && ! -L $validator && $(stat -c '%u:%a:%h' -- "$validator") == 0:555:1 ]] \
    || die "pinned wallet bootstrap validator is unsafe"
python3 "$validator" \
    "$init_output" \
    "$balance_output" \
    "$identity_output" \
    "$WCASH_WALLET_AUTHORITY" \
    "$WCASH_WALLET_BIRTHDAY" \
    "$WCASH_EXPECTED_GENESIS_DISPLAY" \
    "$WCASH_EXPECTED_SIGNER_ACCOUNT" \
    "$WCASH_EXPECTED_PAYOUT_COMMITMENT"
