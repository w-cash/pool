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

[[ $WCASH_RELEASE_ROOT =~ ^/opt/wcash/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ \
    && -d $WCASH_RELEASE_ROOT && ! -L $WCASH_RELEASE_ROOT \
    && $(realpath -e -- "$WCASH_RELEASE_ROOT") == "$WCASH_RELEASE_ROOT" ]] \
    || die "release root is not one immutable version directory"
[[ $WCASH_WALLET_DATABASE == /var/lib/wcash-pool/wcash-wallet.sqlite ]] \
    || die "wallet database path does not match the reviewed deployment"
[[ $WCASH_WALLET_AUTHORITY == /var/lib/wcash-pool/wcash-wallet-authority.json ]] \
    || die "wallet authority path does not match the reviewed deployment"
[[ $WEC_SEED_FILE == /var/lib/wcash-pool-secrets/wcash-seed ]] \
    || die "seed path does not match the reviewed deployment"
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
    [[ -f $WCASH_WALLET_AUTHORITY && ! -L $WCASH_WALLET_AUTHORITY \
        && $(stat -c '%u:%a:%h' -- "$WCASH_WALLET_AUTHORITY") == "$service_uid:600:1" ]] \
        || die "existing wallet authority ownership, mode, or link count is unsafe"
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

python3 - \
    "$init_output" \
    "$balance_output" \
    "$identity_output" \
    "$WCASH_WALLET_AUTHORITY" \
    "$WCASH_WALLET_BIRTHDAY" \
    "$WCASH_EXPECTED_GENESIS_DISPLAY" \
    "$WCASH_EXPECTED_SIGNER_ACCOUNT" \
    "$WCASH_EXPECTED_PAYOUT_COMMITMENT" <<'PY'
import json
import os
import pathlib
import re
import sys
import uuid

(
    init_path,
    balance_path,
    identity_path,
    authority_path,
    expected_birthday,
    expected_genesis,
    expected_account,
    expected_commitment,
) = sys.argv[1:]
discovery = "BOOTSTRAP_DISCOVERY_REQUIRED"


def read_json(path: str, label: str) -> dict:
    try:
        value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"{label} output is invalid: {error}") from None
    if not isinstance(value, dict):
        raise SystemExit(f"{label} output is not an object")
    return value


initialized = read_json(init_path, "wallet initialization")
required_initialized = {
    "account_id",
    "birthday_height",
    "address",
    "transparent_coinbase_address",
    "created",
}
if set(initialized) != required_initialized:
    raise SystemExit("wallet initialization output has an unexpected schema")

identity = read_json(identity_path, "wallet identity")
required_identity = {
    "protocol_version",
    "network",
    "genesis_hash",
    "branch_id",
    "account_id",
    "collector_payout_commitment",
    "fund_source",
    "synchronized",
}
if set(identity) != required_identity:
    raise SystemExit("wallet identity output has an unexpected schema")

try:
    account = uuid.UUID(initialized["account_id"])
except (AttributeError, TypeError, ValueError):
    raise SystemExit("wallet account identifier is invalid") from None
if account.int == 0 or str(account) != initialized["account_id"]:
    raise SystemExit("wallet account identifier is not canonical")
if identity["account_id"] != str(account):
    raise SystemExit("wallet initialization and payout identity accounts differ")
if initialized["birthday_height"] != int(expected_birthday, 10):
    raise SystemExit("wallet birthday differs from the rendered policy")
if not isinstance(initialized["created"], bool):
    raise SystemExit("wallet initialization creation marker is invalid")
for address_key in ("address", "transparent_coinbase_address"):
    address = initialized[address_key]
    if not isinstance(address, str) or not address or len(address) > 512:
        raise SystemExit("wallet initialization returned an invalid address")

commitment = identity["collector_payout_commitment"]
if (
    identity["protocol_version"] != 1
    or identity["network"] != "testnet"
    or identity["genesis_hash"] != expected_genesis
    or not isinstance(identity["branch_id"], str)
    or re.fullmatch(r"[0-9a-f]{8}", identity["branch_id"]) is None
    or identity["fund_source"] != "ironwood"
    or identity["synchronized"] is not True
    or not isinstance(commitment, str)
    or re.fullmatch(r"[0-9a-f]{64}", commitment) is None
    or int(commitment, 16) == 0
):
    raise SystemExit("wallet payout identity differs from the reviewed Testnet policy")
if expected_account != discovery and str(account) != expected_account:
    raise SystemExit("wallet account differs from the reviewed signer account")
if expected_commitment != discovery and commitment != expected_commitment:
    raise SystemExit("wallet commitment differs from the reviewed payout commitment")

balance = read_json(balance_path, "wallet balance")
required_balance = {
    "chain_tip_height",
    "fully_scanned_height",
    "synchronized",
    "accounts",
}
if set(balance) != required_balance:
    raise SystemExit("wallet balance output has an unexpected schema")
if (
    not isinstance(balance["chain_tip_height"], int)
    or balance["chain_tip_height"] < 0
    or balance["fully_scanned_height"] != balance["chain_tip_height"]
    or balance["synchronized"] is not True
    or not isinstance(balance["accounts"], list)
    or len(balance["accounts"]) != 1
):
    raise SystemExit("wallet is not synchronized to one exact account")

account_balance = balance["accounts"][0]
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
if not isinstance(account_balance, dict) or set(account_balance) != value_fields | {"account_id"}:
    raise SystemExit("wallet account balance has an unexpected schema")
if account_balance["account_id"] != str(account):
    raise SystemExit("wallet balance belongs to a different account")
if any(not isinstance(account_balance[field], int) for field in value_fields):
    raise SystemExit("wallet balance contains a non-integer value")
non_ironwood_fields = {
    "sapling_total_zat",
    "orchard_total_zat",
    "transparent_total_zat",
    "transparent_coinbase_total_zat",
    "transparent_coinbase_spendable_zat",
    "transparent_coinbase_pending_zat",
    "transparent_regular_total_zat",
}
if any(account_balance[field] != 0 for field in non_ironwood_fields):
    raise SystemExit("collector contains value outside the direct Ironwood pool")

authority = {
    "schema_version": 1,
    "network": "testnet",
    "genesis_hash": expected_genesis,
    "branch_id": identity["branch_id"],
    "account_id": str(account),
    "collector_payout_commitment": commitment,
    "collector_address": initialized["address"],
    "transparent_coinbase_address": initialized["transparent_coinbase_address"],
    "birthday_height": initialized["birthday_height"],
    "fund_source": "ironwood",
    "synchronized": True,
    "initial_balances_zero": True,
}
target = pathlib.Path(authority_path)
serialized = json.dumps(authority, sort_keys=True, separators=(",", ":")) + "\n"
if target.exists():
    try:
        existing = target.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise SystemExit(f"existing wallet authority cannot be read: {error}") from None
    if existing != serialized:
        raise SystemExit("existing wallet authority differs; manual recovery is required")
else:
    if any(account_balance[field] != 0 for field in value_fields):
        raise SystemExit("new collector is not a fresh, completely empty wallet account")
    temporary = target.with_name(f".{target.name}.new.{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(serialized)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
sys.stdout.write(serialized)
PY
