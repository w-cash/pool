#!/usr/bin/env bash

set -Eeuo pipefail
set +x
umask 077

die() {
    printf 'backend-entrypoint: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 1 ]] || die "usage: backend-entrypoint.sh <init|serve>"
mode=$1
[[ $mode == init || $mode == serve ]] || die "mode must be init or serve"

: "${CREDENTIALS_DIRECTORY:?systemd credential directory is required}"
: "${STATE_DIRECTORY:?systemd state directory is required}"
: "${RUNTIME_DIRECTORY:?systemd runtime directory is required}"
: "${WCASH_RPC_URL:?Wcash RPC URL is required}"
: "${ZCASH_TEMPLATE_RPC_URL:?Zcash template RPC URL is required}"
: "${ZCASH_VALIDATOR_RPC_URL:?Zcash validator RPC URL is required}"
: "${WCASH_POOL_BACKEND_SOCKET:?backend socket is required}"
: "${WCASH_PAYOUT_MODE:?Wcash payout mode is required}"
: "${ZECWEC_RELEASE_PATH:?immutable release path is required}"
: "${WCASH_AUTHORITY_GENESIS_WIRE:?Wcash authority genesis is required}"
: "${ZCASH_AUTHORITY_GENESIS_WIRE:?Zcash authority genesis is required}"
: "${WCASH_AUTHORITY_PAYOUT_COMMITMENT:?Wcash payout commitment is required}"
: "${ZCASH_AUTHORITY_PAYOUT_COMMITMENT:?Zcash payout commitment is required}"
: "${WCASH_AUTHORITY_SIGNER_ACCOUNT:?Wcash signer account is required}"
: "${WCASH_AUTHORITY_SHARE_TARGET_BE:?share-target ceiling is required}"
: "${WCASH_AUTHORITY_CHAIN_ID:?Wcash chain identifier is required}"
: "${WCASH_SHARE_JOURNAL:?share journal path is required}"
: "${WCASH_POOL_BACKEND_IDENTITY:?backend identity path is required}"
: "${WCASH_POOL_BACKEND_JOURNAL:?backend journal path is required}"
[[ $WCASH_PAYOUT_MODE == ironwood ]] \
    || die "the Testnet pool requires direct Ironwood Wcash coinbase payout"
[[ $WCASH_SHARE_JOURNAL == "$STATE_DIRECTORY/share-journal-protocol-v2.jsonl" \
    && $WCASH_POOL_BACKEND_IDENTITY == "$STATE_DIRECTORY/backend-identity-protocol-v2.json" \
    && $WCASH_POOL_BACKEND_JOURNAL == "$STATE_DIRECTORY/backend-journal-protocol-v2.jsonl" ]] \
    || die "backend authority paths do not match the reviewed protocol-v2 namespace"
legacy_share_journal=/var/lib/wcash-pool/share-journal-v2.jsonl
[[ ! -e $legacy_share_journal && ! -L $legacy_share_journal ]] \
    || die "legacy share journal must be reviewed and archived before protocol-v2 initialization"

wallet_authority="$CREDENTIALS_DIRECTORY/wcash-wallet-authority"
[[ -f $wallet_authority && ! -L $wallet_authority ]] \
    || die "Wcash wallet bootstrap authority is unavailable"
wallet_authority_size=$(stat -c '%s' -- "$wallet_authority")
((wallet_authority_size > 0 && wallet_authority_size <= 4096)) \
    || die "Wcash wallet bootstrap authority has an invalid size"
python3 - "$wallet_authority" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import sys
import uuid

path = pathlib.Path(sys.argv[1])
try:
    authority = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"Wcash wallet bootstrap authority is invalid: {error}") from None
required = {
    "schema_version",
    "network",
    "genesis_hash",
    "branch_id",
    "account_id",
    "collector_payout_commitment",
    "collector_address",
    "transparent_coinbase_address",
    "birthday_height",
    "fund_source",
    "synchronized",
    "initial_balances_zero",
}
if not isinstance(authority, dict) or set(authority) != required:
    raise SystemExit("Wcash wallet bootstrap authority has an unexpected schema")
try:
    account = uuid.UUID(authority["account_id"])
except (AttributeError, TypeError, ValueError):
    raise SystemExit("Wcash wallet bootstrap account is invalid") from None
commitment = authority["collector_payout_commitment"]
collector = authority["collector_address"]
derived_commitment = hashlib.sha256(
    b"Wcash/Wcash child payout address/v1\0" + collector.encode("utf-8")
).hexdigest() if isinstance(collector, str) else ""
if (
    authority["schema_version"] != 1
    or authority["network"] != "testnet"
    or authority["genesis_hash"] != os.environ["WCASH_EXPECTED_GENESIS_HASH"]
    or not isinstance(authority["branch_id"], str)
    or re.fullmatch(r"[0-9a-f]{8}", authority["branch_id"]) is None
    or account.int == 0
    or str(account) != authority["account_id"]
    or authority["account_id"] != os.environ["WCASH_AUTHORITY_SIGNER_ACCOUNT"]
    or not isinstance(commitment, str)
    or re.fullmatch(r"[0-9a-f]{64}", commitment) is None
    or commitment != os.environ["WCASH_AUTHORITY_PAYOUT_COMMITMENT"]
    or commitment != derived_commitment
    or not collector
    or len(collector) > 512
    or not isinstance(authority["transparent_coinbase_address"], str)
    or not authority["transparent_coinbase_address"]
    or len(authority["transparent_coinbase_address"]) > 512
    or not isinstance(authority["birthday_height"], int)
    or authority["birthday_height"] < 1
    or authority["fund_source"] != "ironwood"
    or authority["synchronized"] is not True
    or authority["initial_balances_zero"] is not True
):
    raise SystemExit("Wcash wallet bootstrap authority differs from the rendered policy")
PY

read_line() {
    local name=${1:?credential name is required}
    local path="$CREDENTIALS_DIRECTORY/$name"
    [[ -f $path && ! -L $path ]] || die "required credential is unavailable: $name"
    local size
    size=$(stat -c '%s' -- "$path")
    ((size > 0 && size <= 4096)) || die "credential has an invalid size: $name"
    local value extra
    IFS= read -r value <"$path" || [[ -n $value ]] || die "credential is empty: $name"
    extra=$(tail -n +2 -- "$path")
    [[ -z $extra && -n $value && $value != *[$'\r\n\t']* ]] \
        || die "credential has an invalid representation: $name"
    printf '%s' "$value"
}

split_cookie() {
    local name=${1:?credential name is required}
    local username_variable=${2:?username variable is required}
    local password_variable=${3:?password variable is required}
    local cookie
    cookie=$(read_line "$name")
    [[ $cookie == *:* && ${cookie%%:*} != '' && ${cookie#*:} != '' ]] \
        || die "RPC cookie has an invalid representation: $name"
    printf -v "$username_variable" '%s' "${cookie%%:*}"
    printf -v "$password_variable" '%s' "${cookie#*:}"
    export "${username_variable?}" "${password_variable?}"
}

split_cookie wcash-rpc-cookie WCASH_RPC_USERNAME WCASH_RPC_PASSWORD
split_cookie zcash-template-rpc-cookie ZCASH_TEMPLATE_RPC_USERNAME ZCASH_TEMPLATE_RPC_PASSWORD
split_cookie zcash-validator-rpc-cookie ZCASH_VALIDATOR_RPC_USERNAME ZCASH_VALIDATOR_RPC_PASSWORD

WCASH_PAYOUT_ADDRESS=$(read_line wcash-payout-address)
ZCASH_PAYOUT_ADDRESS=$(read_line zcash-payout-address)
export WCASH_PAYOUT_ADDRESS ZCASH_PAYOUT_ADDRESS

ivk_source="$CREDENTIALS_DIRECTORY/wcash-payout-ivk"
[[ -f $ivk_source && ! -L $ivk_source ]] || die "Wcash payout IVK credential is unavailable"
ivk_temporary="$RUNTIME_DIRECTORY/.wcash-payout-ivk.new.$$"
trap 'rm -f -- "$ivk_temporary"' EXIT
umask 077
cp --no-preserve=mode,ownership,timestamps -- "$ivk_source" "$ivk_temporary"
chmod 0600 -- "$ivk_temporary"
mv -fT -- "$ivk_temporary" "$RUNTIME_DIRECTORY/wcash-payout-ivk"
trap - EXIT
WCASH_PAYOUT_IVK_FILE="$RUNTIME_DIRECTORY/wcash-payout-ivk"
export WCASH_PAYOUT_IVK_FILE

# The backend authenticates each connection with SO_PEERCRED.  Keep mining
# submission authority on the public pool identity alone.  The isolated
# projector and payout identities may only perform the protocol handshake,
# replay events, subscribe to a race-free job snapshot, and check health; the
# backend rejects SubmitShare from either read-only identity.
WCASH_POOL_BACKEND_SUBMIT_UID=$(id -u wcash-pool) \
    || die "pool submit UID lookup failed"
WCASH_POOL_BACKEND_PROJECTOR_UID=$(id -u wcash-pool-projector) \
    || die "projector UID lookup failed"
WCASH_POOL_BACKEND_PAYOUT_UID=$(id -u wcash-payout) \
    || die "payout UID lookup failed"
WCASH_POOL_BACKEND_SOCKET_GID=$(getent group wcash-pool-socket | cut -d: -f3) \
    || die "socket GID lookup failed"
for peer_uid in \
    "$WCASH_POOL_BACKEND_SUBMIT_UID" \
    "$WCASH_POOL_BACKEND_PROJECTOR_UID" \
    "$WCASH_POOL_BACKEND_PAYOUT_UID"; do
    [[ $peer_uid =~ ^[1-9][0-9]{0,9}$ && $peer_uid -le 4294967294 ]] \
        || die "backend peer UID is invalid"
done
[[ $WCASH_POOL_BACKEND_SOCKET_GID =~ ^[1-9][0-9]{0,9}$ \
    && $WCASH_POOL_BACKEND_SOCKET_GID -le 4294967294 ]] \
    || die "socket GID is invalid"
[[ $WCASH_POOL_BACKEND_SUBMIT_UID != "$WCASH_POOL_BACKEND_PROJECTOR_UID" \
    && $WCASH_POOL_BACKEND_SUBMIT_UID != "$WCASH_POOL_BACKEND_PAYOUT_UID" \
    && $WCASH_POOL_BACKEND_PROJECTOR_UID != "$WCASH_POOL_BACKEND_PAYOUT_UID" ]] \
    || die "backend peer UIDs must be distinct"
export WCASH_POOL_BACKEND_SUBMIT_UID WCASH_POOL_BACKEND_PROJECTOR_UID \
    WCASH_POOL_BACKEND_PAYOUT_UID WCASH_POOL_BACKEND_SOCKET_GID

binary="$ZECWEC_RELEASE_PATH/wcash-merge-miner"
[[ $ZECWEC_RELEASE_PATH == /opt/wcash/releases/* && -d $ZECWEC_RELEASE_PATH \
    && ! -L $ZECWEC_RELEASE_PATH \
    && $(realpath -e -- "$ZECWEC_RELEASE_PATH") == "$ZECWEC_RELEASE_PATH" \
    && -x $binary && ! -L $binary ]] \
    || die "immutable backend binary is unavailable"

arguments=(
    "$WCASH_RPC_URL"
    "$ZCASH_TEMPLATE_RPC_URL"
    "$ZCASH_VALIDATOR_RPC_URL"
    -
)

if [[ $mode == serve ]]; then
    exec "$binary" native-pool-backend "${arguments[@]}"
fi

output=$("$binary" pool-backend-init "${arguments[@]}")
authority="$STATE_DIRECTORY/backend-authority-protocol-v2.json"
temporary="${authority}.new.$$"
trap 'rm -f -- "$temporary"' EXIT
printf '%s\n' "$output" >"$temporary"
chmod 0600 "$temporary"
python3 - "$temporary" <<'PY'
import json
import os
import pathlib
import re
import sys
import uuid

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
required = {
    "command",
    "result",
    "backend_instance",
    "journal_stream",
    "event_seq",
    "chain_id",
    "listener_workers",
    "wcash_genesis",
    "zcash_genesis",
    "wcash_payout_commitment",
    "zcash_payout_commitment",
    "share_target_ceiling",
    "share_target_ceiling_byte_order",
}
if not isinstance(value, dict) or set(value) != required:
    raise SystemExit("backend authority response has an unexpected schema")
if value["command"] != "pool-backend-init" or value["result"] not in {
    "initialized", "resumed_identity", "already_initialized"
}:
    raise SystemExit("backend authority response is invalid")
backend = uuid.UUID(value["backend_instance"])
journal = uuid.UUID(value["journal_stream"])
if (
    backend.int == 0
    or journal.int == 0
    or backend == journal
    or str(backend) != value["backend_instance"]
    or str(journal) != value["journal_stream"]
):
    raise SystemExit("backend authority identities are invalid")
expected = {
    "wcash_genesis": os.environ["WCASH_AUTHORITY_GENESIS_WIRE"],
    "zcash_genesis": os.environ["ZCASH_AUTHORITY_GENESIS_WIRE"],
    "wcash_payout_commitment": os.environ["WCASH_AUTHORITY_PAYOUT_COMMITMENT"],
    "zcash_payout_commitment": os.environ["ZCASH_AUTHORITY_PAYOUT_COMMITMENT"],
    "share_target_ceiling": os.environ["WCASH_AUTHORITY_SHARE_TARGET_BE"],
}
if any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in expected.values()):
    raise SystemExit("configured backend authority contains invalid hexadecimal")
if any(value[key] != expected_value for key, expected_value in expected.items()):
    raise SystemExit("backend authority differs from the rendered Testnet policy")
if value["share_target_ceiling_byte_order"] != "big_endian":
    raise SystemExit("backend authority share target has ambiguous byte order")
if value["chain_id"] != int(os.environ["WCASH_AUTHORITY_CHAIN_ID"], 10):
    raise SystemExit("backend authority chain is invalid")
if value["listener_workers"] != int(os.environ["WCASH_POOL_BACKEND_LISTENERS"], 10):
    raise SystemExit("backend authority listener count is invalid")
if not isinstance(value["event_seq"], int) or value["event_seq"] < 0:
    raise SystemExit("backend authority event sequence is invalid")
PY
mv -fT -- "$temporary" "$authority"
trap - EXIT
printf '%s\n' "$output"
