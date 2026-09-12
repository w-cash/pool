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
[[ $WCASH_PAYOUT_MODE == transparent || $WCASH_PAYOUT_MODE == ironwood ]] \
    || die "Wcash payout mode must be transparent or ironwood"

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

if [[ $WCASH_PAYOUT_MODE == ironwood ]]; then
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
else
    [[ ! -e $RUNTIME_DIRECTORY/wcash-payout-ivk ]] \
        || die "transparent payout runtime contains a stale incoming viewing key"
    unset WCASH_PAYOUT_IVK_FILE
fi

WCASH_POOL_BACKEND_PEER_UID=$(id -u wcash-pool)
WCASH_POOL_BACKEND_SOCKET_GID=$(getent group wcash-pool-socket | cut -d: -f3)
[[ $WCASH_POOL_BACKEND_PEER_UID =~ ^[0-9]+$ ]] || die "pool UID lookup failed"
[[ $WCASH_POOL_BACKEND_SOCKET_GID =~ ^[0-9]+$ ]] || die "socket GID lookup failed"
export WCASH_POOL_BACKEND_PEER_UID WCASH_POOL_BACKEND_SOCKET_GID

binary=/opt/wcash/current/wcash-merge-miner
[[ -x $binary && ! -L $binary ]] || die "backend binary is unavailable"

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
authority="$STATE_DIRECTORY/backend-authority.json"
temporary="${authority}.new.$$"
trap 'rm -f -- "$temporary"' EXIT
printf '%s\n' "$output" >"$temporary"
chmod 0600 "$temporary"
python3 - "$temporary" <<'PY'
import json
import pathlib
import sys
import uuid

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
required = {"command", "result", "backend_instance", "journal_stream", "chain_id"}
if not required.issubset(value):
    raise SystemExit("backend authority response is incomplete")
if value["command"] != "pool-backend-init" or value["result"] not in {
    "initialized", "resumed_identity", "already_initialized"
}:
    raise SystemExit("backend authority response is invalid")
backend = uuid.UUID(value["backend_instance"])
journal = uuid.UUID(value["journal_stream"])
if backend.int == 0 or journal.int == 0 or backend == journal:
    raise SystemExit("backend authority identities are invalid")
if not isinstance(value["chain_id"], int) or value["chain_id"] <= 0:
    raise SystemExit("backend authority chain is invalid")
PY
mv -fT -- "$temporary" "$authority"
trap - EXIT
printf '%s\n' "$output"
