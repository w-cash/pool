#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command find
require_command python3
require_command stat

[[ $# -eq 5 && $5 == --ack-external-custody-reviewed ]] \
    || die "usage: verify-prelaunch-custody-inputs.sh <release> <staging> <Wcash recovery init JSON> <Wcash recovery identity JSON> --ack-external-custody-reviewed"
release=$(resolve_release_root "$1")
staging=$2
recovery_init=$3
recovery_identity=$4

version=${release##*/}
[[ $version =~ ^pool-([0-9a-f]{7,40})$ ]] \
    || die "custody release name does not contain one reviewed source suffix"
suffix=${BASH_REMATCH[1]}
[[ $staging == "/var/lib/zecwec-custody/zec-$suffix" ]] \
    || die "custody staging path is not bound to the reviewed release"
[[ -d $staging && ! -L $staging \
    && $(stat -c '%U:%G:%a' -- "$staging") == root:root:700 ]] \
    || die "custody staging directory is unavailable or unsafe"

expected_staging=$(printf '%s\n' mnemonic.age mnemonic.txt | LC_ALL=C sort)
require_exact_immediate_entries \
    "$staging" "$expected_staging" "prelaunch custody staging"
for staged_secret in "$staging/mnemonic.age" "$staging/mnemonic.txt"; do
    [[ -f $staged_secret && ! -L $staged_secret \
        && $(stat -c '%U:%G:%a:%h' -- "$staged_secret") == root:root:400:1 ]] \
        || die "prelaunch custody staging contains an unsafe secret file"
done
mnemonic_size=$(stat -c '%s' -- "$staging/mnemonic.txt")
ciphertext_size=$(stat -c '%s' -- "$staging/mnemonic.age")
((mnemonic_size >= 64 && mnemonic_size <= 512)) \
    || die "staged mnemonic size is invalid"
((ciphertext_size >= 128 && ciphertext_size <= 65536)) \
    || die "staged mnemonic ciphertext size is invalid"

zallet_state=/var/lib/zecwec-zallet
zallet_identity=$zallet_state/encryption-identity.txt
zallet_database=$zallet_state/wallet.db
[[ -d $zallet_state && ! -L $zallet_state \
    && $(stat -c '%U:%G:%a' -- "$zallet_state") == \
        zecwec-zallet:zecwec-zallet:700 ]] \
    || die "pre-provisioned Zallet state directory is unsafe"
for zallet_file in "$zallet_identity" "$zallet_database"; do
    [[ -f $zallet_file && ! -L $zallet_file \
        && $(stat -c '%U:%G:%a:%h' -- "$zallet_file") == \
            zecwec-zallet:zecwec-zallet:600:1 ]] \
        || die "pre-provisioned Zallet state is incomplete or unsafe"
done

require_private_regular_file "$recovery_init"
require_private_regular_file "$recovery_identity"
python3 - "$recovery_init" "$recovery_identity" <<'PY'
import json
import pathlib
import sys
import uuid


def read(path: str) -> dict:
    try:
        value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise SystemExit("Wcash recovery evidence is unavailable or invalid") from None
    if not isinstance(value, dict):
        raise SystemExit("Wcash recovery evidence is not an object")
    return value


initialized = read(sys.argv[1])
identity = read(sys.argv[2])
if set(initialized) != {
    "account_id",
    "birthday_height",
    "address",
    "transparent_coinbase_address",
    "created",
}:
    raise SystemExit("Wcash recovery initialization has an unexpected schema")
if set(identity) != {
    "protocol_version",
    "network",
    "genesis_hash",
    "branch_id",
    "account_id",
    "collector_payout_commitment",
    "fund_source",
    "synchronized",
}:
    raise SystemExit("Wcash recovery identity has an unexpected schema")
try:
    account = uuid.UUID(initialized["account_id"])
except (AttributeError, TypeError, ValueError):
    raise SystemExit("Wcash recovery account is invalid") from None
if (
    account.int == 0
    or str(account) != initialized["account_id"]
    or identity["account_id"] != initialized["account_id"]
    or initialized["created"] is not True
    or identity["protocol_version"] != 2
    or identity["network"] != "testnet"
    or identity["genesis_hash"]
    != "6b66fff119977d36d9c989093b516a876dbf6596536791ff35bb4c581e3fda98"
    or identity["branch_id"] != "54ba2bfb"
    or identity["fund_source"] != "ironwood"
    or identity["synchronized"] is not True
):
    raise SystemExit("Wcash recovery evidence differs from Testnet policy")
PY

log "pre-provisioned external custody inputs are present and structurally valid"
