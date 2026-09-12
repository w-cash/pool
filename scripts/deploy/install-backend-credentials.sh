#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command python3

[[ $# -eq 4 ]] \
    || die "usage: install-backend-credentials.sh <settings> <wcash-address-file> <zcash-address-file> <wcash-ivk-file>"
settings=$1
wcash_address=$2
zcash_address=$3
wcash_ivk=$4
require_private_regular_file "$settings"
mode=$(read_setting "$settings" WCASH_PAYOUT_MODE)
[[ $mode == ironwood ]] || die "the Testnet pool requires direct Ironwood Wcash payout"
for source in "$wcash_address" "$zcash_address"; do
    require_private_regular_file "$source"
done
require_private_regular_file "$wcash_ivk"

python3 - "$wcash_address" "$zcash_address" "$mode" "$wcash_ivk" <<'PY'
import pathlib
import re
import sys

wcash = pathlib.Path(sys.argv[1]).read_text(encoding="ascii")
zcash = pathlib.Path(sys.argv[2]).read_text(encoding="ascii")
mode = sys.argv[3]
for label, value in (("Wcash payout address", wcash), ("Zcash payout address", zcash)):
    if value != value.strip() or not 8 <= len(value) <= 512 or any(char.isspace() for char in value):
        raise SystemExit(f"{label} must contain one bounded address")
ivk = pathlib.Path(sys.argv[4]).read_text(encoding="ascii")
if ivk != ivk.strip() or not re.fullmatch(r"[0-9a-f]{128}", ivk):
    raise SystemExit("Wcash payout IVK must contain exactly 64 lowercase hexadecimal bytes")
PY

release_root=$(resolve_release_root "${ZECWEC_RELEASE_PATH:-$ZECWEC_CURRENT_RELEASE}")
ZECWEC_RELEASE_PATH=$release_root \
    "$release_root/deployment/scripts/deploy/verify-release.sh" wcash-wallet
validation=$(mktemp /var/tmp/zecwec-wcash-address.XXXXXX)
trap 'rm -f -- "$validation"' EXIT
chmod 0600 -- "$validation"
"$release_root/wcash-wallet" --network testnet validate-address \
    <"$wcash_address" >"$validation"
python3 - "$wcash_address" "$validation" <<'PY'
import json
import pathlib
import sys

address = pathlib.Path(sys.argv[1]).read_text(encoding="ascii").strip()
validated = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if set(validated) != {"network", "receiver_kind", "canonical"}:
    raise SystemExit("Wcash address validator returned an unexpected schema")
if (
    validated["network"] != "testnet"
    or validated["receiver_kind"] != "ironwood"
    or validated["canonical"] != address
):
    raise SystemExit("Wcash collector must be one canonical Testnet Ironwood address")
PY
rm -f -- "$validation"
trap - EXIT

for item in \
    "WCASH_PAYOUT_ADDRESS_CREDENTIAL:$wcash_address" \
    "ZCASH_PAYOUT_ADDRESS_CREDENTIAL:$zcash_address"; do
    key=${item%%:*}
    source=${item#*:}
    destination=$(read_setting "$settings" "$key")
    expected="$ZECWEC_CREDENTIAL_DIR/${key,,}"
    case "$key" in
        WCASH_PAYOUT_ADDRESS_CREDENTIAL) expected="$ZECWEC_CREDENTIAL_DIR/wcash-payout-address" ;;
        ZCASH_PAYOUT_ADDRESS_CREDENTIAL) expected="$ZECWEC_CREDENTIAL_DIR/zcash-payout-address" ;;
    esac
    [[ $destination == "$expected" ]] || die "$key does not match the reviewed deployment path"
    if [[ -e $destination ]]; then
        cmp --silent -- "$source" "$destination" || die "refusing to replace a different $key"
        require_private_regular_file "$destination"
    else
        install_private_file "$source" "$destination" root root
    fi
done

destination=$(read_setting "$settings" WCASH_PAYOUT_IVK_CREDENTIAL)
[[ $destination == "$ZECWEC_CREDENTIAL_DIR/wcash-payout-ivk" ]] \
    || die "WCASH_PAYOUT_IVK_CREDENTIAL does not match the reviewed deployment path"
if [[ -e $destination ]]; then
    cmp --silent -- "$wcash_ivk" "$destination" \
        || die "refusing to replace a different WCASH_PAYOUT_IVK_CREDENTIAL"
    require_private_regular_file "$destination"
else
    install_private_file "$wcash_ivk" "$destination" root root
fi

log "installed exact backend payout credentials without printing their contents"
