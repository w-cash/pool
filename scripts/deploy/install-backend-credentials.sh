#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command python3

[[ $# -eq 3 || $# -eq 4 ]] \
    || die "usage: install-backend-credentials.sh <settings> <wcash-address-file> <zcash-address-file> [wcash-ivk-file]"
settings=$1
wcash_address=$2
zcash_address=$3
wcash_ivk=${4:-}
require_private_regular_file "$settings"
mode=$(read_setting "$settings" WCASH_PAYOUT_MODE)
[[ $mode == transparent || $mode == ironwood ]] || die "Wcash payout mode is invalid"
if [[ $mode == ironwood ]]; then
    [[ -n $wcash_ivk ]] || die "Ironwood payout requires a Wcash incoming viewing key"
elif [[ -n $wcash_ivk ]]; then
    die "transparent payout must not be supplied a Wcash incoming viewing key"
fi
for source in "$wcash_address" "$zcash_address"; do
    require_private_regular_file "$source"
done
[[ -z $wcash_ivk ]] || require_private_regular_file "$wcash_ivk"

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
if mode == "ironwood":
    ivk = pathlib.Path(sys.argv[4]).read_text(encoding="ascii")
    if ivk != ivk.strip() or not re.fullmatch(r"[0-9a-fA-F]{128}", ivk):
        raise SystemExit("Wcash payout IVK must contain exactly 64 hexadecimal bytes")
PY

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

if [[ $mode == ironwood ]]; then
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
fi

log "installed exact backend payout credentials without printing their contents"
