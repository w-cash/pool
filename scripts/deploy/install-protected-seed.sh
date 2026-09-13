#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command python3

[[ $# -eq 2 ]] || die "usage: install-protected-seed.sh <root-owned-seed-source> <settings>"
source_seed=$1
settings=$2
require_private_regular_file "$source_seed"
require_private_regular_file "$settings"
destination=$(read_setting "$settings" WEC_SEED_FILE)
require_absolute_path "$destination"
[[ $destination == /var/lib/wcash-pool-secrets/wcash-seed ]] \
    || die "WEC_SEED_FILE does not match the reviewed deployment path"

python3 - "$source_seed" <<'PY'
import pathlib
import re
import sys

value = pathlib.Path(sys.argv[1]).read_text(encoding="ascii")
if value != value.strip() or not re.fullmatch(r"[0-9a-fA-F]{64,504}", value) or len(value) % 2:
    raise SystemExit("Wcash seed source must contain one 32..252-byte hexadecimal seed")
PY

[[ ! -L $destination ]] || die "seed destination must not be a symbolic link"
if [[ -e $destination ]]; then
    [[ -f $destination && ! -L $destination ]] || die "existing seed destination is unsafe"
    cmp --silent -- "$source_seed" "$destination" || die "refusing to replace a different Wcash seed"
    [[ $(stat -c '%U:%G:%a:%h' -- "$destination") == wcash-payout:wcash-payout:600:1 ]] \
        || die "existing seed ownership or mode is unsafe"
    log "the existing protected Wcash seed matches the supplied source"
    exit 0
fi

install -d -o root -g wcash-payout -m 0710 -- "$(dirname -- "$destination")"
temporary="${destination}.new.$$"
trap 'rm -f -- "$temporary"' EXIT
install -o wcash-payout -g wcash-payout -m 0600 -- "$source_seed" "$temporary"
mv -fT -- "$temporary" "$destination"
trap - EXIT
log "installed the dedicated Wcash collector seed; prove its Ironwood balance is zero and back it up offline before continuing"
