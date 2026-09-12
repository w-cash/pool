#!/usr/bin/env bash

set -Eeuo pipefail
set +x
umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command getent
require_command id
require_command pgrep
require_command python3
require_command systemctl

[[ $# -eq 5 && $5 == --ack-independent-offline-backup-recovery ]] || die \
    "usage: seal-wcash-custody.sh <settings> <recovery-init-json> <recovery-identity-json> <authority-json> --ack-independent-offline-backup-recovery"
settings=$1
recovery_init=$2
recovery_identity=$3
authority=$4
for protected in "$settings" "$recovery_init" "$recovery_identity"; do
    require_private_regular_file "$protected"
done
require_absolute_path "$authority"
[[ $authority == /var/lib/wcash-pool/wcash-wallet-authority.json ]] \
    || die "wallet authority path does not match the reviewed deployment"
[[ -f $authority && ! -L $authority ]] || die "frozen wallet authority is unavailable"
case $(stat -c '%U:%G:%a:%h' -- "$authority") in
    wcash-pool:wcash-pool:600:1 | root:root:400:1) ;;
    *) die "frozen wallet authority ownership or mode is unsafe" ;;
esac

systemctl stop wcash-pool.service wcash-pool-wallet-init.service \
    || die "could not stop mining and wallet initialization before sealing custody"
for unit in wcash-pool.service wcash-pool-wallet-init.service; do
    [[ $(systemctl show --property=ActiveState --value "$unit") == inactive \
        && $(systemctl show --property=SubState --value "$unit") == dead \
        && $(systemctl show --property=MainPID --value "$unit") == 0 \
        && $(systemctl show --property=ControlPID --value "$unit") == 0 ]] \
        || die "service is not fully inactive before sealing custody"
done
require_no_processes_for_user wcash-pool "mining identity"

seed=$(read_setting "$settings" WEC_SEED_FILE)
[[ $seed == /var/lib/wcash-pool-secrets/wcash-seed ]] \
    || die "seed path does not match the reviewed deployment"
seed_parent=$(dirname -- "$seed")
attestation="$seed_parent/wcash-wallet-recovery.attestation"
[[ -f $seed && ! -L $seed ]] || die "Wcash seed is unavailable"
[[ ! -L $attestation ]] || die "recovery attestation path is unsafe"
if [[ -e $attestation ]]; then
    [[ -f $attestation \
        && $(stat -c '%U:%G:%a:%h' -- "$attestation") == root:root:400:1 ]] \
        || die "existing recovery attestation is unsafe"
fi

verifier="$script_dir/verify-wcash-wallet-recovery.py"
[[ -f $verifier && ! -L $verifier ]] || die "wallet recovery verifier is unavailable"
python3 "$verifier" seal \
    "$authority" "$recovery_init" "$recovery_identity" "$attestation"
chown root:root -- "$authority"
chmod 0400 -- "$authority"
chown root:root -- "$attestation"
chmod 0400 -- "$attestation"

case $(stat -c '%U:%G:%a:%h' -- "$seed") in
    wcash-pool:wcash-pool:600:1)
        chown root:root -- "$seed"
        chmod 0400 -- "$seed"
        ;;
    root:root:400:1) ;;
    *) die "Wcash seed ownership or mode is unsafe" ;;
esac
chown root:root -- "$seed_parent"
chmod 0700 -- "$seed_parent"

require_sealed_wcash_custody "$seed" "$authority" "$attestation"
log "sealed independently recovered Wcash custody outside the mining identity; no wallet service was started"
