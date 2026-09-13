#!/usr/bin/env bash

set -Eeuo pipefail
set +x
umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command find
require_command cmp
require_command install
require_command pgrep
require_command python3
require_command systemctl

for supervisor in \
    zecwec-testnet-pool-start.service \
    wcash-pool-health.timer \
    wcash-pool-health.service \
    zecwec-cookie-refresh.path \
    zecwec-cookie-refresh.service \
    zecwec-testnet-pool.target; do
    stop_loaded_unit_strict "$supervisor"
done

[[ $# -eq 4 && $4 == --ack-testnet-off-host-backup-and-recovery ]] \
    || die "usage: finalize-zec-offline-custody.sh <settings> <release> <custody-staging-dir> --ack-testnet-off-host-backup-and-recovery"
settings=$1
release=$(resolve_release_root "$2")
staging=$3
require_private_regular_file "$settings"
[[ $staging =~ ^/var/lib/zecwec-custody/zec-[0-9a-f]{7,40}$ \
    && -d $staging && ! -L $staging \
    && $(stat -c '%U:%G:%a' -- "$staging") == root:root:700 ]] \
    || die "Testnet custody staging directory is unsafe"

for unit in \
    wcash-pool.service \
    wcash-pool-projector.service \
    wcash-payout-worker.service \
    zecwec-zallet-payout.service \
    zecwec-zallet.service \
    zecwec-zallet-recovery.service \
    wcash-pool-zec-authority-bootstrap.service; do
    systemctl stop "$unit" >/dev/null 2>&1 \
        || die "could not stop a custody-bearing service"
    require_loaded_unit_fully_inactive "$unit"
done
require_no_processes_for_user wcash-pool "mining identity"
require_no_processes_for_user wcash-pool-projector "accounting projector identity"
require_no_processes_for_user wcash-payout "payout identity"
require_no_processes_for_user zecwec-zallet "collector identity"
require_no_processes_for_user zecwec-zallet-recovery "recovery identity"

zec_custody=/var/lib/zecwec-custody
original=$zec_custody/zec-wallet-original.rpc.json
recovered=$zec_custody/zec-wallet-recovered.rpc.json
attestation=$zec_custody/zec-wallet-recovery.attestation.json
initial_zero=$zec_custody/zec-collector-initial-zero.json
initial_zero_attestation=$zec_custody/zec-collector-initial-zero.attestation
native=$release/wcash-poold
ZECWEC_RELEASE_PATH=$release \
    "$release/deployment/scripts/deploy/verify-release.sh" wcash-poold
python3 "$release/deployment/scripts/deploy/verify-zec-wallet-recovery.py" verify \
    "$settings" "$original" "$recovered" "$attestation" "$native"
ZECWEC_RELEASE_PATH=$release \
ZEC_AUTHORITY_CONFIG=/etc/wcash-pool/zec-authority.testnet.toml \
ZEC_AUTHORITY_RESULT=$initial_zero \
ZEC_AUTHORITY_ATTESTATION=$initial_zero_attestation \
    "$release/deployment/scripts/deploy/zec-authority-bootstrap.sh" verify-sealed

mnemonic=$staging/mnemonic.txt
ciphertext=$staging/mnemonic.age
original_identity=/var/lib/zecwec-zallet/encryption-identity.txt
sealed_identity=$(read_setting "$settings" ZALLET_ENCRYPTION_IDENTITY_CREDENTIAL)
recovery_state=/var/lib/zecwec-zallet-recovery
completed=$zec_custody/zec-wallet-recovery-import.completed
intent=$zec_custody/zec-wallet-recovery-import.intent
[[ -f $mnemonic && ! -L $mnemonic \
    && $(stat -c '%U:%G:%a:%h' -- "$mnemonic") == root:root:400:1 ]] \
    || die "plaintext Testnet mnemonic staging is unavailable or unsafe"
[[ -f $ciphertext && ! -L $ciphertext \
    && $(stat -c '%U:%G:%a:%h' -- "$ciphertext") == root:root:400:1 ]] \
    || die "encrypted Testnet mnemonic backup staging is unavailable or unsafe"
expected_staging_entries=$(printf '%s\n' mnemonic.age mnemonic.txt | LC_ALL=C sort) \
    || die "cannot construct the Testnet staging inventory"
require_exact_immediate_entries "$staging" "$expected_staging_entries" \
    "Testnet custody staging directory"
[[ -f $original_identity && ! -L $original_identity \
    && $(stat -c '%U:%G:%a:%h' -- "$original_identity") == \
        zecwec-zallet:zecwec-zallet:600:1 ]] \
    || die "online Zallet decryption identity is unavailable or unsafe"
[[ -f $completed && ! -L $completed \
    && $(stat -c '%U:%G:%a:%h' -- "$completed") == root:root:400:1 ]] \
    || die "fresh recovery import completion marker is unavailable or unsafe"
[[ ! -e $intent && ! -L $intent ]] \
    || die "recovery mutation intent remains; the ceremony is tainted"
custody_entries=$(find "$zec_custody" -mindepth 1 -maxdepth 1 -printf '%f\n' \
    | LC_ALL=C sort) || die "cannot inspect the pre-seal custody directory"
expected_entries=$(printf '%s\n' \
    zec-collector-initial-zero.attestation \
    zec-collector-initial-zero.json \
    zec-wallet-original.rpc.json \
    zec-wallet-recovered.rpc.json \
    zec-wallet-recovery-import.completed \
    zec-wallet-recovery.attestation.json \
    "$(basename -- "$staging")" \
    | LC_ALL=C sort)
[[ $custody_entries == "$expected_entries" ]] \
    || die "pre-seal custody contains an unexpected or missing entry"
python3 "$release/deployment/scripts/deploy/verify-zec-import-completion.py" \
    "$completed" "$release" "$staging" "$original" "$recovered"
[[ -d $recovery_state && ! -L $recovery_state \
    && $(stat -c '%U:%G:%a' -- "$recovery_state") == \
        zecwec-zallet-recovery:zecwec-zallet-recovery:700 ]] \
    || die "fresh recovery datadir is unavailable or unsafe"
require_cleanup_trees_safe "$staging" "$recovery_state"

[[ $sealed_identity == /etc/wcash-pool/credentials/zallet-encryption-identity ]] \
    || die "sealed Zallet identity path does not match the reviewed policy"
install -d -o root -g root -m 0700 -- "$(dirname -- "$sealed_identity")"
[[ ! -L $sealed_identity ]] || die "sealed Zallet identity path is unsafe"
if [[ -e $sealed_identity ]]; then
    [[ -f $sealed_identity \
        && $(stat -c '%U:%G:%a:%h' -- "$sealed_identity") == root:root:400:1 ]] \
        || die "existing sealed Zallet identity is unsafe"
    cmp --silent -- "$original_identity" "$sealed_identity" \
        || die "refusing to replace a different sealed Zallet identity"
else
    temporary_identity="${sealed_identity}.new.$$"
    trap 'rm -f -- "$temporary_identity"' EXIT
    install -o root -g root -m 0400 -- "$original_identity" "$temporary_identity"
    mv -fT -- "$temporary_identity" "$sealed_identity"
    trap - EXIT
fi

# Both trees are exact, reviewed Testnet-only custody paths. The acknowledgement
# confirms their ciphertext and required identity were already copied off-host
# and the mnemonic was independently restored before these unlink operations.
rm -f -- "$original_identity" "$completed"
find "$recovery_state" -xdev -depth -delete
find "$staging" -xdev -depth -delete
sync -f -- /var/lib/zecwec-zallet "$zec_custody"
require_hot_testnet_payout_custody "$settings" "$release"
log "sealed the Testnet Zcash collector for isolated hot payout after independent recovery"
