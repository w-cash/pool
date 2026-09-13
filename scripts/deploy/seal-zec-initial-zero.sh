#!/usr/bin/env bash

set -Eeuo pipefail
set +x
umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command cmp
require_command install
require_command pgrep
require_command systemctl

[[ $# -eq 3 && $3 == --ack-live-testnet-zero-gate ]] \
    || die "usage: seal-zec-initial-zero.sh <settings> <release> --ack-live-testnet-zero-gate"
settings=$1
release=$2
require_private_regular_file "$settings"
release=$(resolve_release_root "$release")
ZECWEC_RELEASE_PATH=$release \
    "$release/deployment/scripts/deploy/verify-release.sh" wcash-poold
ZECWEC_RELEASE_PATH=$release \
    "$release/deployment/scripts/deploy/verify-release.sh" deployment-package

stop_backend_units_for_zec_sealing
require_loaded_unit_fully_inactive wcash-pool-zec-authority-bootstrap.service
staging_result=/var/lib/wcash-pool-backend/zec-collector-initial-zero.json
staging_attestation=/var/lib/wcash-pool-backend/zec-collector-initial-zero.attestation
authority_config=/etc/wcash-pool/zec-authority.testnet.toml
backend_authority=/var/lib/wcash-pool-backend/backend-authority-protocol-v2.json
final_result=/var/lib/zecwec-custody/zec-collector-initial-zero.json
final_attestation=/var/lib/zecwec-custody/zec-collector-initial-zero.attestation
backend_uid=$(id -u wcash-pool-backend)
[[ ! -e $backend_authority && ! -L $backend_authority ]] \
    || die "initial-zero evidence must be sealed before backend authority exists"
for staged in "$staging_result" "$staging_attestation"; do
    [[ -f $staged && ! -L $staged \
        && $(stat -c '%u:%a:%h' -- "$staged") == "$backend_uid:600:1" ]] \
        || die "staged initial-zero evidence is unavailable or unsafe"
done
[[ -f $authority_config && ! -L $authority_config ]] \
    || die "ZEC authority configuration is unavailable"
[[ -d /var/lib/zecwec-custody && ! -L /var/lib/zecwec-custody \
    && $(stat -c '%U:%G:%a' -- /var/lib/zecwec-custody) == root:root:700 ]] \
    || die "ZEC custody directory is unsafe"

verification=$(mktemp -d /var/lib/zecwec-custody/.initial-zero-verify.XXXXXX)
trap 'rm -rf -- "$verification"' EXIT
install -o root -g root -m 0600 "$authority_config" \
    "$verification/zec-authority-config"
install -o root -g root -m 0600 "$staging_result" \
    "$verification/zec-initial-zero-result"
install -o root -g root -m 0600 "$staging_attestation" \
    "$verification/zec-initial-zero-attestation"
CREDENTIALS_DIRECTORY=$verification \
ZECWEC_RELEASE_PATH=$release \
ZEC_AUTHORITY_CONFIG=$verification/zec-authority-config \
ZEC_AUTHORITY_RESULT=$verification/zec-initial-zero-result \
ZEC_AUTHORITY_ATTESTATION=$verification/zec-initial-zero-attestation \
    "$release/deployment/scripts/deploy/zec-authority-bootstrap.sh" verify

for destination in "$final_result" "$final_attestation"; do
    [[ ! -e $destination && ! -L $destination ]] \
        || die "sealed initial-zero destination already exists"
done
install -o root -g root -m 0400 "$verification/zec-initial-zero-result" \
    "$final_result"
install -o root -g root -m 0400 "$verification/zec-initial-zero-attestation" \
    "$final_attestation"
cmp --silent "$final_result" "$verification/zec-initial-zero-result" \
    || die "sealed initial-zero result differs after installation"
cmp --silent "$final_attestation" "$verification/zec-initial-zero-attestation" \
    || die "sealed initial-zero attestation differs after installation"
ZECWEC_RELEASE_PATH=$release \
ZEC_AUTHORITY_CONFIG=$authority_config \
ZEC_AUTHORITY_RESULT=$final_result \
ZEC_AUTHORITY_ATTESTATION=$final_attestation \
    "$release/deployment/scripts/deploy/zec-authority-bootstrap.sh" verify-sealed
rm -f -- "$staging_result" "$staging_attestation"
sync -f -- /var/lib/zecwec-custody /var/lib/wcash-pool-backend
trap - EXIT
rm -rf -- "$verification"
log "root-sealed the Testnet initial-zero authority; no wallet or pool service was started"
