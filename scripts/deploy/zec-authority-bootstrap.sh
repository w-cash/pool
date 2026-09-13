#!/usr/bin/env bash

set -Eeuo pipefail
set +x
umask 077

die() {
    printf 'zec-authority-bootstrap: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 1 ]] || die "usage: zec-authority-bootstrap.sh <reconcile|verify|verify-sealed>"
mode=$1
[[ $mode == reconcile || $mode == verify || $mode == verify-sealed ]] \
    || die "mode must be reconcile, verify, or verify-sealed"

: "${ZECWEC_RELEASE_PATH:?immutable release path is required}"
: "${ZEC_AUTHORITY_CONFIG:?ZEC authority configuration is required}"
: "${ZEC_AUTHORITY_RESULT:?initial-zero result path is required}"
: "${ZEC_AUTHORITY_ATTESTATION:?initial-zero attestation path is required}"
[[ $ZECWEC_RELEASE_PATH == /opt/wcash/releases/* \
    && -d $ZECWEC_RELEASE_PATH \
    && ! -L $ZECWEC_RELEASE_PATH \
    && $(realpath -e -- "$ZECWEC_RELEASE_PATH") == "$ZECWEC_RELEASE_PATH" ]] \
    || die "release root is not one canonical version directory"
[[ -x $ZECWEC_RELEASE_PATH/wcash-poold && ! -L $ZECWEC_RELEASE_PATH/wcash-poold ]] \
    || die "wcash-poold is unavailable"
[[ -f $ZEC_AUTHORITY_CONFIG && ! -L $ZEC_AUTHORITY_CONFIG ]] \
    || die "ZEC authority configuration is unavailable"

verify_canonical_policy() {
    local backend_gid metadata
    [[ $ZEC_AUTHORITY_CONFIG == /etc/wcash-pool/zec-authority.testnet.toml ]] \
        || die "ZEC authority configuration differs from the reviewed path"
    backend_gid=$(id -g wcash-pool-backend) \
        || die "backend authority group is unavailable"
    metadata=$(stat -c '%u:%g:%a:%h' -- "$ZEC_AUTHORITY_CONFIG") \
        || die "ZEC authority configuration metadata is unavailable"
    [[ $metadata == "0:$backend_gid:640:1" ]] \
        || die "ZEC authority configuration ownership or mode is unsafe"
}

verify_artifact() {
    local transport=${1:?artifact transport is required}
    [[ -f $ZEC_AUTHORITY_RESULT && ! -L $ZEC_AUTHORITY_RESULT \
        && -f $ZEC_AUTHORITY_ATTESTATION && ! -L $ZEC_AUTHORITY_ATTESTATION ]] \
        || die "initial-zero ZEC authority evidence is unavailable"
    local result_metadata attestation_metadata trusted_uid
    result_metadata=$(stat -c '%u:%a:%h' -- "$ZEC_AUTHORITY_RESULT")
    attestation_metadata=$(stat -c '%u:%a:%h' -- "$ZEC_AUTHORITY_ATTESTATION")
    trusted_uid=$(id -u)
    if [[ $transport == state ]]; then
        [[ $result_metadata == "$trusted_uid:600:1" \
            && $attestation_metadata == "$trusted_uid:600:1" ]] \
            || die "initial-zero ZEC authority evidence ownership or mode is unsafe"
    elif [[ $transport == credential ]]; then
        [[ $result_metadata =~ ^(0|$trusted_uid):(400|600):1$ \
            && $attestation_metadata =~ ^(0|$trusted_uid):(400|600):1$ ]] \
            || die "initial-zero ZEC authority credential metadata is unsafe"
    elif [[ $transport == sealed ]]; then
        [[ $result_metadata == 0:400:1 \
            && $attestation_metadata == 0:400:1 ]] \
            || die "sealed initial-zero ZEC authority metadata is unsafe"
    else
        die "artifact transport is invalid"
    fi
    local size lines schema config_digest result_digest actual
    size=$(stat -c '%s' -- "$ZEC_AUTHORITY_RESULT")
    lines=$(wc -l <"$ZEC_AUTHORITY_RESULT")
    ((size > 0 && size <= 512 && lines == 1)) \
        || die "initial-zero ZEC authority result is not one bounded record"
    python3 - "$ZEC_AUTHORITY_RESULT" <<'PY'
import json
import pathlib
import re
import sys

try:
    value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit("initial-zero ZEC authority result is invalid") from None
required = {
    "authority_verified",
    "network",
    "consensus_branch_id",
    "collector_pool",
    "initial_balance_zat",
    "tip_height",
    "tip_hash",
}
if (
    not isinstance(value, dict)
    or set(value) != required
    or value["authority_verified"] is not True
    or value["network"] != "testnet"
    or value["consensus_branch_id"] != "37a5165b"
    or value["collector_pool"] != "ironwood"
    or value["initial_balance_zat"] != 0
    or not isinstance(value["tip_height"], int)
    or isinstance(value["tip_height"], bool)
    or value["tip_height"] < 1
    or not isinstance(value["tip_hash"], str)
    or re.fullmatch(r"[0-9a-f]{64}", value["tip_hash"]) is None
    or int(value["tip_hash"], 16) == 0
):
    raise SystemExit("initial-zero ZEC authority result has an unexpected schema")
PY
    [[ $(wc -l <"$ZEC_AUTHORITY_ATTESTATION") -eq 3 ]] \
        || die "initial-zero ZEC authority attestation has an unexpected schema"
    IFS= read -r schema <"$ZEC_AUTHORITY_ATTESTATION"
    config_digest=$(awk -F= '$1 == "config_sha256" { print $2 }' "$ZEC_AUTHORITY_ATTESTATION")
    result_digest=$(awk -F= '$1 == "result_sha256" { print $2 }' "$ZEC_AUTHORITY_ATTESTATION")
    [[ $schema == schema_version=1 \
        && $(grep -c '^config_sha256=' "$ZEC_AUTHORITY_ATTESTATION") -eq 1 \
        && $(grep -c '^result_sha256=' "$ZEC_AUTHORITY_ATTESTATION") -eq 1 \
        && $config_digest =~ ^[0-9a-f]{64}$ \
        && $result_digest =~ ^[0-9a-f]{64}$ ]] \
        || die "initial-zero ZEC authority attestation is invalid"
    actual=$(sha256sum -- "$ZEC_AUTHORITY_CONFIG" | awk '{print $1}')
    [[ $actual == "$config_digest" ]] \
        || die "current ZEC authority policy differs from its initial-zero evidence"
    actual=$(sha256sum -- "$ZEC_AUTHORITY_RESULT" | awk '{print $1}')
    [[ $actual == "$result_digest" ]] \
        || die "initial-zero ZEC authority result digest is invalid"
}

if [[ $mode == verify || $mode == verify-sealed ]]; then
    if [[ $mode == verify-sealed ]]; then
        [[ ${EUID} -eq 0 ]] || die "sealed authority verification must run as root"
        [[ $ZEC_AUTHORITY_CONFIG == /etc/wcash-pool/zec-authority.testnet.toml \
            && $ZEC_AUTHORITY_RESULT == /var/lib/zecwec-custody/zec-collector-initial-zero.json \
            && $ZEC_AUTHORITY_ATTESTATION == /var/lib/zecwec-custody/zec-collector-initial-zero.attestation ]] \
            || die "sealed authority inputs differ from the reviewed root namespace"
        verify_canonical_policy
        verify_artifact sealed
        exit 0
    fi
    : "${CREDENTIALS_DIRECTORY:?systemd credential directory is required}"
    [[ $ZEC_AUTHORITY_CONFIG == "$CREDENTIALS_DIRECTORY/zec-authority-config" \
        && $ZEC_AUTHORITY_RESULT == "$CREDENTIALS_DIRECTORY/zec-initial-zero-result" \
        && $ZEC_AUTHORITY_ATTESTATION == "$CREDENTIALS_DIRECTORY/zec-initial-zero-attestation" ]] \
        || die "verification inputs must use private systemd credential mounts"
    verify_artifact credential
    exit 0
fi

: "${CREDENTIALS_DIRECTORY:?systemd credential directory is required}"

: "${STATE_DIRECTORY:?systemd state directory is required}"
: "${BACKEND_AUTHORITY:?backend authority path is required}"
verify_canonical_policy
[[ $STATE_DIRECTORY == /var/lib/wcash-pool-backend ]] \
    || die "state directory differs from the reviewed authority namespace"
[[ $ZEC_AUTHORITY_RESULT == "$STATE_DIRECTORY/zec-collector-initial-zero.json" \
    && $ZEC_AUTHORITY_ATTESTATION == "$STATE_DIRECTORY/zec-collector-initial-zero.attestation" \
    && $BACKEND_AUTHORITY == "$STATE_DIRECTORY/backend-authority-protocol-v2.json" ]] \
    || die "authority inputs differ from the reviewed protocol-v2 namespace"

# Serialize retries and the backend initializer in the same state directory.
exec 9>"$STATE_DIRECTORY/zec-authority-bootstrap.lock"
flock -x 9

if [[ -e $BACKEND_AUTHORITY || -L $BACKEND_AUTHORITY ]]; then
    [[ -f $BACKEND_AUTHORITY && ! -L $BACKEND_AUTHORITY ]] \
        || die "backend authority path is unsafe"
    verify_artifact state
    exit 0
fi

result_new="$ZEC_AUTHORITY_RESULT.new.$$"
attestation_new="$ZEC_AUTHORITY_ATTESTATION.new.$$"
trap 'rm -f -- "$result_new" "$attestation_new"' EXIT

"$ZECWEC_RELEASE_PATH/wcash-poold" zec-authority-check \
    --config "$ZEC_AUTHORITY_CONFIG" >"$result_new"
chmod 0600 -- "$result_new"
result_size=$(stat -c '%s' -- "$result_new")
[[ $result_size -gt 0 && $result_size -le 512 && $(wc -l <"$result_new") -eq 1 ]] \
    || die "native ZEC authority gate returned an invalid success record"

config_digest=$(sha256sum -- "$ZEC_AUTHORITY_CONFIG" | awk '{print $1}')
result_digest=$(sha256sum -- "$result_new" | awk '{print $1}')
printf '%s\n' \
    'schema_version=1' \
    "config_sha256=$config_digest" \
    "result_sha256=$result_digest" >"$attestation_new"
chmod 0600 -- "$attestation_new"

mv -fT -- "$result_new" "$ZEC_AUTHORITY_RESULT"
mv -fT -- "$attestation_new" "$ZEC_AUTHORITY_ATTESTATION"
sync -f -- "$STATE_DIRECTORY"
trap - EXIT
verify_artifact state
