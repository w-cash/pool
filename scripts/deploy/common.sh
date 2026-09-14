#!/usr/bin/env bash
# Shared deployment helpers. This file must never be sourced with xtrace on.

set -Eeuo pipefail
set +x

# shellcheck disable=SC2034
readonly ZECWEC_CONFIG_DIR=/etc/wcash-pool
# shellcheck disable=SC2034
readonly ZECWEC_CREDENTIAL_DIR=/etc/wcash-pool/credentials
# shellcheck disable=SC2034
readonly ZECWEC_RELEASE_ROOT=/opt/wcash/releases
# shellcheck disable=SC2034
readonly ZECWEC_CURRENT_RELEASE=/opt/wcash/current
# shellcheck disable=SC2034
readonly ZECWEC_LIBEXEC=/usr/local/libexec/zecwec
# PostgreSQL 14 reaches upstream end-of-life during this Testnet launch window.
# Keep the supported server floor explicit and compare PostgreSQL's numeric value.
readonly ZECWEC_MINIMUM_POSTGRES_VERSION_NUM=160000

log() {
    printf 'zecwec-deploy: %s\n' "$*" >&2
}

die() {
    log "ERROR: $*"
    exit 1
}

require_root() {
    [[ ${EUID} -eq 0 ]] || die "this command must run as root"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"
}

require_readonly_systemd_credential() {
    local credential=$1
    local expected_name=$2
    local service_uid=${3:-$(id -u)}
    local metadata owner mode links

    [[ -n ${CREDENTIALS_DIRECTORY:-} \
        && $CREDENTIALS_DIRECTORY == /* \
        && -d $CREDENTIALS_DIRECTORY \
        && ! -L $CREDENTIALS_DIRECTORY ]] \
        || die "systemd credential directory is unavailable"
    [[ $credential == "$CREDENTIALS_DIRECTORY/$expected_name" \
        && -f $credential \
        && ! -L $credential ]] \
        || die "protected credential is unavailable"
    [[ -r $credential ]] \
        || die "protected credential is not readable by the service"

    metadata=$(stat -c '%u:%a:%h' -- "$credential") \
        || die "protected credential metadata is unavailable"
    IFS=: read -r owner mode links <<<"$metadata"
    [[ ($owner == 0 || $owner == "$service_uid") \
        && ($mode == 400 || $mode == 440) \
        && $links == 1 ]] \
        || die "protected credential ownership, mode, or link count is invalid"
    if ((service_uid != 0)); then
        [[ ! -w $credential ]] \
            || die "protected credential is writable by the service"
    fi
}

require_paths_absent() {
    local label=${1:?absence-check label is required}
    shift
    (($# > 0)) || die "$label requires at least one path"
    local path
    for path in "$@"; do
        [[ ! -e $path && ! -L $path ]] \
            || die "$label: $path"
    done
}

start_nginx_for_closed_ingress() {
    require_command nginx
    require_command systemctl
    nginx -t >/dev/null 2>&1 || die "nginx configuration validation failed"
    systemctl start nginx.service \
        || die "nginx could not start while mining ingress was closed"
    systemctl is-active --quiet nginx.service \
        || die "nginx is not active while mining ingress is closed"
}

require_supported_postgres_server() {
    local version_num
    require_command runuser
    require_command psql
    if ! version_num=$(runuser --user postgres -- \
        psql --dbname=postgres --no-psqlrc --set=ON_ERROR_STOP=1 \
        --tuples-only --no-align --command='SHOW server_version_num'); then
        die "PostgreSQL server version could not be established"
    fi
    [[ $version_num =~ ^[0-9]+$ ]] \
        || die "PostgreSQL returned an invalid server_version_num"
    ((10#$version_num >= ZECWEC_MINIMUM_POSTGRES_VERSION_NUM)) \
        || die "PostgreSQL 16 or newer is required (server_version_num=$version_num)"
}

stop_testnet_runtime_after_failure() {
    local settings=${1:-/etc/wcash-pool/deployment.env}
    local cidrs=${2:-/etc/wcash-pool/miner-cidrs}
    local deploy_dir
    systemctl stop zecwec-testnet-pool.target wcash-pool-custody-gate.service \
        wcash-pool-health.timer \
        wcash-payout-worker.service zecwec-zallet-payout.service \
        wcash-pool.service wcash-pool-projector.service >/dev/null 2>&1 || true
    deploy_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
    if [[ -x $deploy_dir/restrict-mining-firewall.sh \
        && -f $settings && ! -L $settings \
        && -f $cidrs && ! -L $cidrs ]]; then
        "$deploy_dir/restrict-mining-firewall.sh" close "$settings" "$cidrs" \
            >/dev/null 2>&1 \
            || log "WARNING: could not close the mining firewall after runtime failure"
    fi
}

require_unreadable_by_user() {
    local path=${1:?path is required}
    local user=${2:?user is required}
    local label=${3:-protected path}
    require_command runuser
    [[ -e $path && ! -L $path ]] || die "$label is unavailable or unsafe"
    local result
    # $1 belongs to the deliberately isolated child shell.
    # shellcheck disable=SC2016
    if ! result=$(runuser --user "$user" -- /bin/sh -c \
        'if /usr/bin/test -r "$1"; then printf readable; else printf unreadable; fi' \
        sh "$path"); then
        die "$label access probe could not enter the mining identity"
    fi
    [[ $result == unreadable ]] || die "$label is readable by the mining identity"
}

require_untraversable_by_user() {
    local path=${1:?path is required}
    local user=${2:?user is required}
    local label=${3:-protected directory}
    require_command runuser
    [[ -d $path && ! -L $path ]] || die "$label is unavailable or unsafe"
    local result
    # $1 belongs to the deliberately isolated child shell.
    # shellcheck disable=SC2016
    if ! result=$(runuser --user "$user" -- /bin/sh -c \
        'if /usr/bin/test -x "$1"; then printf traversable; else printf untraversable; fi' \
        sh "$path"); then
        die "$label traversal probe could not enter the isolated identity"
    fi
    [[ $result == untraversable ]] \
        || die "$label is traversable by the isolated identity"
}

require_exact_user_groups() {
    local user=${1:?user is required}
    local expected=${2:?expected groups are required}
    require_command id
    local actual
    actual=$(id -Gn "$user" | tr ' ' '\n' | LC_ALL=C sort | paste -sd, -) \
        || die "could not establish service identity groups"
    [[ $actual == "$expected" ]] || die "service identity has unexpected group membership"
}

require_distinct_service_identities() {
    require_command id
    local identity uid gid seen_uids=, seen_gids=,
    for identity in \
        wcash-pool \
        wcash-pool-migrate \
        wcash-pool-projector \
        wcash-payout \
        wcash-pool-backend \
        zecwec-zallet \
        zecwec-zallet-recovery; do
        uid=$(id -u "$identity") || die "$identity UID is unavailable"
        gid=$(id -g "$identity") || die "$identity primary GID is unavailable"
        [[ $uid =~ ^[1-9][0-9]*$ && $gid =~ ^[1-9][0-9]*$ ]] \
            || die "service identities must use non-root numeric IDs"
        [[ $seen_uids != *",$uid,"* ]] \
            || die "service identities must use distinct numeric UIDs"
        [[ $seen_gids != *",$gid,"* ]] \
            || die "service identities must use distinct primary GIDs"
        seen_uids+="$uid,"
        seen_gids+="$gid,"
    done
}

require_no_processes_for_user() {
    local user=${1:?user is required}
    local label=${2:-service identity}
    require_command id
    require_command pgrep
    local uid pgrep_status
    uid=$(id -u "$user") || die "$label is unavailable"
    if pgrep -u "$uid" >/dev/null 2>&1; then
        die "$label has an active process outside the custody boundary"
    else
        pgrep_status=$?
    fi
    [[ $pgrep_status == 1 ]] || die "$label process inspection failed"
}

systemctl_value_strict() {
    local unit=${1:?unit is required}
    local field=${2:?systemd field is required}
    local value
    require_command systemctl
    value=$(systemctl show --property="$field" --value "$unit") \
        || die "could not inspect $field for $unit"
    [[ -n $value && $value != *$'\n'* ]] \
        || die "systemd returned an ambiguous $field for $unit"
    printf '%s\n' "$value"
}

require_inactive_unit_process_state() {
    local unit=${1:?unit is required}
    local field value
    require_command systemctl
    case $unit in
        *.service | *.target | *.timer | *.path) ;;
        *) die "unsupported managed systemd unit type: $unit" ;;
    esac
    for field in MainPID ControlPID; do
        value=$(systemctl show --property="$field" --value "$unit") \
            || die "could not inspect $field for $unit"
        [[ $value != *$'\n'* ]] \
            || die "systemd returned an ambiguous $field for $unit"
        case $unit in
            *.service)
                [[ $value == 0 ]] \
                    || die "$unit retains a service process"
                ;;
            *.target | *.timer | *.path)
                [[ -z $value || $value == 0 ]] \
                    || die "$unit returned an unexpected process identifier"
                ;;
        esac
    done
}

require_unit_without_dropins() {
    local unit=${1:?systemd unit is required}
    local paths
    require_command systemctl
    paths=$(systemctl show --property=DropInPaths --value "$unit") \
        || die "could not inspect systemd drop-ins for $unit"
    [[ $paths != *$'\n'* ]] \
        || die "systemd returned ambiguous drop-ins for $unit"
    [[ -z $paths ]] \
        || die "$unit has unmanaged systemd drop-ins; archive them before deployment"
}

require_loaded_unit_fully_inactive() {
    local unit=${1:?unit is required}
    [[ $(systemctl_value_strict "$unit" LoadState) == loaded \
        && $(systemctl_value_strict "$unit" ActiveState) == inactive \
        && $(systemctl_value_strict "$unit" SubState) == dead ]] \
        || die "$unit is not loaded and fully inactive"

    require_inactive_unit_process_state "$unit"
}

# Stop a unit when it exists, but allow an older release not to have introduced
# it yet. A masked, generated, or otherwise ambiguous unit is never treated as
# absent, and a real stop failure is fatal.
stop_loaded_unit_strict() {
    local unit=${1:?unit is required}
    local load_state active_state
    load_state=$(systemctl_value_strict "$unit" LoadState)
    case $load_state in
        loaded)
            active_state=$(systemctl_value_strict "$unit" ActiveState)
            case $active_state in
                active | inactive) ;;
                failed)
                    systemctl reset-failed "$unit" \
                        || die "could not clear the unit's failure state: $unit"
                    ;;
                *)
                    die "$unit has unexpected systemd active state: $active_state"
                    ;;
            esac
            systemctl stop "$unit" || die "could not stop loaded unit: $unit"
            require_loaded_unit_fully_inactive "$unit"
            ;;
        not-found) ;;
        *) die "$unit has unexpected systemd load state: $load_state" ;;
    esac
}

require_tcp_listener_absent() {
    local port=${1:?TCP port is required}
    local label=${2:-service}
    local listeners
    require_command ss
    [[ $port =~ ^[1-9][0-9]{0,4}$ && $port -le 65535 ]] \
        || die "$label TCP port is invalid"
    if ! listeners=$(ss -H -ltn "sport = :$port"); then
        die "$label listener inspection failed"
    fi
    [[ -z $listeners ]] || die "$label listener must be absent"
}

require_direct_origin_mtls_rejection() (
    local host=${1:?origin hostname is required}
    local address=${2:-127.0.0.1}
    [[ $host =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$ \
        && $host != *..* ]] || die "origin hostname is invalid"
    [[ $address =~ ^[0-9a-fA-F:.]+$ ]] || die "origin probe address is invalid"
    require_command curl
    require_command mktemp

    local scratch='' body='' errors='' metadata='' curl_status=0
    local http_status='' verify_result='' remaining=''
    scratch=$(mktemp -d)
    # Expand the mktemp-owned path now because an EXIT trap runs after local
    # function variables have left scope on the deployment host's Bash version.
    # shellcheck disable=SC2064
    trap "rm -rf -- $(printf '%q' "$scratch")" EXIT
    body=$scratch/body
    errors=$scratch/errors

    # Do not use --fail here: nginx can report a missing client certificate as
    # an explicit HTTP 400 on some TLS stacks. curl still verifies the server
    # certificate and records that result even when TLS 1.3 rejects the client
    # with a certificate_required alert.
    if metadata=$(curl --silent --show-error --max-time 10 --noproxy '*' \
        --header 'CF-Connecting-IP: 192.0.2.1' \
        --resolve "$host:443:$address" \
        --output "$body" \
        --write-out $'%{http_code}\n%{ssl_verify_result}\n' \
        "https://$host/healthz" 2>"$errors"); then
        curl_status=0
    else
        curl_status=$?
    fi
    [[ $metadata == *$'\n'* ]] \
        || die "direct origin probe returned invalid TLS metadata"
    http_status=${metadata%%$'\n'*}
    remaining=${metadata#*$'\n'}
    [[ $remaining != *$'\n'* ]] \
        || die "direct origin probe returned invalid TLS metadata"
    verify_result=$remaining
    [[ $http_status =~ ^[0-9]{3}$ && $verify_result =~ ^[0-9]+$ ]] \
        || die "direct origin probe returned invalid TLS metadata"
    [[ $verify_result == 0 ]] \
        || die "direct origin probe could not verify the server certificate"

    if ((curl_status != 0)); then
        grep -Eiq '(^|[^[:alpha:]])(tlsv[0-9.]+ alert )?certificate required([^[:alpha:]]|$)' \
            "$errors" \
            || die "direct origin probe failed without proving client-certificate rejection"
        return 0
    fi
    if [[ $http_status == 400 ]] \
        && grep -Fqi 'No required SSL certificate was sent' "$body"; then
        return 0
    fi
    die "direct origin did not explicitly reject the missing client certificate"
)

# Prove that a direct-ASIC certificate is usable before nginx is allowed to
# expose it.  File ownership alone is insufficient: an expired certificate, a
# certificate for another hostname, an incomplete chain, or a mismatched key
# would leave the advertised TLS endpoint unusable while the service appeared
# healthy.
require_public_tls_certificate() (
    local certificate=${1:?certificate path is required}
    local private_key=${2:?private key path is required}
    local hostname=${3:?certificate hostname is required}
    [[ $hostname =~ ^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$ \
        && $hostname == *.* && $hostname != *..* ]] \
        || die "TLS certificate hostname is invalid"
    require_command cmp
    require_command mktemp
    require_command openssl
    [[ -d /etc/ssl/certs && ! -L /etc/ssl/certs ]] \
        || die "system TLS trust store is unavailable"

    local scratch leaf certificate_key private_public_key
    scratch=$(mktemp -d)
    # Expand the mktemp-owned path now because an EXIT trap runs after local
    # function variables have left scope on the deployment host's Bash version.
    # shellcheck disable=SC2064
    trap "rm -rf -- $(printf '%q' "$scratch")" EXIT
    leaf=$scratch/leaf.pem
    certificate_key=$scratch/certificate-key.pem
    private_public_key=$scratch/private-key.pem

    openssl x509 -in "$certificate" -out "$leaf" \
        || die "mining TLS certificate could not be parsed"
    openssl x509 -in "$leaf" -noout -checkhost "$hostname" >/dev/null \
        || die "mining TLS certificate does not cover the configured hostname"
    openssl x509 -in "$leaf" -noout -checkend 604800 >/dev/null \
        || die "mining TLS certificate expires in less than seven days"
    openssl x509 -in "$leaf" -pubkey -noout >"$certificate_key" \
        || die "mining TLS certificate public key could not be read"
    openssl pkey -in "$private_key" -pubout >"$private_public_key" \
        || die "mining TLS private key could not be read"
    cmp -s -- "$certificate_key" "$private_public_key" \
        || die "mining TLS certificate and private key do not match"
    openssl verify \
        -purpose sslserver \
        -verify_hostname "$hostname" \
        -CApath /etc/ssl/certs \
        -untrusted "$certificate" \
        "$leaf" >/dev/null \
        || die "mining TLS certificate chain is not publicly trusted"
)

require_public_tls_listener() (
    local hostname=${1:?TLS hostname is required}
    local port=${2:?TLS port is required}
    local address=${3:-127.0.0.1}
    local expected_certificate=${4:?expected TLS certificate path is required}
    [[ $hostname =~ ^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$ \
        && $hostname == *.* && $hostname != *..* ]] \
        || die "TLS listener hostname is invalid"
    [[ $port =~ ^[1-9][0-9]{0,4}$ && $port -le 65535 ]] \
        || die "TLS listener port is invalid"
    [[ $address =~ ^[0-9a-fA-F:.]+$ ]] \
        || die "TLS listener address is invalid"
    require_command openssl
    require_command cmp
    require_command mktemp
    require_command timeout
    [[ -d /etc/ssl/certs && ! -L /etc/ssl/certs ]] \
        || die "system TLS trust store is unavailable"
    local scratch handshake expected_der served_der served_leaf
    scratch=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf -- $(printf '%q' "$scratch")" EXIT
    handshake=$scratch/handshake.pem
    expected_der=$scratch/expected.der
    served_der=$scratch/served.der
    served_leaf=$scratch/served-leaf.pem
    timeout --signal=TERM --kill-after=2s 15s \
        openssl s_client \
        -connect "$address:$port" \
        -servername "$hostname" \
        -showcerts \
        -verify_hostname "$hostname" \
        -verify_return_error \
        -CApath /etc/ssl/certs \
        </dev/null >"$handshake" 2>/dev/null \
        || die "TLS listener did not present a publicly trusted certificate for the configured hostname"
    openssl x509 -in "$handshake" -out "$served_leaf" \
        || die "TLS listener response did not contain a certificate"
    openssl x509 -in "$served_leaf" -noout -checkend 604800 >/dev/null \
        || die "live mining TLS certificate expires in less than seven days"
    openssl x509 -in "$expected_certificate" -outform DER -out "$expected_der" \
        || die "configured mining TLS certificate could not be encoded"
    openssl x509 -in "$served_leaf" -outform DER -out "$served_der" \
        || die "live mining TLS certificate could not be encoded"
    cmp -s -- "$expected_der" "$served_der" \
        || die "TLS listener did not present the configured mining certificate"
)

require_cleanup_trees_safe() {
    (($# > 0)) || die "cleanup tree is required"
    local unsupported_entries multiply_linked_entries
    require_command find
    if ! unsupported_entries=$(find "$@" \
        \( -type l -o ! -type d ! -type f \) -print -quit); then
        die "custody cleanup target file types cannot be inspected"
    fi
    [[ -z $unsupported_entries ]] \
        || die "custody cleanup target contains an unsupported file type"
    if ! multiply_linked_entries=$(find "$@" \
        -type f ! -links 1 -print -quit); then
        die "custody cleanup target link counts cannot be inspected"
    fi
    [[ -z $multiply_linked_entries ]] \
        || die "custody cleanup target contains a multiply linked file"
}

require_exact_immediate_entries() {
    local directory=${1:?directory is required}
    local expected=${2-}
    local label=${3:-directory}
    local paths path name sorted_entries
    local entries=''
    require_command find
    if ! paths=$(find "$directory" -mindepth 1 -maxdepth 1 -print); then
        die "$label entries cannot be inspected"
    fi
    if [[ -n $paths ]]; then
        while IFS= read -r path; do
            [[ $path == "$directory/"* ]] \
                || die "$label returned an entry outside its boundary"
            name=${path#"$directory/"}
            [[ -n $name && $name != */* ]] \
                || die "$label returned an ambiguous immediate entry"
            entries+="$name"$'\n'
        done <<<"$paths"
        entries=${entries%$'\n'}
    fi
    sorted_entries=$(printf '%s' "$entries" | LC_ALL=C sort) \
        || die "$label entries cannot be sorted"
    [[ $sorted_entries == "$expected" ]] || die "$label contains unexpected entries"
}

require_deployment_source_tree_safe() {
    local root=${1:?deployment source root is required}
    local matches
    require_command find
    [[ -d $root/deploy && -d $root/scripts && -d $root/docs ]] \
        || die "deployment source tree is incomplete"
    if ! matches=$(find "$root/deploy" "$root/scripts" "$root/docs" \
        -type l -print -quit); then
        die "deployment source symbolic links cannot be inspected"
    fi
    [[ -z $matches ]] || die "deployment source must not contain symbolic links"
    if ! matches=$(find "$root/deploy" "$root/scripts" "$root/docs" \
        ! -type d ! -type f -print -quit); then
        die "deployment source file types cannot be inspected"
    fi
    [[ -z $matches ]] || die "deployment source contains an unsupported file type"
    if ! matches=$(find "$root/deploy" "$root/scripts" "$root/docs" \
        \( -type d -name __pycache__ \
        -o -type f \( -name '*.pyc' -o -name '*.pyo' \) \) -print -quit); then
        die "deployment source Python cache state cannot be inspected"
    fi
    [[ -z $matches ]] \
        || die "deployment source contains Python bytecode or cache directories"
}

stop_backend_units_for_zec_sealing() {
    local unit
    require_command systemctl
    for unit in \
        zecwec-testnet-pool-start.service \
        wcash-pool-health.timer \
        wcash-pool-health.service \
        zecwec-cookie-refresh.path \
        zecwec-cookie-refresh.service \
        zecwec-testnet-pool.target \
        wcash-pool-custody-gate.service \
        wcash-pool.service \
        wcash-pool-projector.service \
        wcash-payout-worker.service \
        zecwec-zallet-payout.service \
        wcash-pool-backend.service \
        wcash-pool-backend-init.service \
        wcash-pool-migrate.service \
        wcash-pool-preflight.service; do
        [[ $(systemctl_value_strict "$unit" LoadState) == loaded ]] \
            || die "backend-capable service is missing or not loaded"
        systemctl stop "$unit" >/dev/null 2>&1 \
            || die "could not stop a backend-capable service before sealing"
        require_loaded_unit_fully_inactive "$unit"
    done
    require_no_processes_for_user wcash-pool-backend "backend identity"
}

require_sealed_wcash_custody() {
    local seed=${1:?seed path is required}
    local authority=${2:?authority path is required}
    local attestation=${3:?attestation path is required}
    local parent authority_parent
    parent=$(dirname -- "$seed")
    authority_parent=$(dirname -- "$authority")
    [[ -d $parent && ! -L $parent \
        && $(stat -c '%U:%G:%a' -- "$parent") == root:root:700 ]] \
        || die "sealed Wcash custody directory is unsafe"
    [[ -f $seed && ! -L $seed \
        && $(stat -c '%U:%G:%a:%h' -- "$seed") == root:root:400:1 ]] \
        || die "sealed Wcash seed is unsafe"
    [[ -f $attestation && ! -L $attestation \
        && $(stat -c '%U:%G:%a:%h' -- "$attestation") == root:root:400:1 ]] \
        || die "Wcash recovery attestation is unsafe"
    [[ -d $authority_parent && ! -L $authority_parent \
        && $(stat -c '%U:%G:%a' -- "$authority_parent") == \
            wcash-payout:wcash-payout:700 ]] \
        || die "frozen Wcash authority parent is unsafe"
    [[ -f $authority && ! -L $authority \
        && $(stat -c '%U:%G:%a:%h' -- "$authority") == \
            root:wcash-payout:440:1 ]] \
        || die "frozen Wcash authority is unsafe"
    require_unreadable_by_user "$parent" wcash-pool "sealed Wcash custody directory"
    require_unreadable_by_user "$seed" wcash-pool "sealed Wcash seed"
    local isolated_identity
    for isolated_identity in wcash-pool wcash-pool-projector wcash-pool-backend; do
        require_untraversable_by_user "$authority_parent" "$isolated_identity" \
            "frozen Wcash authority parent"
        require_unreadable_by_user "$authority" "$isolated_identity" \
            "frozen Wcash authority"
    done
    python3 "$(dirname -- "${BASH_SOURCE[0]}")/verify-wcash-wallet-recovery.py" \
        verify "$authority" "$attestation"
}

require_hot_testnet_payout_custody() {
    local settings=${1:?settings path is required}
    local release_root=${2:-${ZECWEC_RELEASE_PATH:-}}
    local wcash_seed wcash_authority wcash_recovery_attestation
    local payout_state zallet_state zallet_config zallet_payout_config
    local zallet_identity zallet_identity_credential zallet_recovery_state
    local zallet_recovery_config zec_custody zec_original zec_recovered
    local zec_recovery_attestation zec_initial_zero zec_initial_zero_attestation
    local zec_recovery_verifier native_validator
    [[ $release_root == /opt/wcash/releases/* \
        && -d $release_root && ! -L $release_root \
        && $(realpath -e -- "$release_root") == "$release_root" ]] \
        || die "payout custody gate requires one immutable release root"
    require_exact_user_groups wcash-pool wcash-pool,wcash-pool-socket
    require_exact_user_groups wcash-pool-migrate wcash-pool-migrate
    require_exact_user_groups wcash-pool-projector wcash-pool-projector,wcash-pool-socket
    require_exact_user_groups wcash-payout wcash-payout,wcash-pool-socket
    require_exact_user_groups wcash-pool-backend wcash-pool-backend,wcash-pool-socket
    require_exact_user_groups zecwec-zallet zecwec-zallet
    require_exact_user_groups zecwec-zallet-recovery zecwec-zallet-recovery
    require_distinct_service_identities
    wcash_seed=$(read_setting "$settings" WEC_SEED_FILE)
    wcash_authority=/var/lib/wcash-payout/wcash-wallet-authority.json
    wcash_recovery_attestation=/var/lib/wcash-pool-secrets/wcash-wallet-recovery.attestation
    require_sealed_wcash_custody \
        "$wcash_seed" "$wcash_authority" "$wcash_recovery_attestation"
    payout_state=$(read_setting "$settings" PAYOUT_STATE_DIR)
    [[ $payout_state == /var/lib/wcash-payout && -d $payout_state && ! -L $payout_state \
        && $(stat -c '%U:%G:%a' -- "$payout_state") == wcash-payout:wcash-payout:700 ]] \
        || die "payout worker state directory is unsafe"
    require_unreadable_by_user "$payout_state" wcash-pool "payout worker state"
    zallet_state=$(read_setting "$settings" ZALLET_STATE_DIR)
    zallet_config=$(read_setting "$settings" ZALLET_CONFIG_FILE)
    zallet_payout_config=/etc/wcash-pool/zallet-payout.toml
    zallet_identity=$zallet_state/encryption-identity.txt
    zallet_identity_credential=$(read_setting "$settings" ZALLET_ENCRYPTION_IDENTITY_CREDENTIAL)
    zallet_recovery_state=/var/lib/zecwec-zallet-recovery
    zallet_recovery_config=/etc/wcash-pool/zallet-recovery.toml
    [[ $zallet_state == /var/lib/zecwec-zallet && -d $zallet_state && ! -L $zallet_state \
        && $(stat -c '%U:%G:%a' -- "$zallet_state") == zecwec-zallet:zecwec-zallet:700 ]] \
        || die "Zallet state directory is unsafe"
    [[ $zallet_config == /etc/wcash-pool/zallet.toml \
        && -f $zallet_config && ! -L $zallet_config \
        && $(stat -c '%U:%G:%a:%h' -- "$zallet_config") == root:zecwec-zallet:640:1 ]] \
        || die "bootstrap Zallet configuration is unsafe"
    [[ -f $zallet_payout_config && ! -L $zallet_payout_config \
        && $(stat -c '%U:%G:%a:%h' -- "$zallet_payout_config") == \
            root:zecwec-zallet:640:1 ]] \
        || die "payout Zallet configuration is unsafe"
    require_command runuser
    runuser --user zecwec-zallet -- /usr/bin/test -r "$zallet_config" \
        || die "bootstrap Zallet configuration is unreadable by its service identity"
    runuser --user zecwec-zallet -- /usr/bin/test -r "$zallet_payout_config" \
        || die "payout Zallet configuration is unreadable by its service identity"
    require_unreadable_by_user "$zallet_state" wcash-pool "Zallet state"
    require_unreadable_by_user "$zallet_config" wcash-pool "bootstrap Zallet configuration"
    require_unreadable_by_user "$zallet_payout_config" wcash-pool \
        "payout Zallet configuration"
    [[ ! -e $zallet_identity && ! -L $zallet_identity ]] \
        || die "Zallet state contains an unsealed decryption identity"
    [[ $zallet_identity_credential == /etc/wcash-pool/credentials/zallet-encryption-identity \
        && -f $zallet_identity_credential && ! -L $zallet_identity_credential \
        && $(stat -c '%U:%G:%a:%h' -- "$zallet_identity_credential") == root:root:400:1 ]] \
        || die "sealed Zallet payout identity credential is unavailable or unsafe"
    require_unreadable_by_user "$zallet_identity_credential" wcash-pool \
        "sealed Zallet payout identity"
    require_unreadable_by_user "$zallet_identity_credential" zecwec-zallet \
        "sealed Zallet payout identity source"
    [[ ! -e $zallet_recovery_state && ! -L $zallet_recovery_state ]] \
        || die "isolated Zallet recovery state must be removed before mining"
    [[ -f $zallet_recovery_config && ! -L $zallet_recovery_config \
        && $(stat -c '%U:%G:%a:%h' -- "$zallet_recovery_config") == \
            root:zecwec-zallet-recovery:640:1 ]] \
        || die "Zallet recovery configuration is unsafe"
    require_unreadable_by_user "$zallet_state" zecwec-zallet-recovery \
        "original Zallet state"

    zec_custody=/var/lib/zecwec-custody
    zec_original=$zec_custody/zec-wallet-original.rpc.json
    zec_recovered=$zec_custody/zec-wallet-recovered.rpc.json
    zec_recovery_attestation=$zec_custody/zec-wallet-recovery.attestation.json
    zec_initial_zero=$zec_custody/zec-collector-initial-zero.json
    zec_initial_zero_attestation=$zec_custody/zec-collector-initial-zero.attestation
    zec_recovery_verifier=$release_root/deployment/scripts/deploy/verify-zec-wallet-recovery.py
    native_validator=$release_root/wcash-poold
    [[ -d $zec_custody && ! -L $zec_custody \
        && $(stat -c '%U:%G:%a' -- "$zec_custody") == root:root:700 ]] \
        || die "Zcash recovery custody directory is unsafe"
    local custody_entries expected_entries
    require_command find
    custody_entries=$(find "$zec_custody" -mindepth 1 -maxdepth 1 -printf '%f\n' \
        | LC_ALL=C sort) || die "Zcash recovery custody contents cannot be inspected"
    expected_entries=$(printf '%s\n' \
        zec-collector-initial-zero.attestation \
        zec-collector-initial-zero.json \
        zec-wallet-original.rpc.json \
        zec-wallet-recovered.rpc.json \
        zec-wallet-recovery.attestation.json \
        | LC_ALL=C sort)
    [[ $custody_entries == "$expected_entries" ]] \
        || die "Zcash recovery custody contains unsealed or unexpected material"
    local evidence
    for evidence in \
        "$zec_original" \
        "$zec_recovered" \
        "$zec_recovery_attestation" \
        "$zec_initial_zero" \
        "$zec_initial_zero_attestation"; do
        [[ -f $evidence && ! -L $evidence \
            && $(stat -c '%U:%G:%a:%h' -- "$evidence") == root:root:400:1 ]] \
            || die "Zcash recovery evidence is unavailable or unsafe"
    done
    [[ -x $zec_recovery_verifier && ! -L $zec_recovery_verifier \
        && -x $native_validator && ! -L $native_validator ]] \
        || die "immutable Zcash recovery authority is unavailable"
    require_unreadable_by_user "$zec_custody" wcash-pool \
        "Zcash recovery custody directory"
    require_unreadable_by_user "$zec_custody" zecwec-zallet \
        "Zcash recovery custody directory"
    require_unreadable_by_user "$zec_custody" zecwec-zallet-recovery \
        "Zcash recovery custody directory"
    python3 "$zec_recovery_verifier" verify \
        "$settings" "$zec_original" "$zec_recovered" \
        "$zec_recovery_attestation" "$native_validator"
    ZECWEC_RELEASE_PATH=$release_root \
    ZEC_AUTHORITY_CONFIG=/etc/wcash-pool/zec-authority.testnet.toml \
    ZEC_AUTHORITY_RESULT=$zec_initial_zero \
    ZEC_AUTHORITY_ATTESTATION=$zec_initial_zero_attestation \
        "$release_root/deployment/scripts/deploy/zec-authority-bootstrap.sh" \
        verify-sealed
}

# Kept as a compatibility name for older operator scripts. The gate now proves
# isolated hot Testnet payout custody, not an offline/deferred runtime.
require_offline_collector_custody() {
    require_hot_testnet_payout_custody "$@"
}

require_absolute_path() {
    local path=${1:?path is required}
    [[ $path == /* ]] || die "path must be absolute"
    [[ $path != *'/../'* && $path != *'/./'* && $path != */.. && $path != */. ]] \
        || die "path must be lexically normalized"
}

require_safe_name() {
    local value=${1:?value is required}
    local label=${2:-name}
    [[ $value =~ ^[A-Za-z_][A-Za-z0-9_.-]{0,62}$ ]] \
        || die "$label has an unsafe representation"
}

resolve_release_root() {
    local candidate=${1:-$ZECWEC_CURRENT_RELEASE}
    require_absolute_path "$candidate"
    [[ -e $candidate || -L $candidate ]] || die "selected release is unavailable"
    local resolved
    resolved=$(realpath -e -- "$candidate")
    [[ $resolved =~ ^/opt/wcash/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ \
        && -d $resolved && ! -L $resolved ]] \
        || die "selected release is not one canonical immutable version directory"
    printf '%s' "$resolved"
}

require_private_regular_file() {
    local path=${1:?path is required}
    require_absolute_path "$path"
    [[ -f $path && ! -L $path ]] || die "protected input is not a regular file"
    local mode owner links
    mode=$(stat -c '%a' -- "$path")
    owner=$(stat -c '%u' -- "$path")
    links=$(stat -c '%h' -- "$path")
    [[ $owner == 0 && $mode == 600 && $links == 1 ]] \
        || die "protected input must be root-owned, mode 0600, with one link"
}

require_trusted_etc_file() {
    local path=${1:?path is required}
    local private=${2:-false}
    require_absolute_path "$path"
    [[ $path == /etc/* && -f $path ]] || die "trusted file must resolve below /etc"
    local resolved
    resolved=$(realpath -e -- "$path")
    [[ $resolved == /etc/* && -f $resolved && ! -L $resolved ]] \
        || die "trusted file resolves outside /etc or is not regular"
    local owner mode links forbidden
    owner=$(stat -Lc '%u' -- "$path")
    mode=$(stat -Lc '%a' -- "$path")
    links=$(stat -Lc '%h' -- "$path")
    forbidden=022
    $private && forbidden=077
    [[ $owner == 0 && $links == 1 && $mode =~ ^[0-7]{3,4}$ \
        && $((8#$mode & 8#$forbidden)) -eq 0 ]] \
        || die "trusted file ownership, mode, or link count is unsafe"
}

install_private_file() {
    local source=${1:?source is required}
    local destination=${2:?destination is required}
    local owner=${3:?owner is required}
    local group=${4:?group is required}
    require_private_regular_file "$source"
    require_absolute_path "$destination"
    install -d -o root -g root -m 0700 -- "$(dirname -- "$destination")"
    local temporary="${destination}.new.$$"
    if ! install -o "$owner" -g "$group" -m 0600 -- "$source" "$temporary"; then
        rm -f -- "$temporary"
        die "failed to stage protected file"
    fi
    if ! mv -fT -- "$temporary" "$destination"; then
        rm -f -- "$temporary"
        die "failed to install protected file"
    fi
}

read_one_line_credential() {
    local path=${1:?credential path is required}
    local maximum=${2:-4096}
    [[ -f $path && ! -L $path ]] || die "credential is unavailable"
    local size
    size=$(stat -c '%s' -- "$path")
    ((size > 0 && size <= maximum)) || die "credential has an invalid size"
    local value extra
    IFS= read -r value <"$path" || [[ -n $value ]] || die "credential is empty"
    extra=$(tail -n +2 -- "$path")
    [[ -z $extra ]] || die "credential must contain exactly one line"
    [[ $value != *[$'\r\n\t']* ]] || die "credential contains control characters"
    printf '%s' "$value"
}

read_setting() {
    local path=${1:?settings path is required}
    local key=${2:?settings key is required}
    [[ $key =~ ^[A-Z][A-Z0-9_]*$ ]] || die "settings key is invalid"
    local count value
    count=$(awk -F= -v key="$key" '$1 == key { count += 1 } END { print count + 0 }' "$path")
    [[ $count == 1 ]] || die "settings key must occur exactly once: $key"
    value=$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$path")
    [[ -n $value && $value != *[$'\r\n\t']* ]] || die "settings value is invalid: $key"
    printf '%s' "$value"
}
