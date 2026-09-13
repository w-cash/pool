#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command getent
require_command groupadd
require_command useradd
require_command usermod
require_command openssl
require_command python3

[[ $# -eq 1 ]] || die "usage: provision-host.sh <deployment-source-root>"
source_root=$1
require_absolute_path "$source_root"
[[ -d $source_root/deploy && -d $source_root/scripts/deploy && -d $source_root/docs \
    && -d $source_root/patches/zallet-v0.1.0-beta.3 ]] \
    || die "deployment source root is incomplete"
require_deployment_source_tree_safe "$source_root"
expected_zallet_patch_entries=$(printf '%s\n' \
    0001-reserve-wallet-database-capacity.patch \
    0002-signal-data-requests-after-chain-writes.patch \
    0003-remove-nonreproducible-shadow-paths.patch \
    0004-observe-batch-decryptor-shutdown.patch \
    README.md \
    librustzcash-1f6bb207-recovery-tip-gate.patch \
    zewif-zcashd-0.1.0-rc.5-relocatable-db-dump.patch | LC_ALL=C sort)
zallet_patch_source="$source_root/patches/zallet-v0.1.0-beta.3"
require_exact_immediate_entries \
    "$zallet_patch_source" "$expected_zallet_patch_entries" "Zallet patch source"
if ! unsupported_patch_entry=$(find "$zallet_patch_source" -mindepth 1 \
    \( -type l -o ! -type f \) -print -quit); then
    die "Zallet patch source file types cannot be inspected"
fi
[[ -z $unsupported_patch_entry ]] || die "Zallet patch source contains an unsafe file"

getent group wcash-pool-socket >/dev/null || groupadd --system wcash-pool-socket
getent group wcash-pool >/dev/null || groupadd --system wcash-pool
getent group wcash-pool-backend >/dev/null || groupadd --system wcash-pool-backend
getent group wcash-pool-migrate >/dev/null || groupadd --system wcash-pool-migrate
getent group wcash-pool-projector >/dev/null || groupadd --system wcash-pool-projector
getent group wcash-payout >/dev/null || groupadd --system wcash-payout
getent group zecwec-zallet >/dev/null || groupadd --system zecwec-zallet
getent group zecwec-zallet-recovery >/dev/null || groupadd --system zecwec-zallet-recovery

id -u wcash-pool >/dev/null 2>&1 \
    || useradd --system --gid wcash-pool --home-dir /var/lib/wcash-pool --shell /usr/sbin/nologin wcash-pool
id -u wcash-pool-migrate >/dev/null 2>&1 \
    || useradd --system --gid wcash-pool-migrate --home-dir /nonexistent \
        --shell /usr/sbin/nologin wcash-pool-migrate
id -u wcash-pool-projector >/dev/null 2>&1 \
    || useradd --system --gid wcash-pool-projector --home-dir /var/lib/wcash-pool-projector --shell /usr/sbin/nologin wcash-pool-projector
id -u wcash-payout >/dev/null 2>&1 \
    || useradd --system --gid wcash-payout --home-dir /var/lib/wcash-payout --shell /usr/sbin/nologin wcash-payout
id -u wcash-pool-backend >/dev/null 2>&1 \
    || useradd --system --gid wcash-pool-backend \
        --home-dir /var/lib/wcash-pool-backend --shell /usr/sbin/nologin \
        wcash-pool-backend
id -u zecwec-zallet >/dev/null 2>&1 \
    || useradd --system --gid zecwec-zallet --home-dir /var/lib/zecwec-zallet --shell /usr/sbin/nologin zecwec-zallet
id -u zecwec-zallet-recovery >/dev/null 2>&1 \
    || useradd --system --gid zecwec-zallet-recovery \
        --home-dir /var/lib/zecwec-zallet-recovery --shell /usr/sbin/nologin \
        zecwec-zallet-recovery

usermod --gid wcash-pool --groups wcash-pool-socket wcash-pool
usermod --gid wcash-pool-migrate --groups '' wcash-pool-migrate
usermod --gid wcash-pool-projector --groups wcash-pool-socket wcash-pool-projector
usermod --gid wcash-payout --groups wcash-pool-socket wcash-payout
usermod --gid wcash-pool-backend --groups wcash-pool-socket wcash-pool-backend
usermod --gid zecwec-zallet --groups '' zecwec-zallet
usermod --gid zecwec-zallet-recovery --groups '' zecwec-zallet-recovery
require_distinct_service_identities

python3 - <<'PY'
import pexpect

try:
    version = tuple(int(part) for part in pexpect.__version__.split("."))
except (AttributeError, ValueError):
    raise SystemExit("provision-host: pexpect version is invalid")
if version < (4, 8):
    raise SystemExit("provision-host: pexpect 4.8 or newer is required")
PY

install -d -o root -g root -m 0755 /opt/wcash /opt/wcash/releases
install -d -o root -g root -m 0755 /usr/local/share "$ZECWEC_LIBEXEC"
install -d -o root -g root -m 0755 "$ZECWEC_CONFIG_DIR"
install -d -o root -g root -m 0700 "$ZECWEC_CREDENTIAL_DIR"
install -d -o root -g root -m 0755 "$ZECWEC_CONFIG_DIR/tls"
install -d -o wcash-pool -g wcash-pool -m 0700 /var/lib/wcash-pool
install -d -o wcash-pool-projector -g wcash-pool-projector -m 0700 /var/lib/wcash-pool-projector
install -d -o wcash-payout -g wcash-payout -m 0700 /var/lib/wcash-payout
install -d -o wcash-pool-backend -g wcash-pool-socket -m 0700 /var/lib/wcash-pool-backend
install -d -o root -g root -m 0700 /var/lib/zecwec-custody
wcash_seed=/var/lib/wcash-pool-secrets/wcash-seed
if [[ -e $wcash_seed || -L $wcash_seed ]]; then
    [[ -f $wcash_seed && ! -L $wcash_seed ]] \
        || die "existing Wcash seed is unsafe"
    case $(stat -c '%U:%G:%a:%h' -- "$wcash_seed") in
        wcash-pool:wcash-pool:600:1 | wcash-payout:wcash-payout:600:1)
            install -d -o root -g wcash-payout -m 0710 /var/lib/wcash-pool-secrets
            ;;
        root:root:400:1)
            install -d -o root -g root -m 0700 /var/lib/wcash-pool-secrets
            ;;
        *) die "existing Wcash seed ownership or mode is unsafe" ;;
    esac
else
    install -d -o root -g wcash-payout -m 0710 /var/lib/wcash-pool-secrets
fi
install -d -o zecwec-zallet -g zecwec-zallet -m 0700 /var/lib/zecwec-zallet

deployment_destination=/usr/local/share/zecwec-deploy
deployment_staging=$(mktemp -d /usr/local/share/.zecwec-deploy.new.XXXXXX) \
    || die "cannot create deployment-source staging directory"
deployment_previous=
cleanup_provision_staging() {
    local tree
    for tree in "$deployment_staging" "$deployment_previous"; do
        [[ -n $tree && -d $tree && ! -L $tree ]] || continue
        [[ $tree =~ ^/usr/local/share/\.zecwec-deploy\.(new\.[A-Za-z0-9]+|previous\.[0-9]+)$ ]] \
            || die "refusing to clean an unexpected deployment staging path"
        find "$tree" -xdev -depth -delete \
            || die "cannot remove obsolete deployment staging state"
    done
}
trap cleanup_provision_staging EXIT
chmod 0755 -- "$deployment_staging"
for directory in deploy scripts docs patches; do
    cp -a -- "$source_root/$directory" "$deployment_staging/"
done
find "$deployment_staging" -type d -exec chmod 0755 {} +
find "$deployment_staging" -type f -exec chmod 0644 {} +
find "$deployment_staging/scripts" -type f \( -name '*.sh' -o -name '*.py' \) \
    -exec chmod 0555 {} +
require_deployment_source_tree_safe "$deployment_staging"
require_exact_immediate_entries \
    "$deployment_staging" \
    "$(printf '%s\n' deploy docs patches scripts | LC_ALL=C sort)" \
    "installed deployment source staging"

if [[ -e $deployment_destination || -L $deployment_destination ]]; then
    [[ -d $deployment_destination && ! -L $deployment_destination ]] \
        || die "existing deployment source is not a real directory"
    deployment_previous="/usr/local/share/.zecwec-deploy.previous.$$"
    [[ ! -e $deployment_previous && ! -L $deployment_previous ]] \
        || die "deployment-source replacement path already exists"
    mv -T -- "$deployment_destination" "$deployment_previous"
fi
if ! mv -T -- "$deployment_staging" "$deployment_destination"; then
    if [[ -n $deployment_previous && ! -e $deployment_destination ]]; then
        mv -T -- "$deployment_previous" "$deployment_destination" \
            || die "deployment-source install and restoration both failed"
        deployment_previous=
    fi
    die "cannot install the exact deployment source snapshot"
fi
deployment_staging=

if ! unsupported_libexec_entry=$(find "$ZECWEC_LIBEXEC" -mindepth 1 -maxdepth 1 \
    ! -type l -print -quit); then
    die "deployment command links cannot be inspected"
fi
[[ -z $unsupported_libexec_entry ]] \
    || die "deployment command directory contains a non-link entry"
find "$ZECWEC_LIBEXEC" -mindepth 1 -maxdepth 1 -type l -delete \
    || die "stale deployment command links cannot be removed"
for executable in "$deployment_destination"/scripts/deploy/*.sh \
    "$deployment_destination"/scripts/deploy/*.py; do
    ln -s -- "$executable" "$ZECWEC_LIBEXEC/$(basename -- "$executable")"
done
cleanup_provision_staging
deployment_previous=
trap - EXIT

for secret in portal-token-pepper portal-totp-key; do
    destination="$ZECWEC_CREDENTIAL_DIR/$secret"
    if [[ ! -e $destination ]]; then
        temporary="${destination}.new.$$"
        umask 077
        openssl rand 32 >"$temporary"
        install -o root -g root -m 0600 "$temporary" "$destination"
        rm -f -- "$temporary"
    fi
    require_private_regular_file "$destination"
    [[ $(stat -c '%s' -- "$destination") -eq 32 ]] || die "$secret must contain exactly 32 bytes"
done

log "host identities and protected directories are ready; no service was installed, enabled, or started"
