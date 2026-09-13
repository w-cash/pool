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

[[ $# -eq 1 ]] || die "usage: provision-host.sh <deployment-source-root>"
source_root=$1
require_absolute_path "$source_root"
[[ -d $source_root/deploy && -d $source_root/scripts/deploy && -d $source_root/docs ]] \
    || die "deployment source root is incomplete"
if find "$source_root/deploy" "$source_root/scripts/deploy" "$source_root/docs" \
    -type l -print -quit | grep -q .; then
    die "deployment source trees must not contain symbolic links"
fi

getent group wcash-pool-socket >/dev/null || groupadd --system wcash-pool-socket
getent group wcash-pool >/dev/null || groupadd --system wcash-pool
getent group zecwec-zallet >/dev/null || groupadd --system zecwec-zallet

id -u wcash-pool >/dev/null 2>&1 \
    || useradd --system --gid wcash-pool --home-dir /var/lib/wcash-pool --shell /usr/sbin/nologin wcash-pool
id -u wcash-pool-backend >/dev/null 2>&1 \
    || useradd --system --gid wcash-pool-socket --home-dir /var/lib/wcash-pool-backend --shell /usr/sbin/nologin wcash-pool-backend
id -u zecwec-zallet >/dev/null 2>&1 \
    || useradd --system --gid zecwec-zallet --home-dir /var/lib/zecwec-zallet --shell /usr/sbin/nologin zecwec-zallet

usermod --gid wcash-pool --groups wcash-pool-socket wcash-pool
usermod --gid wcash-pool-socket --groups '' wcash-pool-backend
usermod --gid zecwec-zallet --groups '' zecwec-zallet

install -d -o root -g root -m 0755 /opt/wcash /opt/wcash/releases
install -d -o root -g root -m 0755 /usr/local/share/zecwec-deploy "$ZECWEC_LIBEXEC"
install -d -o root -g root -m 0755 "$ZECWEC_CONFIG_DIR"
install -d -o root -g root -m 0700 "$ZECWEC_CREDENTIAL_DIR"
install -d -o root -g root -m 0755 "$ZECWEC_CONFIG_DIR/tls"
install -d -o wcash-pool -g wcash-pool -m 0700 /var/lib/wcash-pool
install -d -o wcash-pool-backend -g wcash-pool-socket -m 0700 /var/lib/wcash-pool-backend
install -d -o root -g root -m 0700 /var/lib/zecwec-custody
wcash_seed=/var/lib/wcash-pool-secrets/wcash-seed
if [[ -e $wcash_seed || -L $wcash_seed ]]; then
    [[ -f $wcash_seed && ! -L $wcash_seed ]] \
        || die "existing Wcash seed is unsafe"
    case $(stat -c '%U:%G:%a:%h' -- "$wcash_seed") in
        wcash-pool:wcash-pool:600:1)
            install -d -o root -g wcash-pool -m 0710 /var/lib/wcash-pool-secrets
            ;;
        root:root:400:1)
            install -d -o root -g root -m 0700 /var/lib/wcash-pool-secrets
            ;;
        *) die "existing Wcash seed ownership or mode is unsafe" ;;
    esac
else
    install -d -o root -g wcash-pool -m 0710 /var/lib/wcash-pool-secrets
fi
install -d -o zecwec-zallet -g zecwec-zallet -m 0700 /var/lib/zecwec-zallet

for directory in deploy scripts docs; do
    cp -a -- "$source_root/$directory" "/usr/local/share/zecwec-deploy/"
done
find /usr/local/share/zecwec-deploy -type d -exec chmod 0755 {} +
find /usr/local/share/zecwec-deploy -type f -exec chmod 0644 {} +
find /usr/local/share/zecwec-deploy/scripts -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod 0555 {} +
for executable in /usr/local/share/zecwec-deploy/scripts/deploy/*.sh /usr/local/share/zecwec-deploy/scripts/deploy/*.py; do
    ln -sfn -- "$executable" "$ZECWEC_LIBEXEC/$(basename -- "$executable")"
done

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
