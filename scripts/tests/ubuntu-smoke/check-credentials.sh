#!/usr/bin/env bash
set -Eeuo pipefail
set +x

[[ -f /.dockerenv && -f /etc/zecwec-disposable-smoke \
    && ! -e /etc/wcash-pool/deployment.env ]] || {
    printf 'Run only in the disposable smoke-test image\n' >&2
    exit 1
}
# systemd 249 moves credential mounts from a helper namespace. Docker's
# private /run tmpfs otherwise hides that mount even from a one-command unit.
mount --make-shared /run
id wcash-smoke >/dev/null 2>&1 || useradd --system --no-create-home wcash-smoke
install -d -o wcash-smoke -g wcash-smoke -m 0700 /run/wcash-credential-smoke

# Run inside the disposable Ubuntu 22.04 systemd container. The binary fixture
# checks process ordering and actual LoadCredential lifetime, not mining logic.
install -d -m 0755 /opt/wcash/releases/credential-test /etc/wcash-pool
install -d -m 0700 /etc/wcash-pool/credentials
printf '%s' 'disposable-credential-fixture' >/etc/wcash-pool/credentials/smoke
chmod 0600 /etc/wcash-pool/credentials/smoke
cp /workspace/scripts/deploy/{common.sh,pool-entrypoint.sh} /opt/wcash/releases/credential-test/
cat >/opt/wcash/releases/credential-test/wcash-poold <<'FIXTURE'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ ! -r $CREDENTIALS_DIRECTORY/smoke ]]; then
    printf 'fixture credential unavailable during %s\n' "$1" >&2
    exit 1
fi
if [[ $(cat "$CREDENTIALS_DIRECTORY/smoke") != disposable-credential-fixture ]]; then
    printf 'fixture credential mismatch during %s\n' "$1" >&2
    exit 1
fi
[[ ! -w $CREDENTIALS_DIRECTORY/smoke ]]
printf '%s\n' "$1" >>/run/wcash-credential-smoke/order
if [[ -f /run/wcash-credential-smoke/fail \
    && $(cat /run/wcash-credential-smoke/fail) == "$1" ]]; then
    exit 9
fi
FIXTURE
chmod 0755 /opt/wcash/releases/credential-test/{wcash-poold,pool-entrypoint.sh}

for mode in preflight serve; do
    if [[ $mode == preflight ]]; then unit=wcash-pool-preflight.service; else unit=wcash-pool.service; fi
    cat >"/etc/systemd/system/$unit" <<UNIT
[Unit]
Description=Disposable credential-lifetime smoke test
[Service]
Type=oneshot
User=wcash-smoke
Group=wcash-smoke
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
PrivateMounts=true
ReadWritePaths=/run/wcash-credential-smoke
Environment=ZECWEC_RELEASE_PATH=/opt/wcash/releases/credential-test
LoadCredential=smoke:/etc/wcash-pool/credentials/smoke
ExecStart=/opt/wcash/releases/credential-test/pool-entrypoint.sh $mode
UNIT
    rm -f /run/wcash-credential-smoke/{order,fail}
    systemctl daemon-reload
    systemctl start "$unit"
    if [[ $mode == preflight ]]; then
        expected=$'config-check\npreflight'
    else
        expected=$'config-check\npreflight\nserve'
    fi
    [[ $(cat /run/wcash-credential-smoke/order) == "$expected" ]]
    printf 'PASS actual systemd credential lifetime: %s\n' "$mode"
    for failure in config-check preflight; do
        rm -f /run/wcash-credential-smoke/order
        printf '%s' "$failure" >/run/wcash-credential-smoke/fail
        systemctl reset-failed "$unit" 2>/dev/null || true
        if systemctl start "$unit" >/dev/null 2>&1; then
            printf 'Startup ignored %s failure\n' "$failure" >&2
            exit 1
        fi
        if [[ $failure == config-check ]]; then
            expected=config-check
        else
            expected=$'config-check\npreflight'
        fi
        [[ $(cat /run/wcash-credential-smoke/order) == "$expected" ]]
    done
    printf 'PASS startup failure stops later commands: %s\n' "$mode"
done
systemd --version | head -n 1
