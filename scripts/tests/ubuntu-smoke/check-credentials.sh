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
if [[ $1 == payout-worker ]]; then
    exec python3 - <<'PY'
import os
import pathlib
import signal
import socket

pathlib.Path('/run/wcash-credential-smoke/worker-pid').write_text(str(os.getpid()))
address = os.environ['NOTIFY_SOCKET']
if address.startswith('@'):
    address = '\0' + address[1:]
with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
    notifier.sendto(b'READY=1', address)
signal.pause()
PY
fi
FIXTURE
chmod 0755 /opt/wcash/releases/credential-test/{wcash-poold,pool-entrypoint.sh}

for mode in preflight serve payout; do
    case "$mode" in
        preflight) unit=wcash-pool-preflight.service; service_type=oneshot ;;
        serve) unit=wcash-pool.service; service_type=oneshot ;;
        payout) unit=wcash-payout-worker.service; service_type=notify ;;
    esac
    cat >"/etc/systemd/system/$unit" <<UNIT
[Unit]
Description=Disposable credential-lifetime smoke test
[Service]
Type=$service_type
NotifyAccess=main
TimeoutStartSec=10
TimeoutStopSec=5
User=wcash-smoke
Group=wcash-smoke
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
PrivateMounts=true
ReadWritePaths=/run/wcash-credential-smoke
Environment=ZECWEC_RELEASE_PATH=/opt/wcash/releases/credential-test
LoadCredential=smoke:/etc/wcash-pool/credentials/smoke
ExecStartPre=/usr/bin/true
ExecStartPre=/usr/bin/true
ExecStart=/opt/wcash/releases/credential-test/pool-entrypoint.sh $mode
UNIT
    rm -f /run/wcash-credential-smoke/{order,fail}
    systemctl daemon-reload
    systemctl start "$unit"
    failures=(config-check preflight)
    case "$mode" in
        preflight) expected=$'config-check\npreflight' ;;
        serve) expected=$'config-check\npreflight\nserve' ;;
        payout)
            expected=$'payout-config-check\npayout-worker'
            failures=(payout-config-check)
            ;;
    esac
    [[ $(cat /run/wcash-credential-smoke/order) == "$expected" ]]
    if [[ $mode == payout ]]; then
        [[ $(systemctl show "$unit" --property=MainPID --value) \
            == "$(cat /run/wcash-credential-smoke/worker-pid)" ]]
        systemctl stop "$unit"
        rm /run/wcash-credential-smoke/worker-pid
        printf 'PASS payout READY notification from exec-preserved MainPID\n'
    fi
    printf 'PASS actual systemd credential lifetime: %s\n' "$mode"
    for failure in "${failures[@]}"; do
        rm -f /run/wcash-credential-smoke/order
        printf '%s' "$failure" >/run/wcash-credential-smoke/fail
        systemctl reset-failed "$unit" 2>/dev/null || true
        if systemctl start "$unit" >/dev/null 2>&1; then
            printf 'Startup ignored %s failure\n' "$failure" >&2
            exit 1
        fi
        if [[ $failure == config-check || $failure == payout-config-check ]]; then
            expected=$failure
        else
            expected=$'config-check\npreflight'
        fi
        [[ $(cat /run/wcash-credential-smoke/order) == "$expected" ]]
        [[ ! -e /run/wcash-credential-smoke/worker-pid ]]
    done
    printf 'PASS startup failure stops later commands: %s\n' "$mode"
    if [[ $mode == payout ]]; then
        rm -f /run/wcash-credential-smoke/{order,fail}
        sed -i '/^LoadCredential=/d' "/etc/systemd/system/$unit"
        systemctl daemon-reload
        systemctl reset-failed "$unit"
        if systemctl start "$unit" >/dev/null 2>&1; then
            printf 'Payout startup ignored missing credential directory\n' >&2
            exit 1
        fi
        [[ ! -e /run/wcash-credential-smoke/order \
            && ! -e /run/wcash-credential-smoke/worker-pid ]]
        printf 'PASS missing credentials prevent payout check and worker\n'
    fi
done
systemd --version | head -n 1
