#!/usr/bin/env bash
set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
docker build -t zecwec-ubuntu-smoke:22.04 "$script_dir"
container_id=$(docker create --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
    --mount "type=bind,source=$repo_root,target=/workspace,readonly" \
    zecwec-ubuntu-smoke:22.04)
cleanup() { docker rm -f "$container_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker start "$container_id" >/dev/null
for attempt in $(seq 1 60); do
    if docker exec "$container_id" systemctl is-active basic.target >/dev/null 2>&1; then
        break
    fi
    if [[ $attempt == 60 ]]; then
        printf 'Disposable systemd container did not start\n' >&2
        exit 1
    fi
    sleep 1
done
docker exec "$container_id" bash /workspace/scripts/tests/ubuntu-smoke/check-credentials.sh
docker exec "$container_id" systemctl stop nginx.service
docker exec "$container_id" python3 /workspace/scripts/tests/ubuntu-smoke/check-nginx.py
