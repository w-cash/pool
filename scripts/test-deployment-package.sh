#!/usr/bin/env bash

set -Eeuo pipefail
set +x

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT

command -v shellcheck >/dev/null 2>&1 || {
    printf 'deployment-package-test: shellcheck is required\n' >&2
    exit 1
}

bash -n "$repo_root"/scripts/deploy/*.sh "$repo_root/scripts/test-deployment-package.sh"
shellcheck "$repo_root"/scripts/deploy/*.sh "$repo_root/scripts/test-deployment-package.sh"
PYTHONPYCACHEPREFIX="$temporary/pycache" python3 -m py_compile "$repo_root"/scripts/deploy/*.py

mkdir -p "$temporary/release" "$temporary/output"
for binary in wcash-poold wcash-merge-miner wcash-wallet zallet; do
    cp /bin/sh "$temporary/release/$binary"
    chmod 0555 "$temporary/release/$binary"
done
(
    cd "$temporary/release"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum wcash-poold wcash-merge-miner wcash-wallet zallet >SHA256SUMS
    else
        shasum -a 256 wcash-poold wcash-merge-miner wcash-wallet zallet >SHA256SUMS
    fi
)

python3 - \
    "$repo_root/deploy/config/deployment.env.example" \
    "$temporary/deployment.env" \
    "$temporary/authority.json" <<'PY'
import json
import pathlib
import sys

source, output, authority = map(pathlib.Path, sys.argv[1:])
wcash_display = bytes(range(1, 33)).hex()
zcash_display = bytes(range(33, 65)).hex()
uuids = {
    "DEPLOYMENT_ID": "11111111-1111-4111-8111-111111111111",
    "POOL_INSTANCE": "22222222-2222-4222-8222-222222222222",
    "WCASH_SIGNER_ACCOUNT": "33333333-3333-4333-8333-333333333333",
    "ZCASH_SIGNER_ACCOUNT": "44444444-4444-4444-8444-444444444444",
}
hex_values = {
    "WCASH_GENESIS_DISPLAY": wcash_display,
    "WCASH_GENESIS_WIRE": bytes.fromhex(wcash_display)[::-1].hex(),
    "ZCASH_GENESIS_DISPLAY": zcash_display,
    "ZCASH_GENESIS_WIRE": bytes.fromhex(zcash_display)[::-1].hex(),
    "WCASH_PAYOUT_COMMITMENT_WIRE": "41" * 32,
    "ZCASH_PAYOUT_COMMITMENT_WIRE": "42" * 32,
    "INITIAL_SHARE_TARGET_BE": (1).to_bytes(32, "big").hex(),
    "EASIEST_SHARE_TARGET_BE": "ff" * 32,
}
lines = []
for raw in source.read_text(encoding="utf-8").splitlines():
    if "=" not in raw or raw.lstrip().startswith("#"):
        lines.append(raw)
        continue
    key, value = raw.split("=", 1)
    if key in uuids:
        value = uuids[key]
    elif key in hex_values:
        value = hex_values[key]
    lines.append(f"{key}={value}")
rendered = "\n".join(lines) + "\n"
for raw in rendered.splitlines():
    if "=" in raw and not raw.lstrip().startswith("#"):
        _, value = raw.split("=", 1)
        if "CHANGE_ME" in value:
            raise SystemExit("fixture did not replace every required value")
output.write_text(rendered, encoding="utf-8")
authority.write_text(
    json.dumps(
        {
            "command": "pool-backend-init",
            "result": "initialized",
            "backend_instance": "55555555-5555-4555-8555-555555555555",
            "journal_stream": "66666666-6666-4666-8666-666666666666",
            "event_seq": 0,
            "chain_id": 1464025427,
            "listener_workers": 2,
            "share_target_ceiling": (1).to_bytes(32, "big").hex(),
        }
    )
    + "\n",
    encoding="utf-8",
)
PY

python3 "$repo_root/scripts/deploy/render_deployment.py" finalize \
    --settings "$temporary/deployment.env" \
    --authority "$temporary/authority.json" \
    --source-root "$repo_root" \
    --release-root "$temporary/release" \
    --output "$temporary/output" \
    --pool-uid 12345

python3 - "$temporary/output" <<'PY'
import json
import pathlib
import re
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
runtime = tomllib.loads((root / "pool.runtime.toml").read_text(encoding="utf-8"))
migrate = tomllib.loads((root / "pool.migrate.toml").read_text(encoding="utf-8"))
zallet = tomllib.loads((root / "zallet.toml").read_text(encoding="utf-8"))
manifest = json.loads((root / "render-manifest.json").read_text(encoding="utf-8"))

assert runtime["network"] == "testnet"
assert runtime["wcash_wallet_uid"] == 12345
assert runtime["wcash_seed_uid"] == 12345
assert runtime["nonce_reservation"] == 65536
assert runtime["backend_instance"] == "55555555-5555-4555-8555-555555555555"
assert runtime["journal_stream"] == "66666666-6666-4666-8666-666666666666"
assert runtime["database_url_file"] == "/run/credentials/wcash-pool.service/database-url"
assert runtime["wcash_node_rpc"] == "127.0.0.1:38232"
assert runtime["wcash_node_cookie_file"] == "/run/credentials/wcash-pool.service/wcash-node-cookie"
assert runtime["zcash_signer_account_index"] == 0
assert migrate["database_url_file"] == "/run/credentials/wcash-pool-migrate.service/database-url"
assert zallet["consensus"]["network"] == "test"
assert zallet["external"]["broadcast"] is False
assert zallet["features"]["as_of_version"] == "0.1.0-beta.3"
assert zallet["rpc"]["bind"] == ["127.0.0.1:28232"]
assert manifest["network"] == "testnet"

for path in root.rglob("*"):
    if path.is_file():
        text = path.read_text(encoding="utf-8")
        assert "CHANGE_ME" not in text
        assert re.search(r"@[A-Z][A-Z0-9_]*@", text) is None

pool_unit = (root / "systemd/wcash-pool.service").read_text(encoding="utf-8")
backend_unit = (root / "systemd/wcash-pool-backend.service").read_text(encoding="utf-8")
assert "User=wcash-pool\n" in pool_unit
assert "SupplementaryGroups=wcash-pool-socket" in pool_unit
assert "LoadCredential=database-url:" in pool_unit
assert "LoadCredential=wcash-node-cookie:" in pool_unit
assert "User=wcash-pool-backend\n" in backend_unit
assert "Group=wcash-pool-socket\n" in backend_unit
assert "LoadCredential=wcash-payout-ivk:" not in backend_unit

stratum = (root / "nginx/zecwec-testnet-stratum.conf").read_text(encoding="utf-8")
assert "listen 3443 ssl;" in stratum
assert "server 127.0.0.1:3333;" in stratum
PY

sed 's/^WCASH_PAYOUT_MODE=transparent$/WCASH_PAYOUT_MODE=ironwood/' \
    "$temporary/deployment.env" >"$temporary/ironwood.env"
python3 "$repo_root/scripts/deploy/render_deployment.py" bootstrap \
    --settings "$temporary/ironwood.env" \
    --source-root "$repo_root" \
    --release-root "$temporary/release" \
    --output "$temporary/ironwood-output" \
    --pool-uid 12345
grep -Fq 'LoadCredential=wcash-payout-ivk:' \
    "$temporary/ironwood-output/systemd/wcash-pool-backend.service" \
    || {
        printf 'deployment-package-test: Ironwood render omitted its IVK credential\n' >&2
        exit 1
    }

cp "$temporary/deployment.env" "$temporary/bad.env"
python3 - "$temporary/bad.env" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace(
    "WCASH_GENESIS_WIRE=201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201",
    "WCASH_GENESIS_WIRE=" + "99" * 32,
)
path.write_text(text, encoding="utf-8")
PY
if python3 "$repo_root/scripts/deploy/render_deployment.py" bootstrap \
    --settings "$temporary/bad.env" \
    --source-root "$repo_root" \
    --release-root "$temporary/release" \
    --output "$temporary/rejected" \
    --pool-uid 12345 >/dev/null 2>&1; then
    printf 'deployment-package-test: renderer accepted mismatched genesis byte order\n' >&2
    exit 1
fi

if rg -n '76\.13\.10\.156|187\.7\.23\.198|/Users/mykyta|BEGIN OPENSSH PRIVATE KEY' \
    "$repo_root/deploy" "$repo_root/scripts/deploy" "$repo_root/docs/zecwec-testnet-deployment.md"; then
    printf 'deployment-package-test: sensitive host-specific material detected\n' >&2
    exit 1
fi

if rg -n '[[:blank:]]+$' \
    "$repo_root/deploy" \
    "$repo_root/scripts/deploy" \
    "$repo_root/scripts/test-deployment-package.sh" \
    "$repo_root/docs/zecwec-testnet-deployment.md"; then
    printf 'deployment-package-test: trailing whitespace detected\n' >&2
    exit 1
fi

git -C "$repo_root" diff --check -- deploy scripts/deploy scripts/test-deployment-package.sh docs/zecwec-testnet-deployment.md
printf 'deployment-package-test: all checks passed\n'
