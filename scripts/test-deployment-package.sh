#!/usr/bin/env bash

set -Eeuo pipefail
set +x

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
temporary=$(CDPATH='' cd -- "$temporary" && pwd -P)
trap 'rm -rf -- "$temporary"' EXIT

command -v shellcheck >/dev/null 2>&1 || {
    printf 'deployment-package-test: shellcheck is required\n' >&2
    exit 1
}

bash -n "$repo_root"/scripts/deploy/*.sh \
    "$repo_root/scripts/build-zallet-testnet.sh" \
    "$repo_root/scripts/test-deployment-package.sh"
shellcheck "$repo_root"/scripts/deploy/*.sh \
    "$repo_root/scripts/build-zallet-testnet.sh" \
    "$repo_root/scripts/test-deployment-package.sh"
grep -Fq 'base_commit=987382f67e622915228686e9f956c6a9c9a7514c' \
    "$repo_root/scripts/build-zallet-testnet.sh"
grep -Fq 'toolchain=1.95.0' "$repo_root/scripts/build-zallet-testnet.sh"
# shellcheck disable=SC2016
grep -Fq 'cargo "+$toolchain" build --locked --release' \
    "$repo_root/scripts/build-zallet-testnet.sh"
grep -Fq -- '--features rpc-cli,zcashd-import' \
    "$repo_root/scripts/build-zallet-testnet.sh"
grep -Fq 'const MIN_WALLET_POOL_SIZE: usize = 8;' \
    "$repo_root/patches/zallet-v0.1.0-beta.3/0001-reserve-wallet-database-capacity.patch"
grep -Fq 'config.timeouts.wait = Some(WALLET_POOL_WAIT_TIMEOUT);' \
    "$repo_root/patches/zallet-v0.1.0-beta.3/0001-reserve-wallet-database-capacity.patch"
grep -Fq '.runtime(deadpool::Runtime::Tokio1)' \
    "$repo_root/patches/zallet-v0.1.0-beta.3/0001-reserve-wallet-database-capacity.patch"
grep -Fx -- '    --deadline 1080' \
    "$repo_root/scripts/deploy/wait-zallet-ready.sh" >/dev/null
# shellcheck disable=SC2016
grep -Fq '$script_dir/zallet_rpc_health.py' \
    "$repo_root/scripts/deploy/wait-zallet-ready.sh"
if grep -Fq '/usr/local/libexec' "$repo_root/scripts/deploy/wait-zallet-ready.sh"; then
    printf 'deployment-package-test: Zallet readiness escaped its immutable release\n' >&2
    exit 1
fi
PYTHONPYCACHEPREFIX="$temporary/pycache" python3 -m py_compile "$repo_root"/scripts/deploy/*.py
PYTHONDONTWRITEBYTECODE=1 python3 - "$repo_root/scripts/deploy/zallet_rpc_health.py" <<'PY'
import http.client
import importlib.util
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("zallet_rpc_health", source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class IncompleteRpcResponse:
    def __init__(self, *_args, **_kwargs):
        pass

    def request(self, *_args, **_kwargs):
        raise http.client.IncompleteRead(b"", 1)

    def close(self):
        pass

module.http.client.HTTPConnection = IncompleteRpcResponse
assert module.probe("127.0.0.1", 1, "user:test-value", 0.1) is False

tip = {
    "blockhash": "01" * 32,
    "height": 4_341_450,
}
ready = {
    "node_tip": tip,
    "wallet_tip": dict(tip),
    "fully_synced_height": tip["height"],
    "locked": False,
}
assert module.wallet_status_is_ready(ready) is True
accountless = dict(ready)
accountless.pop("fully_synced_height")
assert module.wallet_status_is_ready(accountless) is True
for field, value in [
    ("locked", True),
    ("sync_work_remaining", {"unscanned_blocks": 1}),
    ("sync_work_remaining", None),
    ("fully_synced_height", tip["height"] - 1),
    ("fully_synced_height", None),
    ("fully_synced_height", True),
    ("fully_synced_height", str(tip["height"])),
]:
    invalid = dict(ready)
    invalid[field] = value
    assert module.wallet_status_is_ready(invalid) is False
for field, value in [("height", tip["height"] - 1), ("blockhash", "11" * 32)]:
    invalid = dict(ready)
    invalid["wallet_tip"] = dict(tip)
    invalid["wallet_tip"][field] = value
    assert module.wallet_status_is_ready(invalid) is False
for blockhash in ["0" * 64, "AA" * 32, "gg" * 32]:
    invalid = dict(ready)
    invalid["node_tip"] = {"blockhash": blockhash, "height": tip["height"]}
    invalid["wallet_tip"] = dict(invalid["node_tip"])
    assert module.wallet_status_is_ready(invalid) is False
for height in [False, 0, -1, 0x1_0000_0000]:
    invalid = dict(ready)
    invalid["node_tip"] = {"blockhash": tip["blockhash"], "height": height}
    invalid["wallet_tip"] = dict(invalid["node_tip"])
    invalid["fully_synced_height"] = height
    assert module.wallet_status_is_ready(invalid) is False

class StaticRpcResponse:
    status = 200

    def __init__(self, payload):
        self.payload = payload

    def read(self, _limit):
        return json.dumps(self.payload).encode("utf-8")

class StaticRpcConnection:
    payload = None

    def __init__(self, *_args, **_kwargs):
        pass

    def request(self, *_args, **_kwargs):
        pass

    def getresponse(self):
        return StaticRpcResponse(self.payload)

    def close(self):
        pass

module.http.client.HTTPConnection = StaticRpcConnection
StaticRpcConnection.payload = {
    "id": "zecwec-readiness",
    "error": None,
    "result": ready,
}
assert module.probe("127.0.0.1", 28232, "user:test-value", 0.1) is True
for malformed in [
    [],
    {"id": "wrong-id", "error": None, "result": ready},
    {"id": "zecwec-readiness", "error": {"code": -1}, "result": ready},
]:
    StaticRpcConnection.payload = malformed
    assert module.probe("127.0.0.1", 28232, "user:test-value", 0.1) is False
PY
cargo build --locked --quiet --manifest-path "$repo_root/Cargo.toml" \
    --package wcash-poold --bin wcash-poold

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
    "WCASH_PAYOUT_COMMITMENT_WIRE": bytes(range(65, 97)).hex(),
    "ZCASH_PAYOUT_COMMITMENT_WIRE": bytes(range(97, 129)).hex(),
    "INITIAL_SHARE_TARGET_BE": bytes(range(1, 33)).hex(),
    "EASIEST_SHARE_TARGET_BE": bytes(range(129, 161)).hex(),
}
integer_values = {
    "ZCASH_SIGNER_ACCOUNT_INDEX": "0",
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
    elif key in integer_values:
        value = integer_values[key]
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
            "wcash_genesis": bytes.fromhex(wcash_display)[::-1].hex(),
            "zcash_genesis": bytes.fromhex(zcash_display)[::-1].hex(),
            "wcash_payout_commitment": bytes(range(65, 97)).hex(),
            "zcash_payout_commitment": bytes(range(97, 129)).hex(),
            "share_target_ceiling": bytes(range(129, 161)).hex(),
            "share_target_ceiling_byte_order": "big_endian",
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
preflight = tomllib.loads((root / "pool.preflight.toml").read_text(encoding="utf-8"))
zallet = tomllib.loads((root / "zallet.toml").read_text(encoding="utf-8"))
manifest = json.loads((root / "render-manifest.json").read_text(encoding="utf-8"))

assert runtime["network"] == "testnet"
assert runtime["wcash_wallet_uid"] == 0
assert runtime["wcash_seed_uid"] == 12345
assert runtime["nonce_reservation"] == 65536
assert runtime["backend_instance"] == "55555555-5555-4555-8555-555555555555"
assert runtime["journal_stream"] == "66666666-6666-4666-8666-666666666666"
assert runtime["database_url_file"] == "/run/credentials/wcash-pool.service/database-url"
assert runtime["wcash_node_rpc"] == "127.0.0.1:38232"
assert runtime["wcash_node_cookie_file"] == "/run/credentials/wcash-pool.service/wcash-node-cookie"
assert runtime["zcash_signer_account_index"] == 0
assert migrate["database_url_file"] == "/run/credentials/wcash-pool-migrate.service/database-url"
assert preflight["database_url_file"] == "/run/credentials/wcash-pool-preflight.service/database-url"
assert preflight["zallet_cookie_file"] == "/run/credentials/wcash-pool-preflight.service/zallet-cookie"
assert preflight["wcash_node_cookie_file"] == "/run/credentials/wcash-pool-preflight.service/wcash-node-cookie"
assert runtime["wcash_wallet_program"] == str(root.parent / "release" / "wcash-wallet")
assert runtime["wcash_wallet_sync_batch_size"] == 16
assert runtime["wcash_wallet_sync_timeout_seconds"] == 900
assert runtime["wcash_signer_account"] == "33333333-3333-4333-8333-333333333333"
assert runtime["zcash_signer_account"] == "44444444-4444-4444-8444-444444444444"
assert zallet["consensus"]["network"] == "test"
assert zallet["builder"] == {"limits": {}}
assert zallet["external"]["broadcast"] is False
assert zallet["features"]["as_of_version"] == "0.1.0-beta.3"
assert zallet["rpc"]["bind"] == ["127.0.0.1:28232"]
assert manifest["network"] == "testnet"
assert manifest["release_root"] == str(root.parent / "release")
assert manifest["deployment_schema"] == 1

for path in root.rglob("*"):
    if path.is_file():
        text = path.read_text(encoding="utf-8")
        assert "CHANGE_ME" not in text
        assert "BOOTSTRAP_DISCOVERY_REQUIRED" not in text
        assert re.search(r"@[A-Z][A-Z0-9_]*@", text) is None

pool_unit = (root / "systemd/wcash-pool.service").read_text(encoding="utf-8")
backend_unit = (root / "systemd/wcash-pool-backend.service").read_text(encoding="utf-8")
assert "User=wcash-pool\n" in pool_unit
assert "SupplementaryGroups=wcash-pool-socket" in pool_unit
assert "LoadCredential=database-url:" in pool_unit
assert "LoadCredential=wcash-node-cookie:" in pool_unit
assert "/opt/wcash/current" not in pool_unit
assert str(root.parent / "release") in pool_unit
assert "User=wcash-pool-backend\n" in backend_unit
assert "Group=wcash-pool-socket\n" in backend_unit
assert "LoadCredential=wcash-payout-ivk:" in backend_unit
assert "LoadCredential=wcash-wallet-authority:/var/lib/wcash-pool/wcash-wallet-authority.json" in backend_unit
assert "LoadCredential=zec-authority-config:/etc/wcash-pool/zec-authority.testnet.toml" in backend_unit
assert "LoadCredential=zec-initial-zero-result:/var/lib/wcash-pool-backend/zec-collector-initial-zero.json" in backend_unit
assert "LoadCredential=zec-initial-zero-attestation:/var/lib/wcash-pool-backend/zec-collector-initial-zero.attestation" in backend_unit
assert "zec-authority-bootstrap.sh verify" in backend_unit

preflight_unit = (root / "systemd/wcash-pool-preflight.service").read_text(encoding="utf-8")
zallet_unit = (root / "systemd/zecwec-zallet.service").read_text(encoding="utf-8")
executable_condition_units = {
    "wcash-pool-backend-init.service",
    "wcash-pool-backend.service",
    "wcash-pool-migrate.service",
    "wcash-pool-preflight.service",
    "wcash-pool-wallet-init.service",
    "wcash-pool-zec-authority-bootstrap.service",
    "wcash-pool.service",
    "zecwec-zallet.service",
}
found_executable_conditions = set()
for service in (root / "systemd").glob("*.service"):
    rendered_service = service.read_text(encoding="utf-8")
    assert "ConditionPathIsExecutable=" not in rendered_service
    if "ConditionFileIsExecutable=" in rendered_service:
        assert rendered_service.count("ConditionFileIsExecutable=") == 1
        found_executable_conditions.add(service.name)
assert found_executable_conditions == executable_condition_units
assert "pool.preflight.toml" in preflight_unit
assert "/run/credentials/wcash-pool-preflight.service" not in pool_unit
assert "TimeoutStopSec=1920s" in pool_unit
assert "KillMode=mixed" in pool_unit
assert "TimeoutStartSec=1800s" in pool_unit
assert "TimeoutStartSec=1800s" in preflight_unit
assert "TimeoutStartSec=1200s" in zallet_unit
assert "ConditionFileIsExecutable=" in zallet_unit
assert "ConditionPathIsExecutable=" not in zallet_unit

wallet_init_unit = (root / "systemd/wcash-pool-wallet-init.service").read_text(encoding="utf-8")
assert "EnvironmentFile=/etc/wcash-pool/wcash-wallet-bootstrap.env" in wallet_init_unit
assert "TimeoutStartSec=1200s" in wallet_init_unit
wallet_bootstrap = (root / "wcash-wallet-bootstrap.env").read_text(encoding="utf-8")
assert "WCASH_WALLET_BIRTHDAY=1" in wallet_bootstrap
assert "WCASH_WALLET_AUTHORITY=/var/lib/wcash-pool/wcash-wallet-authority.json" in wallet_bootstrap
zec_authority = tomllib.loads((root / "zec-authority.testnet.toml").read_text(encoding="utf-8"))
assert zec_authority["network"] == "testnet"
assert zec_authority["zcash_genesis_wire"] == bytes.fromhex(bytes(range(33, 65)).hex())[::-1].hex()
assert zec_authority["collector_payout_commitment"] == bytes(range(97, 129)).hex()
assert zec_authority["collector_account"] == "44444444-4444-4444-8444-444444444444"
assert zec_authority["collector_account_index"] == 0
assert zec_authority["required_confirmations"] == 100
assert zec_authority["zallet_cookie_file"] == "/run/credentials/wcash-pool-zec-authority-bootstrap.service/zallet-cookie"
assert zec_authority["zcash_node_cookie_file"] == "/run/credentials/wcash-pool-zec-authority-bootstrap.service/zcash-node-cookie"
zec_authority_unit = (root / "systemd/wcash-pool-zec-authority-bootstrap.service").read_text(encoding="utf-8")
assert "Before=wcash-pool-backend-init.service" in zec_authority_unit
assert "wcash-poold zec-authority-check" not in zec_authority_unit
assert "zec-authority-bootstrap.sh reconcile" in zec_authority_unit
assert "BindsTo=zecwec-zallet.service" not in zec_authority_unit

backend_environment = (root / "backend.env").read_text(encoding="utf-8")
assert "WCASH_SHARE_TARGET=" + bytes(range(129, 161)).hex() in backend_environment
assert "WCASH_AUTHORITY_SHARE_TARGET_BE=" + bytes(range(129, 161)).hex() in backend_environment
assert "WCASH_AUTHORITY_SIGNER_ACCOUNT=33333333-3333-4333-8333-333333333333" in backend_environment
assert "ZCASH_AUTHORITY_SIGNER_ACCOUNT=" not in backend_environment
assert "ZCASH_AUTHORITY_SIGNER_ACCOUNT_INDEX=" not in backend_environment
assert "WCASH_SHARE_JOURNAL=/var/lib/wcash-pool-backend/share-journal-protocol-v2.jsonl" in backend_environment
assert "WCASH_POOL_BACKEND_IDENTITY=/var/lib/wcash-pool-backend/backend-identity-protocol-v2.json" in backend_environment
assert "WCASH_POOL_BACKEND_JOURNAL=/var/lib/wcash-pool-backend/backend-journal-protocol-v2.jsonl" in backend_environment

stratum = (root / "nginx/zecwec-testnet-stratum.conf").read_text(encoding="utf-8")
assert "listen 3443 ssl;" in stratum
assert "server 127.0.0.1:3333;" in stratum

portal = (root / "nginx/zecwec-testnet-portal.conf").read_text(encoding="utf-8")
assert portal.count("ssl_verify_client on;") == 2
assert portal.count("ssl_client_certificate /etc/wcash-pool/tls/cloudflare-origin-pull-ca.pem;") == 2
assert "proxy_set_header X-Forwarded-For $http_cf_connecting_ip;" in portal
assert "limit_req_zone $zecwec_credential_client zone=zecwec_portal_credentials:10m rate=6r/m;" in portal
assert "limit_req zone=zecwec_portal_credentials burst=4 nodelay;" in portal
assert "limit_req_status 429;" in portal
assert '\"POST:/api/v1/workers\" $http_cf_connecting_ip;' in portal
assert "return 444;" in portal
PY

grep -Fq 'stage-portal)' "$repo_root/scripts/deploy/enable-nginx-edge.sh"
grep -Fq -- '--ack-cloudflare-access' "$repo_root/scripts/deploy/enable-nginx-edge.sh"
grep -Fq 'Cloudflare Access did not deny the anonymous staging probe' \
    "$repo_root/scripts/deploy/enable-nginx-edge.sh"
grep -Fq 'public_status != 200' "$repo_root/scripts/deploy/enable-nginx-edge.sh"
grep -Fq 'public_body != '\''{"status":"ok"}'\''' \
    "$repo_root/scripts/deploy/enable-nginx-edge.sh"

mkdir -p "$temporary/config-check-credentials"
chmod 0700 "$temporary/config-check-credentials"
printf 'postgresql://pool@/zecwec\n' >"$temporary/config-check-credentials/database-url"
printf '%032d' 0 | tr 0 a >"$temporary/config-check-credentials/portal-pepper"
printf '%032d' 0 | tr 0 b >"$temporary/config-check-credentials/portal-totp"
chmod 0600 "$temporary/config-check-credentials"/*
python3 - \
    "$temporary/output/pool.runtime.toml" \
    "$temporary/config-check.toml" \
    "$temporary/config-check-credentials" <<'PY'
import pathlib
import sys

source, output, credentials = map(pathlib.Path, sys.argv[1:])
text = source.read_text(encoding="utf-8")
replacements = {
    "/run/credentials/wcash-pool.service/database-url": str(credentials / "database-url"),
    "/run/credentials/wcash-pool.service/portal-token-pepper": str(credentials / "portal-pepper"),
    "/run/credentials/wcash-pool.service/portal-totp-key": str(credentials / "portal-totp"),
}
for old, new in replacements.items():
    if text.count(old) != 1:
        raise SystemExit(f"rendered config did not contain one exact credential path: {old}")
    text = text.replace(old, new)
output.write_text(text, encoding="utf-8")
output.chmod(0o600)
PY
"$repo_root/target/debug/wcash-poold" config-check \
    --config "$temporary/config-check.toml" \
    | grep -Fqx '{"valid":true,"network":"testnet"}' \
    || {
        printf 'deployment-package-test: real Rust config-check rejected rendered policy\n' >&2
        exit 1
    }

python3 - "$temporary/deployment.env" "$temporary/discovery.env" <<'PY'
import pathlib
import sys

source, output = map(pathlib.Path, sys.argv[1:])
text = source.read_text(encoding="utf-8")
keys = {
    "WCASH_SIGNER_ACCOUNT",
    "ZCASH_SIGNER_ACCOUNT",
    "WCASH_PAYOUT_COMMITMENT_WIRE",
    "ZCASH_PAYOUT_COMMITMENT_WIRE",
    "ZCASH_SIGNER_ACCOUNT_INDEX",
}
lines = []
for line in text.splitlines():
    key = line.split("=", 1)[0]
    if key in keys:
        line = f"{key}=BOOTSTRAP_DISCOVERY_REQUIRED"
    lines.append(line)
output.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
python3 "$repo_root/scripts/deploy/render_deployment.py" wallet-bootstrap \
    --settings "$temporary/discovery.env" \
    --source-root "$repo_root" \
    --release-root "$temporary/release" \
    --output "$temporary/wallet-bootstrap-output" \
    --pool-uid 12345
[[ ! -e $temporary/wallet-bootstrap-output/backend.env \
    && ! -e $temporary/wallet-bootstrap-output/zec-authority.testnet.toml \
    && ! -e $temporary/wallet-bootstrap-output/pool.runtime.toml \
    && ! -e $temporary/wallet-bootstrap-output/systemd/wcash-pool.service \
    && ! -e $temporary/wallet-bootstrap-output/systemd/wcash-pool-zec-authority-bootstrap.service ]] \
    || {
        printf 'deployment-package-test: wallet discovery rendered runtime authority\n' >&2
        exit 1
    }
grep -Fq 'WCASH_EXPECTED_SIGNER_ACCOUNT=BOOTSTRAP_DISCOVERY_REQUIRED' \
    "$temporary/wallet-bootstrap-output/wcash-wallet-bootstrap.env"

wallet_protocol_fixture="$temporary/wallet-protocol-v2"
mkdir -p "$wallet_protocol_fixture"
wallet_account=33333333-3333-4333-8333-333333333333
wallet_genesis=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
wallet_commitment=4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60
python3 - \
    "$wallet_protocol_fixture" \
    "$wallet_account" \
    "$wallet_genesis" \
    "$wallet_commitment" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
account, genesis, commitment = sys.argv[2:]
root.joinpath("init.json").write_text(
    json.dumps(
        {
            "account_id": account,
            "birthday_height": 1,
            "address": "wutest1realistic-ironwood-collector-fixture",
            "transparent_coinbase_address": "wttest1realistic-coinbase-fixture",
            "created": True,
        }
    )
    + "\n",
    encoding="utf-8",
)
root.joinpath("identity-v2.json").write_text(
    json.dumps(
        {
            "protocol_version": 2,
            "network": "testnet",
            "genesis_hash": genesis,
            "branch_id": "b3cfd27e",
            "account_id": account,
            "collector_payout_commitment": commitment,
            "fund_source": "ironwood",
            "synchronized": True,
        }
    )
    + "\n",
    encoding="utf-8",
)
value_fields = {
    "ironwood_total_zat",
    "ironwood_spendable_zat",
    "ironwood_locked_zat",
    "ironwood_pending_change_zat",
    "ironwood_pending_spendability_zat",
    "sapling_total_zat",
    "orchard_total_zat",
    "transparent_total_zat",
    "transparent_coinbase_total_zat",
    "transparent_coinbase_spendable_zat",
    "transparent_coinbase_pending_zat",
    "transparent_regular_total_zat",
}
account_balance = {field: 0 for field in value_fields}
account_balance["account_id"] = account
root.joinpath("balance.json").write_text(
    json.dumps(
        {
            "chain_tip_height": 48,
            "fully_scanned_height": 48,
            "synchronized": True,
            "accounts": [account_balance],
        }
    )
    + "\n",
    encoding="utf-8",
)

identity_bool = json.loads(root.joinpath("identity-v2.json").read_text(encoding="utf-8"))
identity_bool["protocol_version"] = True
root.joinpath("identity-bool-protocol.json").write_text(
    json.dumps(identity_bool) + "\n", encoding="utf-8"
)

init_bool = json.loads(root.joinpath("init.json").read_text(encoding="utf-8"))
init_bool["birthday_height"] = True
root.joinpath("init-bool-birthday.json").write_text(
    json.dumps(init_bool) + "\n", encoding="utf-8"
)

balance_bool_tip = json.loads(root.joinpath("balance.json").read_text(encoding="utf-8"))
balance_bool_tip["chain_tip_height"] = True
root.joinpath("balance-bool-tip.json").write_text(
    json.dumps(balance_bool_tip) + "\n", encoding="utf-8"
)

balance_bool_scan = json.loads(root.joinpath("balance.json").read_text(encoding="utf-8"))
balance_bool_scan["fully_scanned_height"] = True
root.joinpath("balance-bool-scan.json").write_text(
    json.dumps(balance_bool_scan) + "\n", encoding="utf-8"
)

balance_bool_value = json.loads(root.joinpath("balance.json").read_text(encoding="utf-8"))
balance_bool_value["accounts"][0]["ironwood_total_zat"] = False
root.joinpath("balance-bool-value.json").write_text(
    json.dumps(balance_bool_value) + "\n", encoding="utf-8"
)
PY

wallet_validator="$repo_root/scripts/deploy/validate-wcash-wallet-bootstrap.py"
python3 "$wallet_validator" \
    "$wallet_protocol_fixture/init.json" \
    "$wallet_protocol_fixture/balance.json" \
    "$wallet_protocol_fixture/identity-v2.json" \
    "$wallet_protocol_fixture/authority-v2.json" \
    1 \
    "$wallet_genesis" \
    "$wallet_account" \
    "$wallet_commitment" \
    >"$wallet_protocol_fixture/authority-output.json"
cmp -s \
    "$wallet_protocol_fixture/authority-v2.json" \
    "$wallet_protocol_fixture/authority-output.json" \
    || {
        printf 'deployment-package-test: wallet protocol-v2 authority output is unstable\n' >&2
        exit 1
    }

assert_wallet_protocol_rejected() {
    local label=$1
    local init=$2
    local balance=$3
    local identity=$4
    local rejected_authority="$wallet_protocol_fixture/authority-rejected-$label.json"
    if python3 "$wallet_validator" \
        "$init" \
        "$balance" \
        "$identity" \
        "$rejected_authority" \
        1 \
        "$wallet_genesis" \
        "$wallet_account" \
        "$wallet_commitment" >/dev/null 2>&1; then
        printf 'deployment-package-test: wallet bootstrap accepted malformed %s output\n' \
            "$label" >&2
        exit 1
    fi
    [[ ! -e $rejected_authority ]] || {
        printf 'deployment-package-test: rejected wallet output wrote authority state\n' >&2
        exit 1
    }
}

assert_wallet_protocol_rejected \
    bool-protocol \
    "$wallet_protocol_fixture/init.json" \
    "$wallet_protocol_fixture/balance.json" \
    "$wallet_protocol_fixture/identity-bool-protocol.json"
assert_wallet_protocol_rejected \
    bool-birthday \
    "$wallet_protocol_fixture/init-bool-birthday.json" \
    "$wallet_protocol_fixture/balance.json" \
    "$wallet_protocol_fixture/identity-v2.json"
assert_wallet_protocol_rejected \
    bool-tip \
    "$wallet_protocol_fixture/init.json" \
    "$wallet_protocol_fixture/balance-bool-tip.json" \
    "$wallet_protocol_fixture/identity-v2.json"
assert_wallet_protocol_rejected \
    bool-scan \
    "$wallet_protocol_fixture/init.json" \
    "$wallet_protocol_fixture/balance-bool-scan.json" \
    "$wallet_protocol_fixture/identity-v2.json"
assert_wallet_protocol_rejected \
    bool-balance \
    "$wallet_protocol_fixture/init.json" \
    "$wallet_protocol_fixture/balance-bool-value.json" \
    "$wallet_protocol_fixture/identity-v2.json"

for rejected_version in 1 4294967295; do
    rejected_identity="$wallet_protocol_fixture/identity-v$rejected_version.json"
    python3 - \
        "$wallet_protocol_fixture/identity-v2.json" \
        "$rejected_identity" \
        "$rejected_version" <<'PY'
import json
import pathlib
import sys

source, output = map(pathlib.Path, sys.argv[1:3])
identity = json.loads(source.read_text(encoding="utf-8"))
identity["protocol_version"] = int(sys.argv[3], 10)
output.write_text(json.dumps(identity) + "\n", encoding="utf-8")
PY
    assert_wallet_protocol_rejected \
        "protocol-$rejected_version" \
        "$wallet_protocol_fixture/init.json" \
        "$wallet_protocol_fixture/balance.json" \
        "$rejected_identity"
done

if python3 "$repo_root/scripts/deploy/render_deployment.py" bootstrap \
    --settings "$temporary/discovery.env" \
    --source-root "$repo_root" \
    --release-root "$temporary/release" \
    --output "$temporary/rejected-discovery-bootstrap" \
    --pool-uid 12345 >/dev/null 2>&1; then
    printf 'deployment-package-test: authority bootstrap accepted discovery sentinels\n' >&2
    exit 1
fi

python3 "$repo_root/scripts/deploy/render_deployment.py" bootstrap \
    --settings "$temporary/deployment.env" \
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

sed 's/^WCASH_PAYOUT_MODE=ironwood$/WCASH_PAYOUT_MODE=transparent/' \
    "$temporary/deployment.env" >"$temporary/transparent.env"
if python3 "$repo_root/scripts/deploy/render_deployment.py" bootstrap \
    --settings "$temporary/transparent.env" \
    --source-root "$repo_root" \
    --release-root "$temporary/release" \
    --output "$temporary/transparent-output" \
    --pool-uid 12345 >/dev/null 2>&1; then
    printf 'deployment-package-test: renderer accepted a transparent launch collector\n' >&2
    exit 1
fi

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

python3 - "$temporary/authority.json" "$temporary/bad-authority.json" <<'PY'
import json
import pathlib
import sys

source, output = map(pathlib.Path, sys.argv[1:])
authority = json.loads(source.read_text(encoding="utf-8"))
authority["share_target_ceiling"] = bytes(range(128, 160)).hex()
output.write_text(json.dumps(authority) + "\n", encoding="utf-8")
PY
if python3 "$repo_root/scripts/deploy/render_deployment.py" finalize \
    --settings "$temporary/deployment.env" \
    --authority "$temporary/bad-authority.json" \
    --source-root "$repo_root" \
    --release-root "$temporary/release" \
    --output "$temporary/rejected-authority" \
    --pool-uid 12345 >/dev/null 2>&1; then
    printf 'deployment-package-test: renderer accepted a mismatched target authority\n' >&2
    exit 1
fi

ln -s "$temporary/release" "$temporary/release-link"
if python3 "$repo_root/scripts/deploy/render_deployment.py" bootstrap \
    --settings "$temporary/deployment.env" \
    --source-root "$repo_root" \
    --release-root "$temporary/release-link" \
    --output "$temporary/rejected-symlink-release" \
    --pool-uid 12345 >/dev/null 2>&1; then
    printf 'deployment-package-test: renderer accepted a symlink release root\n' >&2
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
