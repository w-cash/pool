#!/usr/bin/env python3
"""Isolated real-node funding/mining helper for the W1 settlement gate.

Uses real Equihash merged mining and unmodified Regtest consensus. The Zcash
parent reward is an unspent public fixture; Wcash funds belong to a fresh local
seed. This is a payout/settlement gate, not a pool share-projection gate.
"""
import argparse
import base64
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import time

WEC_GENESIS = '70bf0bab17eff361a6331bb825b3b7253c8c96ff96407f948161d2912658bb1c'
ZEC_GENESIS = '029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327'
PARENT = 'tmJymvcUCn1ctbghvTJpXBwHiMEB8P6wxNV'
PORTS = {'wec': (48232, 48233), 'zec': (18232, 18233), 'validator': (18242, 18243)}


def isolated_env():
    return {key: value for key, value in os.environ.items()
            if not key.startswith(('WCASH_', 'ZCASH_'))}


def private(path, data):
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(0o600)


def command(root, label, args, *, stdin=None, env=None, timeout=600):
    result = subprocess.run(list(map(str, args)), input=stdin,
                            env=isolated_env() if env is None else env,
                            capture_output=True, timeout=timeout)
    private(root / (label + '.stdout'), result.stdout)
    private(root / (label + '.stderr'), result.stderr)
    if result.returncode:
        raise RuntimeError(f'{label} failed; see protected diagnostics')
    return json.loads(result.stdout)


def rpc(root, name, method, params=None):
    cookie = (root / name / '.cookie').read_bytes().strip()
    conn = http.client.HTTPConnection('127.0.0.1', PORTS[name][0], timeout=60)
    try:
        conn.request('POST', '/', json.dumps({'jsonrpc': '2.0', 'id': 1,
                      'method': method, 'params': params or []}),
                     {'Content-Type': 'application/json',
                      'Authorization': 'Basic ' + base64.b64encode(cookie).decode()})
        result = json.loads(conn.getresponse().read())
        if result.get('error'):
            raise RuntimeError(f'{name}.{method}: {result["error"]}')
        return result['result']
    finally:
        conn.close()


def until(check, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, RuntimeError, ValueError):
            pass
        time.sleep(0.25)
    raise RuntimeError('bounded readiness check timed out')


def mine(root, count):
    manifest = json.loads((root / 'manifest.json').read_text())
    with (root / 'mining.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        env = isolated_env()
        env.update({'WCASH_EXPECTED_GENESIS_HASH': WEC_GENESIS,
                    'ZCASH_EXPECTED_GENESIS_HASH': ZEC_GENESIS,
                    'ZCASH_NETWORK': 'regtest',
                    'WCASH_PAYOUT_ADDRESS': manifest['collector_address'],
                    'WCASH_PAYOUT_IVK_FILE': str(root / 'collector.ivk'),
                    'ZCASH_PAYOUT_ADDRESS': PARENT,
                    'WCASH_SHARE_JOURNAL': str(root / 'mining.jsonl')})
        for name, prefix in [('wec', 'WCASH_RPC'), ('zec', 'ZCASH_TEMPLATE_RPC'),
                             ('validator', 'ZCASH_VALIDATOR_RPC')]:
            user, password = (root / name / '.cookie').read_text().strip().split(':', 1)
            env[prefix + '_USERNAME'], env[prefix + '_PASSWORD'] = user, password
        initial = rpc(root, 'wec', 'getblockcount')
        for height in range(initial + 1, initial + count + 1):
            started = time.monotonic()
            result = command(root, f'mine-{height:05}', [manifest['miner_binary'],
                'native-mine', 'http://127.0.0.1:48232', 'http://127.0.0.1:18232',
                'http://127.0.0.1:18242', '-', '512', str(height * 512)], env=env)
            assert result['result'] == 'processed' and result['wcash_candidate'], result
            until(lambda: rpc(root, 'wec', 'getblockcount') >= height)
            if height == initial + 1 or height % 10 == 0 or height == initial + count:
                print(f'Real Regtest height {height}; last proof {time.monotonic()-started:.1f}s', flush=True)


def script_for(address):
    assert address.startswith('WR'), 'recipient must use the Regtest P2PKH namespace'
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = 0
    for char in address:
        value = value * 58 + alphabet.index(char)
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    raw = b'\0' * (len(address) - len(address.lstrip('1'))) + raw
    payload, checksum = raw[:-4], raw[-4:]
    assert hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum
    assert len(payload) == 22
    return '76a914' + payload[2:].hex() + '88ac'


def start(args):
    root = args.runtime.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    for ancestor in (root, *root.parents):
        if ancestor.stat().st_mode & 0o022:
            raise RuntimeError('runtime ancestors must not be group/other writable')
    private(root / 'seed.hex', secrets.token_hex(32) + '\n')
    wallet = args.wallet.resolve()
    seed = (root / 'seed.hex').read_bytes()
    collector = command(root, 'collector', [wallet, '--network', 'regtest',
        'derive-collector', '--ivk-file', root / 'collector.ivk'], stdin=seed)
    recipient = command(root, 'recipient', [wallet, '--network', 'regtest',
        'derive-address'], stdin=secrets.token_hex(32).encode() + b'\n')
    recipient_address = recipient['transparent_coinbase_address']
    validated = command(root, 'validate-recipient', [wallet, '--network', 'regtest',
        'validate-address'], stdin=(recipient_address + '\n').encode())
    assert validated == {'network': 'regtest', 'receiver_kind': 'transparent_p2pkh',
                         'canonical': recipient_address}
    processes = []
    def stop(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for name, binary in [('wec', args.wcash_node), ('zec', args.zcash_node),
                             ('validator', args.zcash_node)]:
            directory = root / name
            directory.mkdir(mode=0o700)
            network = 'WcashRegtest' if name == 'wec' else 'Regtest'
            upgrade = '' if name == 'wec' else '\n[network.testnet_parameters.activation_heights]\n"NU6.3" = 1\n'
            grpc = '\nlightwalletd_listen_addr = "127.0.0.1:48234"' if name == 'wec' else ''
            mining = 'internal_miner = false' if name == 'wec' else 'miner_address = ' + json.dumps(PARENT)
            config = f'''[network]
network = "{network}"
listen_addr = "127.0.0.1:{PORTS[name][1]}"
initial_mainnet_peers = []
initial_testnet_peers = []
cache_dir = false
peerset_initial_target_size = 1
max_connections_per_ip = 1
{upgrade}
[state]
cache_dir = {json.dumps(str(directory / 'state'))}
[rpc]
listen_addr = "127.0.0.1:{PORTS[name][0]}"
cookie_dir = {json.dumps(str(directory))}
enable_cookie_auth = true
debug_force_finished_sync = true{grpc}
[mempool]
debug_enable_at_height = 0
[mining]
extra_coinbase_data = "W1PayoutRegtest"
{mining}
[tracing]
filter = "info"
'''
            private(directory / 'node.toml', config)
            with (directory / 'node.log').open('wb') as log:
                os.chmod(log.name, 0o600)
                processes.append(subprocess.Popen([str(binary.resolve()), '-c',
                    str(directory / 'node.toml'), 'start'], stdout=log, stderr=subprocess.STDOUT,
                    env=isolated_env()))
            expected = WEC_GENESIS if name == 'wec' else ZEC_GENESIS
            until(lambda: rpc(root, name, 'getblockhash', [0]) == expected)
        common = [wallet, '--network', 'regtest', '--db', root / 'wallet.sqlite',
                  '--lightwalletd', 'http://127.0.0.1:48234']
        command(root, 'wallet-init', [*common, 'init', '--birthday', '1'], stdin=seed)
        manifest = {'wallet_binary': str(wallet), 'wallet_db': str(root / 'wallet.sqlite'),
            'seed_file': str(root / 'seed.hex'), 'lightwalletd_endpoint': 'http://127.0.0.1:48234',
            'node_rpc': '127.0.0.1:48232', 'node_cookie_file': str(root / 'wec/.cookie'),
            'recipient_address': recipient_address,
            'recipient_script': script_for(recipient_address),
            'collector_address': collector['address'], 'miner_binary': str(args.miner.resolve())}
        private(root / 'manifest.json', json.dumps(manifest, indent=2))
        mine(root, args.blocks)
        command(root, 'wallet-sync', [*common, 'sync'])
        identity = command(root, 'wallet-identity', [*common, 'payout-identity'])
        manifest.update({'source_account': identity['account_id'],
                         'collector_commitment': identity['collector_payout_commitment']})
        private(root / 'manifest.json', json.dumps(manifest, indent=2))
        command(root, 'wallet-observe', [*common, 'payout-observe'])
        print('FUNDED: ' + str(root / 'manifest.json'), flush=True)
        while all(proc.poll() is None for proc in processes):
            time.sleep(1)
        raise RuntimeError('a Regtest node exited')
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
        for proc in processes:
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--mine', type=int)
    parser.add_argument('--blocks', type=int, default=104)
    for item in ('wallet', 'miner', 'wcash-node', 'zcash-node'):
        parser.add_argument('--' + item, type=Path)
    args = parser.parse_args()
    if args.mine is not None:
        if args.mine < 1:
            parser.error('--mine must be positive')
        mine(args.runtime.resolve(), args.mine)
    else:
        if any(getattr(args, key) is None for key in ('wallet', 'miner', 'wcash_node', 'zcash_node')):
            parser.error('starting requires all four binary paths')
        start(args)
