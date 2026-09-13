#!/usr/bin/env python3
"""Real local node/backend/PostgreSQL/portal/ZIP-301 composition.

Requires explicitly regtest-enabled binaries. Credentials and wallet material stay
inside a mode-0700 runtime directory. No wallet or chain responses are fabricated.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import time
import uuid

WEC_GENESIS = '70bf0bab17eff361a6331bb825b3b7253c8c96ff96407f948161d2912658bb1c'
ZEC_GENESIS = '029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327'
TARGET = '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'


def private(path, value):
    path.write_bytes(value if isinstance(value, bytes) else value.encode())
    path.chmod(0o600)


class RpcNotReady(Exception):
    """A node has not yet opened its local chain state."""


class Harness:
    def __init__(self, args):
        self.args = args
        self.root = args.runtime.resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root.chmod(0o700)
        self.processes = []
        self.cookies = {}
        self.csrf = None
        self.origin = 'https://localhost:18443'

    def command(self, label, command, *, env=None, stdin=None, timeout=300):
        result = subprocess.run([str(x) for x in command], input=stdin, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        private(self.root / (label + '.stdout'), result.stdout)
        private(self.root / (label + '.stderr'), result.stderr)
        if result.returncode:
            raise RuntimeError(f'{label} failed; protected diagnostic files retained')
        return result.stdout

    def spawn(self, label, command, *, env=None):
        log = open(self.root / (label + '.log'), 'wb')
        os.chmod(log.name, 0o600)
        proc = subprocess.Popen([str(x) for x in command], stdout=log, stderr=subprocess.STDOUT,
                                env=env, start_new_session=True)
        log.close()
        self.processes.append((label, proc))
        private(self.root / 'processes.json', json.dumps({name: p.pid for name, p in self.processes}))
        return proc

    def alive(self):
        for name, proc in self.processes:
            if proc.poll() is not None:
                raise RuntimeError(f'{name} exited; protected diagnostic file retained')

    def until(self, label, check, seconds=90):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.alive()
            try:
                value = check()
                if value:
                    return value
            except (OSError, ValueError, http.client.HTTPException, RpcNotReady):
                pass
            time.sleep(0.25)
        raise RuntimeError(f'{label} did not become ready')

    def rpc(self, name, method, params=None):
        port = {'wec': 28232, 'zec': 18232, 'validator': 18242}[name]
        cookie = (self.root / name / '.cookie').read_text().strip()
        headers = {'Content-Type': 'application/json',
                   'Authorization': 'Basic ' + base64.b64encode(cookie.encode()).decode()}
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
        try:
            conn.request('POST', '/', json.dumps({'jsonrpc': '2.0', 'id': 'full-pool-regtest',
                                                 'method': method, 'params': params or []}), headers)
            response = json.loads(conn.getresponse().read())
        finally:
            conn.close()
        if response.get('error'):
            if response['error'].get('code') in (-28, -10):
                raise RpcNotReady()
            raise RuntimeError(f'{name}.{method} returned an RPC error')
        return response['result']

    def portal(self, route, payload=None, method=None):
        conn = http.client.HTTPConnection('127.0.0.1', 18080, timeout=30)
        headers = {'Origin': self.origin, 'Host': 'localhost:18443', 'Content-Type': 'application/json'}
        if self.cookies:
            headers['Cookie'] = '; '.join(k + '=' + v for k, v in self.cookies.items())
        if self.csrf:
            headers['X-CSRF-Token'] = self.csrf
        try:
            conn.request(method or ('POST' if payload is not None else 'GET'), route,
                         json.dumps(payload) if payload is not None else None, headers)
            response = conn.getresponse()
            for name, value in response.getheaders():
                if name.lower() == 'set-cookie':
                    key, val = value.split(';', 1)[0].split('=', 1)
                    self.cookies[key] = val
            raw = response.read()
            if response.status >= 400:
                raise RuntimeError(f'portal {route} returned HTTP {response.status}')
            return json.loads(raw) if raw else None
        finally:
            conn.close()

    def node_config(self, name, collector):
        directory = self.root / name
        directory.mkdir(mode=0o700, exist_ok=True)
        network = 'WcashRegtest' if name == 'wec' else 'Regtest'
        rpc, peer = {'wec': (28232, 28233), 'zec': (18232, 18233), 'validator': (18242, 18243)}[name]
        upgrade = '' if name == 'wec' else '\n[network.testnet_parameters.activation_heights]\n"NU6.3" = 1\n'
        mining = 'internal_miner = false\n' if name == 'wec' else 'miner_address = ' + json.dumps(collector) + '\n'
        text = f'''[network]
network = "{network}"
listen_addr = "127.0.0.1:{peer}"
initial_mainnet_peers = []
initial_testnet_peers = []
cache_dir = false
peerset_initial_target_size = 1
max_connections_per_ip = 1
{upgrade}
[state]
cache_dir = {json.dumps(str(directory / 'state'))}

[rpc]
listen_addr = "127.0.0.1:{rpc}"
cookie_dir = {json.dumps(str(directory))}
enable_cookie_auth = true
debug_force_finished_sync = true
lightwalletd_listen_addr = "127.0.0.1:{19067 if name == 'wec' else 19068 if name == 'zec' else 19069}"

[mining]
extra_coinbase_data = "FullPoolRegtest"
{mining}
[tracing]
filter = "info"
'''
        path = directory / 'node.toml'
        private(path, text)
        return path

    def run(self):
        args = self.args
        pg_env = os.environ.copy()
        pg_env['PGDATABASE'] = args.database_url_file.read_text().strip()
        version = int(self.command('postgres-version', ['psql', '-Atqc', 'SHOW server_version_num'], env=pg_env))
        if version // 10000 != 16:
            raise RuntimeError('full composition requires PostgreSQL16')
        collector = args.zec_collector_file.read_text().strip()
        if not collector:
            raise RuntimeError('a wallet-owned ZEC collector address is required')
        seed = self.root / 'wec.seed'
        if not seed.exists():
            private(seed, secrets.token_hex(32) + '\n')
        derived_file = self.root / 'wec-collector.json'
        if not derived_file.exists():
            derived = self.command('derive-wec-collector', [args.wallet, '--network', 'regtest',
                'derive-collector', '--ivk-file', self.root / 'wec.ivk'], stdin=seed.read_bytes())
            private(derived_file, derived)
        wec_collector = json.loads(derived_file.read_text())['address']
        for name, binary in [('wec', args.wcash_node), ('zec', args.zcash_node), ('validator', args.zcash_node)]:
            self.spawn(name, [binary, '-c', self.node_config(name, collector), 'start'])
            expected = WEC_GENESIS if name == 'wec' else ZEC_GENESIS
            self.until(name + ' genesis', lambda n=name, e=expected: self.rpc(n, 'getblockhash', [0]) == e)
        env = os.environ.copy()
        env.update({'WCASH_EXPECTED_GENESIS_HASH': WEC_GENESIS, 'ZCASH_EXPECTED_GENESIS_HASH': ZEC_GENESIS,
                    'ZCASH_NETWORK': 'regtest', 'WCASH_PAYOUT_ADDRESS': wec_collector,
                    'WCASH_PAYOUT_IVK_FILE': str(self.root / 'wec.ivk'), 'ZCASH_PAYOUT_ADDRESS': collector,
                    'WCASH_POOL_BACKEND_IDENTITY': str(self.root / 'backend.identity'),
                    'WCASH_POOL_BACKEND_JOURNAL': str(self.root / 'backend.journal'),
                    'WCASH_POOL_BACKEND_SOCKET': str(self.root / 'backend.sock'),
                    'WCASH_POOL_BACKEND_SUBMIT_UID': str(os.getuid()),
                    'WCASH_POOL_BACKEND_PROJECTOR_UID': str(os.getuid() + 1),
                    'WCASH_POOL_BACKEND_PAYOUT_UID': str(os.getuid() + 2),
                    'WCASH_POOL_BACKEND_SOCKET_GID': str(os.getgid()), 'WCASH_SHARE_TARGET': TARGET})
        for name, prefix in [('wec', 'WCASH_RPC'), ('zec', 'ZCASH_TEMPLATE_RPC'), ('validator', 'ZCASH_VALIDATOR_RPC')]:
            user, password = (self.root / name / '.cookie').read_text().strip().split(':', 1)
            env[prefix + '_USERNAME'], env[prefix + '_PASSWORD'] = user, password
        urls = ['http://127.0.0.1:28232', 'http://127.0.0.1:18232', 'http://127.0.0.1:18242', '-']
        authority = json.loads(self.command('backend-init', [args.miner, 'pool-backend-init', *urls], env=env))
        self.spawn('backend', [args.miner, 'native-pool-backend', *urls], env=env)
        self.until('backend socket', lambda: (self.root / 'backend.sock').exists())
        config = self.write_pool_config(authority)
        self.command('pool-config', [args.poold, 'config-check', '--config', config])
        self.command('pool-migrate', [args.poold, 'migrate', '--config', config])
        self.spawn('projector', [args.poold, 'projector', '--config', config])
        self.spawn('poold', [args.poold, 'serve', '--config', config])
        self.until('portal', lambda: self.portal('/healthz'))
        password = secrets.token_urlsafe(32)
        account = self.portal('/api/v1/auth/register', {'username': 'regtest_team', 'password': password})
        login = self.portal('/api/v1/auth/login', {'username': 'regtest_team', 'password': password})
        self.csrf = login['csrf_token']
        worker = self.portal('/api/v1/workers', {'label': 'asic_1'})['worker']
        private(self.root / 'portal-session.json', json.dumps({'account': account, 'password': password,
                'worker': worker, 'cookies': self.cookies, 'csrf': self.csrf}))
        miner_env = os.environ.copy()
        miner_env['WCASH_STRATUM_PASSWORD'] = worker['token']
        for height in range(1, args.blocks + 1):
            started = time.monotonic()
            proof = self.command(f'zip301-mine-{height:04}', [args.miner, 'zip301-mine',
                                '127.0.0.1:18237', worker['mining_username'], '256', '0'],
                                env=miner_env, timeout=900)
            if json.loads(proof).get('result') != 'accepted':
                raise RuntimeError('real ZIP-301 submission was not accepted')
            self.until('Wcash chain win', lambda: self.rpc('wec', 'getblockcount') >= height)
            self.until('Zcash chain win', lambda: self.rpc('zec', 'getblockcount') >= height)
            if height == 1 or height % 10 == 0 or height == args.blocks:
                print(f'Real ZIP-301 chain wins: height {height}, last proof {time.monotonic()-started:.1f}s', flush=True)
        blocks = self.until('projected pool wins', lambda: self.two_chain_blocks())
        result = {'network': 'regtest', 'postgres_major': version // 10000, 'portal_account_created': True,
                  'worker_created': True, 'real_zip301_solver': True, 'mined_blocks_per_chain': args.blocks, 'blocks': blocks,
                  'balances': self.portal('/api/v1/balances'),
                  'limitations': ['Local functional processes share one Unix UID; production role isolation is tested separately.',
                                  'Portal HTTP is exercised behind its exact HTTPS origin contract; TLS termination is tested separately.']}
        private(self.root / 'result.json', json.dumps(result, indent=2))
        print('PASS mining stage: real portal account, worker, ZIP-301 proofs, both chains, and PostgreSQL projection', flush=True)
        if args.keep_running:
            print('Services remain available for real wallet payout integration; Ctrl-C stops only this harness.', flush=True)
            while True:
                self.alive()
                time.sleep(1)

    def two_chain_blocks(self):
        result = self.portal('/api/v1/blocks')
        items = result.get('items', [])
        return result if {'wec', 'zec'} <= {item.get('asset') for item in items} else None

    def write_pool_config(self, authority):
        network_target = self.rpc('zec', 'getblocktemplate')['target']
        if (not isinstance(network_target, str) or len(network_target) != 64
                or not 0 < int(network_target, 16) <= int(TARGET, 16)):
            raise RuntimeError('invalid regtest network target')
        for name in ('pepper', 'totp'):
            if not (self.root / name).exists():
                private(self.root / name, secrets.token_bytes(32))
        values = {'network': 'regtest', 'deployment_id': str(uuid.uuid4()), 'pool_instance': str(uuid.uuid4()),
                  **{key: authority[key] for key in ('backend_instance', 'journal_stream', 'chain_id',
                     'wcash_genesis', 'zcash_genesis', 'wcash_payout_commitment', 'zcash_payout_commitment')},
                  'backend_socket': str(self.root / 'backend.sock'), 'database_url_file': str(self.args.database_url_file.resolve()),
                  'stratum_listen': '127.0.0.1:18237', 'portal_listen': '127.0.0.1:18080', 'portal_origin': self.origin,
                  'nonce_namespace': 1, 'nonce_reservation': 1000, 'database_connections': 8,
                  'maximum_miners': 8, 'maximum_miners_per_ip': 8, 'authentication_parallelism': 2,
                  'wcash_wallet_program': str(self.args.wallet.resolve()),
                  'wcash_wallet_sha256': hashlib.sha256(self.args.wallet.read_bytes()).hexdigest(),
                  'wcash_wallet_uid': os.getuid(), 'payout_mode': 'deferred',
                  'wcash_node_rpc': '127.0.0.1:28232', 'wcash_node_cookie_file': str(self.root / 'wec' / '.cookie'),
                  'zcash_node_rpc': '127.0.0.1:18232', 'zcash_node_cookie_file': str(self.root / 'zec' / '.cookie'),
                  'portal_token_pepper_file': str(self.root / 'pepper'), 'portal_totp_key_file': str(self.root / 'totp'),
                  # A first accepted ordinary share need not win a block. Assign
                  # the actual fixed Regtest network target for this winner test.
                  'initial_share_target_be': network_target, 'easiest_share_target_be': TARGET}
        path = self.root / 'pool.toml'
        text = '\n'.join(key + ' = ' + json.dumps(value) for key, value in values.items()) + '\n'
        for asset in ('wcash', 'zcash'):
            text += f'''\n[{asset}_policy]
pplns_window_work = "1"
payout_threshold_zat = 100000
required_confirmations = 100
maximum_payout_outputs = 10
maximum_network_fee_zat = 1000000
maximum_network_fee_bps = 1000
policy_version = 1
'''
        private(path, text)
        return path

    def close(self):
        for name, proc in reversed(self.processes):
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for name, proc in reversed(self.processes):
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('runtime', 'database-url-file', 'zec-collector-file', 'wallet', 'miner', 'wcash-node', 'zcash-node', 'poold'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--blocks', type=int, default=101, help='Real merged blocks; 101 preserves the100-confirmation maturity policy')
    parser.add_argument('--keep-running', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.blocks <= 1000:
        parser.error('--blocks must be in1..1000')
    harness = Harness(args)
    try:
        harness.run()
    finally:
        harness.close()


if __name__ == '__main__':
    main()
