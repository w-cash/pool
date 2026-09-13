#!/usr/bin/env python3
"""Read-only final ledger/chain check for the real local Regtest composition.

This checks live PostgreSQL and node RPC, never a prior result.json assertion.
Recipient wallet receipt and restart/replay checks are additional acceptance
evidence: this verifier does not claim to decrypt shielded transaction outputs.
"""
import argparse
import base64
import datetime
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib
import uuid
from urllib.parse import unquote, urlsplit

GENESIS = {
    'wcash': '70bf0bab17eff361a6331bb825b3b7253c8c96ff96407f948161d2912658bb1c',
    'zcash': '029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327',
}
REQUIRED_PAYMENTS = {('wcash', 'ironwood'), ('zcash', 'ironwood'), ('zcash', 'transparent')}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def display_block(wire_hex):
    require(isinstance(wire_hex, str) and len(wire_hex) == 64, 'invalid stored block hash')
    return bytes.fromhex(wire_hex)[::-1].hex()


class Verifier:
    def __init__(self, runtime):
        self.runtime = runtime.resolve()
        self.config = tomllib.loads((self.runtime / 'pool.toml').read_text())
        require(self.config.get('network') == 'regtest', 'requires explicit Regtest configuration')
        self.deployment = str(uuid.UUID(self.config['deployment_id']))

    def database_environment(self, connect_timeout=10):
        database = urlsplit(Path(self.config['database_url_file']).read_text().strip())
        require(database.scheme in ('postgres', 'postgresql')
                and database.hostname in ('127.0.0.1', 'localhost', '::1'),
                'verification requires loopback PostgreSQL')
        # libpq does not expand a URI supplied through PGDATABASE. Keep its
        # credentials out of argv and exclude inherited PostgreSQL overrides.
        env = {key: value for key, value in os.environ.items() if not key.startswith('PG')}
        env.update({'PGHOST': database.hostname, 'PGPORT': str(database.port or 5432),
                    'PGUSER': unquote(database.username or ''),
                    'PGPASSWORD': unquote(database.password or ''),
                    'PGDATABASE': unquote(database.path.lstrip('/')),
                    'PGCONNECT_TIMEOUT': str(connect_timeout)})
        return env

    def query(self, select):
        result = subprocess.run(['psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c',
                                 'SELECT COALESCE(json_agg(r),\'[]\'::json) FROM (' + select + ') r'],
                                env=self.database_environment(), capture_output=True, timeout=30)
        # Neither connection errors nor result rows are printed: they can carry
        # private connection details or account information.
        require(result.returncode == 0, 'live PostgreSQL query failed')
        return json.loads(result.stdout)

    def rpc(self, chain, method, params):
        key = {'wcash': 'wec', 'zcash': 'zec'}[chain]
        cookie = (self.runtime / key / '.cookie').read_text().strip()
        conn = http.client.HTTPConnection('127.0.0.1', {'wcash': 28232, 'zcash': 18232}[chain], timeout=30)
        try:
            conn.request('POST', '/', json.dumps({'jsonrpc': '2.0', 'id': 'verify-regtest',
                                                 'method': method, 'params': params}),
                         {'Content-Type': 'application/json',
                          'Authorization': 'Basic ' + base64.b64encode(cookie.encode()).decode()})
            response = conn.getresponse()
            require(response.status == 200, 'live node RPC HTTP failure')
            body = json.loads(response.read())
        finally:
            conn.close()
        require(not body.get('error'), 'live node RPC method failed')
        return body['result']

    def canonical_transaction(self, chain, height, wire_block_hash, txid, depth, *, coinbase=False):
        block_hash = self.rpc(chain, 'getblockhash', [height])
        require(block_hash == display_block(wire_block_hash), 'stored block is outside the current best chain')
        block = self.rpc(chain, 'getblock', [block_hash, 1])
        require(block.get('height') == height and block.get('confirmations', 0) >= depth,
                'block has insufficient independent node confirmations')
        require(txid in block.get('tx', []), 'stored transaction is absent from the independently fetched block')
        if coinbase:
            require(block['tx'][0] == txid, 'stored winner transaction is not the actual coinbase')

    def run(self):
        dep = "'" + self.deployment + "'::uuid"
        identity = self.query(f"SELECT network,encode(wcash_genesis,'hex') AS wcash_genesis,"
                              f"encode(zcash_genesis,'hex') AS zcash_genesis FROM deployments WHERE id={dep}")
        require(len(identity) == 1 and identity[0]['network'] == 'regtest',
                'database deployment is not the exact Regtest identity')
        for chain, expected in GENESIS.items():
            require(display_block(identity[0][chain + '_genesis']) == expected,
                    'database genesis differs from frozen Regtest identity')
        version = self.query("SELECT current_setting('server_version_num')::int AS version")[0]['version']
        require(version >= 160000, 'requires PostgreSQL 16 or newer')
        tips = {}
        for chain, expected in GENESIS.items():
            require(self.rpc(chain, 'getblockhash', [0]) == expected, 'node genesis differs from frozen Regtest identity')
            tips[chain] = self.rpc(chain, 'getblockcount', [])
        shares = self.query(f"SELECT count(*) AS count FROM shares WHERE deployment_id={dep}")[0]['count']
        require(shares > 0, 'no actual projected miner shares')
        invalid = self.query(f"""SELECT t.id FROM ledger_transactions t
            LEFT JOIN ledger_entries e ON (e.deployment_id,e.transaction_id)=(t.deployment_id,t.id)
            WHERE t.deployment_id={dep} GROUP BY t.id,t.sealed_at,t.sealed_entry_count
            HAVING t.sealed_at IS NULL OR count(e.line_no) <> t.sealed_entry_count
                OR COALESCE(sum(e.amount_zat),1) <> 0""")
        require(not invalid, 'ledger contains an unsealed or non-conserving transaction')
        winners = self.query(f"""SELECT w.chain,w.height,encode(w.block_hash_le,'hex') AS block_hash,
            encode(w.coinbase_txid_le,'hex') AS coinbase,w.maturity_confirmations,
            EXISTS (SELECT 1 FROM ledger_transactions t JOIN ledger_entries e
                ON (e.deployment_id,e.transaction_id)=(t.deployment_id,t.id)
                WHERE t.deployment_id=w.deployment_id AND t.chain=w.chain
                AND t.backend_event_seq=w.active_maturity_event_seq AND t.kind='winner_matured'
                AND e.ledger_account='miner_payable' AND e.amount_zat < 0) AS has_miner_credit
            FROM winners w WHERE w.deployment_id={dep} AND w.state='matured'""")
        require({row['chain'] for row in winners} == set(GENESIS), 'missing mature miner credit on one or both chains')
        for row in winners:
            require(row['has_miner_credit'], 'matured winner is missing its active miner credit posting')
            require(row['maturity_confirmations'] >= 100, 'coinbase maturity policy was shortened')
            self.canonical_transaction(row['chain'], row['height'], row['block_hash'],
                                       display_block(row['coinbase']), row['maturity_confirmations'], coinbase=True)
        payouts = self.query(f"""SELECT b.id,b.chain,encode(b.transaction_id,'hex') AS txid,
            encode(b.confirmation_block_hash,'hex') AS block_hash,b.confirmation_height AS height,
            b.confirmation_count,p.required_confirmations,d.receiver_kind,i.account_id,i.amount_zat,
            i.liability_amount_zat,b.network_fee_zat,
            (SELECT count(*) FROM ledger_transactions t WHERE t.deployment_id=b.deployment_id
             AND t.chain=b.chain AND t.kind='payout_confirmed' AND t.reference=b.id::text) AS postings
            FROM payout_batches b JOIN payout_items i ON (i.deployment_id,i.batch_id)=(b.deployment_id,b.id)
            JOIN payout_destinations d ON (d.deployment_id,d.id)=(i.deployment_id,i.destination_id)
            JOIN chain_policies p ON (p.deployment_id,p.chain,p.policy_version)=(b.deployment_id,b.chain,b.policy_version)
            WHERE b.deployment_id={dep} AND b.state='confirmed'""")
        require(REQUIRED_PAYMENTS <= {(r['chain'], r['receiver_kind']) for r in payouts},
                'missing confirmed Wcash shielded, Zcash shielded, or Zcash transparent payout')
        settlement = self.query(f"""SELECT t.reference AS batch_id,e.account_id,e.ledger_account,e.amount_zat
            FROM ledger_transactions t JOIN ledger_entries e
              ON (e.deployment_id,e.transaction_id)=(t.deployment_id,t.id)
            JOIN payout_batches b ON b.deployment_id=t.deployment_id AND b.id::text=t.reference
              AND b.chain=t.chain AND b.state='confirmed'
            WHERE t.deployment_id={dep} AND t.kind='payout_confirmed'""")
        check_settlement(payouts, settlement)
        seen = set()
        for row in payouts:
            require(row['required_confirmations'] >= 100
                    and row['confirmation_count'] >= row['required_confirmations'],
                    'payout confirmation policy was shortened or not met')
            require(row['postings'] == 1, 'confirmed payout must have exactly one settlement ledger posting')
            require(0 < row['amount_zat'] <= row['liability_amount_zat'] and row['network_fee_zat'] >= 0,
                    'payout value or fee is invalid')
            key = (row['chain'], row['id'])
            if key not in seen:
                self.canonical_transaction(row['chain'], row['height'], row['block_hash'],
                                           row['txid'], row['required_confirmations'])
                seen.add(key)
        return {'checked_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'source': 'live PostgreSQL and both node RPCs', 'network': 'regtest',
                'postgres_major': version // 10000, 'chain_heights': tips,
                'projected_shares': shares, 'canonical_mature_winners': len(winners),
                'canonical_confirmed_payout_batches': len(seen),
                'recipient_profiles': [list(x) for x in sorted(REQUIRED_PAYMENTS)],
                'ledger_conserves': True,
                'additional_required_evidence': ['recipient wallet receipts', 'restart and replay scenario',
                                                 'production feature guards', 'Ubuntu role and origin isolation']}


def check_settlement(payouts, settlement):
    for batch in {r['id'] for r in payouts}:
        items = [r for r in payouts if r['id'] == batch]
        lines = [r for r in settlement if r['batch_id'] == batch]
        fee = items[0]['network_fee_zat']
        net = sum(r['amount_zat'] for r in items)
        gross = sum(r['liability_amount_zat'] for r in items)
        require(0 <= fee <= gross - net, 'settled fee exceeds the miner reserve')
        expected_accounts = {r['account_id']: r['liability_amount_zat'] for r in items}
        pending = {}
        totals = {}
        for row in lines:
            account, kind, amount = row['account_id'], row['ledger_account'], row['amount_zat']
            totals[kind] = totals.get(kind, 0) + amount
            if kind == 'payout_pending':
                require(account in expected_accounts and amount > 0, 'invalid pending liability settlement account')
                pending[account] = pending.get(account, 0) + amount
            elif kind == 'miner_payable':
                require(account in expected_accounts and amount < 0, 'invalid miner fee refund account')
            else:
                require(account is None, 'pool settlement entry unexpectedly identifies a miner account')
        expected = {'payout_pending': gross, 'collector_spendable_asset': -(net + fee),
                    'miner_payable': -(gross - net - fee), 'network_fee_expense': fee,
                    'miner_network_fee_contribution': -fee}
        require(pending == expected_accounts, 'settlement does not discharge the exact per-miner liabilities')
        require({k: v for k, v in totals.items() if v} == {k: v for k, v in expected.items() if v},
                'settlement does not conserve the exact payout, fee, and refund amounts')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = Verifier(args.runtime).run()
    except RuntimeError as error:
        print('FAIL: ' + str(error) + '; no certificate emitted.', file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError,
            http.client.HTTPException):
        print('FAIL: live Regtest ledger/chain acceptance has not passed; no certificate emitted.', file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
