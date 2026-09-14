#!/usr/bin/env python3
"""Replay one real ZIP-301 proof on its original authorized local connection.

Run only after the local harness mining stage is idle. This launches one native
miner through a loopback-only proxy. Raw messages and miner output stay in a
new private evidence directory. It does not restart any pool or node service.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import selectors
import socket
import stat
import subprocess
import sys
import time
import uuid

from verify import GENESIS, Verifier, display_block, require

MAX_LINE = 262144
IDLE_DEADLINE_SECONDS = 20
PROJECTION_DEADLINE_SECONDS = 30


class ReplayVerifier(Verifier):
    """Keep each live query inside the bounded replay check deadline."""
    query_deadline = None

    def rpc(self, chain, method, params):
        timeout = 2 if self.query_deadline is None else min(2, self.query_deadline - time.monotonic())
        require(timeout > 0, 'node preflight deadline reached before replay')
        return super().rpc(chain, method, params, timeout=timeout)

    def query(self, select):
        timeout = 2 if self.query_deadline is None else min(2, self.query_deadline - time.monotonic())
        require(timeout > 0, 'projection query deadline reached before replay')
        result = subprocess.run(['psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c',
                                 "SELECT COALESCE(json_agg(r),'[]'::json) FROM (" + select + ') r'],
                                env=self.database_environment(connect_timeout=2), capture_output=True, timeout=timeout)
        require(result.returncode == 0, 'live PostgreSQL replay query failed')
        return json.loads(result.stdout)


def private_file(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')


def encode(message):
    return (json.dumps(message, separators=(',', ':')) + '\n').encode()


def retained_side_chain_is_idle(row, status):
    """Unknown is usable only after exact durable side-chain evidence, never alone."""
    winner = {'chain': row['chain'], 'block_hash_le': row['block'], 'height': row['height'],
              'coinbase_txid_le': row['coinbase'], 'reward_zat': row['reward'],
              'maturity_confirmations': row['maturity']}
    require(row['chain'] == 'zcash' and row['inactive'] is True
            and row['allocations'] == 0 and row['credit'] == 0,
            'retained side-chain candidate has active economic state')
    require(row['proofs'] == [{'share': row['share'], 'job': row['job'], 'state': 'side_chain'}],
            'retained side-chain candidate lacks its exact proof state')
    event, committed = row['event'], row['committed']
    require(isinstance(event, dict) and event.get('event') == 'winner_side_chain'
            and event.get('share_id') == row['share'] and event.get('job_id') == row['job']
            and event.get('winner') == winner
            and type(event.get('event_seq')) is int and event['event_seq'] > row['committed_seq'],
            'retained side-chain candidate lacks matching durable classification')
    tip = event.get('tip', {})
    require(isinstance(tip, dict) and type(tip.get('height')) is int and tip['height'] >= 0
            and isinstance(tip.get('block_hash_le'), str) and len(tip['block_hash_le']) == 64
            and tip['block_hash_le'] != row['block'], 'durable side-chain tip evidence is invalid')
    require(len(bytes.fromhex(tip['block_hash_le'])) == 32, 'invalid durable side-chain tip hash')
    require(isinstance(committed, dict) and committed.get('event') == 'share_committed'
            and committed.get('job_id') == row['job'], 'side-chain committed job evidence differs')
    receipt = committed.get('receipt', {})
    require(receipt.get('share_id') == row['share'] and receipt.get('job_id') == row['job']
            and receipt.get('event_seq') == row['committed_seq']
            and receipt.get('parent_hash_le') == row['block']
            and winner in receipt.get('winners', []), 'side-chain committed receipt evidence differs')
    require(isinstance(status, dict), 'invalid exact side-chain node status')
    if status == {'state': 'unknown'}:
        # The native node may prune a previously classified noncanonical fork.
        # The earlier exact durable event, not Unknown, supplies the evidence.
        return True
    require(status.get('hash') == display_block(row['block'])
            and status.get('height') == row['height'], 'side-chain node identity differs')
    if status.get('state') == 'best_chain':
        require(set(status) == {'state', 'hash', 'height', 'confirmations'}
                and type(status['confirmations']) is int and status['confirmations'] > 0,
                'invalid exact canonical node status')
        return False  # Await the actual positive projection, never fabricate it.
    require(set(status) == {'state', 'hash', 'height'} and status.get('state') == 'side_chain',
            'invalid exact side-chain node classification')
    return True


class ReplayExchange:
    """Protocol state only; fixture tests of this class are not live evidence."""
    def __init__(self):
        self.original = None
        self.accepted = None
        self.replay_id = 'regtest-replay-' + uuid.uuid4().hex
        self.replay_sent = False
        self.rejection_code = None
        self.response_mode = None

    def request(self, message):
        require(message.get('id') != self.replay_id, 'replay request ID collision')
        if message.get('method') == 'mining.submit':
            require(self.original is None, 'native miner submitted more than one proof')
            require(message.get('id') is not None and isinstance(message.get('params'), list),
                    'invalid native mining submission')
            self.original = message

    def response(self, message):
        if self.original is not None and message.get('id') == self.original['id']:
            require(self.accepted is None, 'duplicate original submission response')
            require(message.get('result') is True and message.get('error') is None,
                    'original real proof was not accepted')
            self.accepted = message
            return 'accepted'
        if message.get('id') == self.replay_id:
            require(self.replay_sent and self.accepted is not None, 'unsolicited replay response')
            error = message.get('error')
            if message.get('result') is True and error is None:
                self.response_mode = 'idempotent_success'
                return 'replayed'
            require((message.get('result') is None or message.get('result') is False)
                    and isinstance(error, list) and len(error) >= 2
                    and type(error[0]) is int and error[0] in (21, 22),
                    'replay response is neither idempotent success nor stale/duplicate rejection')
            self.rejection_code = error[0]
            self.response_mode = 'stale' if error[0] == 21 else 'duplicate'
            return 'replayed'
        return 'forward'

    def replay(self):
        require(self.accepted is not None and not self.replay_sent, 'invalid replay state')
        self.replay_sent = True
        return {**self.original, 'id': self.replay_id}


class LedgerCheck:
    def __init__(self, verifier, worker_id):
        self.verifier = verifier
        self.dep = "'" + verifier.deployment + "'::uuid"
        self.worker = "'" + str(uuid.UUID(worker_id)) + "'::uuid"
        require(verifier.query(f'SELECT network FROM deployments WHERE id={self.dep}')
                == [{'network': 'regtest'}], 'database deployment is not Regtest')
        self.before = self.counts()
        self.projected = None
        self.job = None
        self.original_facts = None

    def require_idle(self):
        deadline = time.monotonic() + IDLE_DEADLINE_SECONDS
        self.verifier.query_deadline = deadline
        try:
            for chain, genesis in GENESIS.items():
                require(self.verifier.rpc(chain, 'getblockhash', [0]) == genesis,
                        'replay preflight node is not the exact Regtest chain')
            while time.monotonic() < deadline:
                before = self.idle_snapshot()
                require(before['total'] == self.before['total'] and before['worker'] == self.before['worker'],
                        'other mining is active; wait before replay')
                if before['pending']:
                    time.sleep(0.25)
                    continue
                tips = self.node_tips()
                rows = self.side_chains()
                classified = all(retained_side_chain_is_idle(row, self.verifier.rpc(
                    row['chain'], 'getblockstatus', [display_block(row['block'])])) for row in rows)
                time.sleep(min(0.5, max(0, deadline - time.monotonic())))
                after = self.idle_snapshot()
                if classified and before == after and tips == self.node_tips():
                    self.retained_side_chain_count = len(rows)
                    return
            raise RuntimeError('winner projections or independent node tips did not become idle before replay')
        finally:
            self.verifier.query_deadline = None

    def node_tips(self):
        tips = {chain: self.verifier.rpc(chain, 'getbestblockhash', []) for chain in GENESIS}
        require(all(isinstance(tip, str) and len(tip) == 64 and len(bytes.fromhex(tip)) == 32
                    for tip in tips.values()), 'invalid independent node tip')
        return tips

    def idle_snapshot(self):
        rows = self.verifier.query(f'''SELECT
            (SELECT count(*) FROM shares WHERE deployment_id={self.dep}) AS total,
            (SELECT count(*) FROM shares WHERE deployment_id={self.dep} AND worker_id={self.worker}) AS worker,
            (SELECT count(*) FROM winners WHERE deployment_id={self.dep} AND state IN ('submitted','requeued')) AS pending,
            (SELECT md5(COALESCE(jsonb_agg(to_jsonb(w) ORDER BY w.chain,w.block_hash_le)::TEXT,''))
             FROM winners w WHERE w.deployment_id={self.dep}) AS winners,
            (SELECT md5(COALESCE(jsonb_agg(to_jsonb(p) ORDER BY p.chain,p.block_hash_le,p.share_id)::TEXT,''))
             FROM winner_proofs p WHERE p.deployment_id={self.dep}) AS proofs,
            (SELECT md5(COALESCE(jsonb_agg(to_jsonb(a) ORDER BY a.chain,a.block_hash_le,a.observation_event_seq,a.account_id)::TEXT,''))
             FROM winner_allocations a WHERE a.deployment_id={self.dep}) AS allocations,
            (SELECT md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id)::TEXT,''))
             FROM ledger_transactions t WHERE t.deployment_id={self.dep} AND t.kind LIKE 'winner_%') AS credit''')
        require(len(rows) == 1, 'invalid idle snapshot query')
        return rows[0]

    def side_chains(self):
        return self.verifier.query(f'''SELECT w.chain,w.height,encode(w.block_hash_le,'hex') AS block,
            encode(w.share_id,'hex') AS share,encode(w.job_id,'hex') AS job,
            encode(w.coinbase_txid_le,'hex') AS coinbase,w.reward_zat AS reward,w.maturity_confirmations AS maturity,
            (w.active_proof_share_id IS NULL AND w.active_observation_event_seq IS NULL AND w.active_maturity_event_seq IS NULL) AS inactive,
            (SELECT count(*) FROM winner_allocations a WHERE (a.deployment_id,a.chain,a.block_hash_le)=(w.deployment_id,w.chain,w.block_hash_le)) AS allocations,
            (SELECT count(*) FROM ledger_transactions t WHERE t.deployment_id=w.deployment_id AND t.chain=w.chain
             AND t.reference=w.chain || ':' || encode(w.block_hash_le,'hex')) AS credit,
            (SELECT jsonb_agg(jsonb_build_object('share',encode(p.share_id,'hex'),'job',encode(p.job_id,'hex'),'state',p.state) ORDER BY p.share_id)
             FROM winner_proofs p WHERE (p.deployment_id,p.chain,p.block_hash_le)=(w.deployment_id,w.chain,w.block_hash_le)) AS proofs,
            c.event_seq AS committed_seq,c.payload AS committed,
            (SELECT e.payload FROM backend_events e WHERE e.deployment_id=w.deployment_id AND e.event_kind='winner_side_chain'
             AND e.payload->>'share_id'=encode(w.share_id,'hex') AND e.payload->>'job_id'=encode(w.job_id,'hex')
             AND e.payload->'winner'->>'block_hash_le'=encode(w.block_hash_le,'hex') ORDER BY e.event_seq DESC LIMIT 1) AS event
            FROM winners w JOIN shares s ON (s.deployment_id,s.share_id)=(w.deployment_id,w.share_id)
            JOIN backend_events c ON (c.deployment_id,c.event_seq)=(s.deployment_id,s.event_seq)
            WHERE w.deployment_id={self.dep} AND w.state='side_chain' ORDER BY w.chain,w.block_hash_le''')

    def counts(self):
        rows = self.verifier.query(f'''SELECT count(*) AS total,
            count(*) FILTER (WHERE worker_id={self.worker}) AS worker
            FROM shares WHERE deployment_id={self.dep}''')
        require(len(rows) == 1, 'invalid share count query')
        return rows[0]

    def winner_facts(self):
        return self.verifier.query(f'''SELECT w.chain,w.state,encode(w.share_id,'hex') AS share,
            encode(w.block_hash_le,'hex') AS block,
            (SELECT json_agg(r ORDER BY r.observation_event_seq,r.account_id) FROM
                (SELECT a.observation_event_seq,a.account_id,a.amount_zat,a.selected_work::TEXT
                 FROM winner_allocations a WHERE a.deployment_id=w.deployment_id
                 AND a.chain=w.chain AND a.block_hash_le=w.block_hash_le) r) AS allocations,
            (SELECT json_agg(r ORDER BY r.id,r.line_no) FROM
                (SELECT t.id,t.kind,e.line_no,e.account_id,e.ledger_account,e.amount_zat
                 FROM ledger_transactions t JOIN ledger_entries e
                 ON (e.deployment_id,e.transaction_id)=(t.deployment_id,t.id)
                 WHERE t.deployment_id=w.deployment_id AND t.chain=w.chain
                 AND t.reference=w.chain || ':' || encode(w.block_hash_le,'hex')) r) AS credit
            FROM winners w JOIN shares s
              ON (s.deployment_id,s.share_id)=(w.deployment_id,w.share_id)
            WHERE s.deployment_id={self.dep} AND s.worker_id={self.worker}
              AND s.job_id=decode('{self.job}','hex') ORDER BY w.chain,w.block_hash_le''')

    def await_original(self, submission, *, deadline=None):
        params = submission['params']
        require(len(params) == 5 and isinstance(params[1], str) and len(params[1]) == 64,
                'native proof does not contain an exact job ID')
        self.job = bytes.fromhex(params[1]).hex()
        # Acceptance has already reached the one-shot miner. Its independent
        # upstream connection remains authorized while real winners project.
        projection_deadline = time.monotonic() + PROJECTION_DEADLINE_SECONDS
        deadline = projection_deadline if deadline is None else min(deadline, projection_deadline)
        self.verifier.query_deadline = deadline
        expected = {key: value + 1 for key, value in self.before.items()}
        try:
            while time.monotonic() < deadline:
                current = self.counts()
                require(all(self.before[key] <= current[key] <= expected[key] for key in expected),
                        'share count changed unexpectedly; run with other mining stopped')
                if current == expected:
                    facts = self.winner_facts()
                    # The harness assigns the actual Regtest network target. This
                    # proof must produce one observed winner and allocation on each
                    # chain before its replay can be compared without projection lag.
                    if (len(facts) == 2 and {row['chain'] for row in facts} == {'wcash', 'zcash'}
                            and len({row['share'] for row in facts}) == 1
                            and all(row['state'] in ('observed', 'matured')
                                    and row['allocations'] and row['credit'] for row in facts)):
                        self.projected = current
                        self.original_facts = facts
                        return
                time.sleep(min(0.2, max(0, deadline - time.monotonic())))
            raise RuntimeError('original share and both winner allocations did not project before replay')
        finally:
            self.verifier.query_deadline = None

    def verify_unchanged(self, seconds):
        require(self.projected is not None, 'original share projection was not checked')
        deadline = time.monotonic() + seconds
        while True:
            require(self.counts() == self.projected, 'share count increased after replay')
            require(self.winner_facts() == self.original_facts,
                    'winner allocations or reward ledger entries changed after replay')
            if time.monotonic() >= deadline:
                return
            time.sleep(0.25)


def proxy(downstream, upstream, transcript, before_replay, after_replay, deadline):
    exchange = ReplayExchange()
    buffers = {downstream: bytearray(), upstream: bytearray()}
    with selectors.DefaultSelector() as selector:
        selector.register(downstream, selectors.EVENT_READ)
        selector.register(upstream, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            for key, _ in selector.select(timeout=min(1, max(0, deadline - time.monotonic()))):
                source = key.fileobj
                chunk = source.recv(65536)
                if not chunk and source is downstream and exchange.accepted is not None:
                    # A one-shot miner exits after acceptance. Retain its exact
                    # authorized upstream session and stop polling the closed end.
                    selector.unregister(downstream)
                    continue
                require(bool(chunk), 'connection closed before replay acceptance checks completed')
                buffer = buffers[source]
                buffer.extend(chunk)
                while b'\n' in buffer:
                    line, _, remaining = buffer.partition(b'\n')
                    buffer[:] = remaining
                    require(len(line) <= MAX_LINE, 'ZIP-301 message exceeded proxy limit')
                    message = json.loads(line)
                    require(isinstance(message, dict), 'invalid ZIP-301 envelope')
                    direction = 'miner-to-pool' if source is downstream else 'pool-to-miner'
                    transcript.write(encode({'direction': direction, 'message': message}))
                    transcript.flush()
                    if source is downstream:
                        exchange.request(message)
                        upstream.sendall(line + b'\n')
                        continue
                    result = exchange.response(message)
                    if result == 'accepted':
                        downstream.sendall(line + b'\n')
                        before_replay(exchange.original)
                        require(time.monotonic() < deadline, 'projection exhausted replay deadline')
                        replay = exchange.replay()
                        transcript.write(encode({'direction': 'proxy-replay-to-pool', 'message': replay}))
                        transcript.flush()
                        upstream.sendall(encode(replay))
                    elif result == 'replayed':
                        after_replay()
                        return exchange
                    elif exchange.accepted is None:
                        # After acceptance the one-shot client can close; drain
                        # upstream notices without writing to the completed miner.
                        downstream.sendall(line + b'\n')
                require(len(buffer) <= MAX_LINE, 'unterminated ZIP-301 message exceeded proxy limit')
        raise RuntimeError('real mining or replay timed out')


def run(args):
    runtime = args.runtime.resolve()
    mode = runtime.stat()
    require(stat.S_ISDIR(mode.st_mode) and mode.st_uid == os.getuid()
            and stat.S_IMODE(mode.st_mode) & 0o077 == 0, 'runtime must be owner-private')
    verifier = ReplayVerifier(runtime)
    require(verifier.config.get('stratum_listen') == '127.0.0.1:18237',
            'requires the fixed loopback full-pool Regtest edge')
    session = json.loads((runtime / 'portal-session.json').read_text())
    worker = session['worker']
    require(isinstance(worker['token'], str) and worker['token']
            and isinstance(worker['mining_username'], str), 'missing harness worker credentials')
    ledger = LedgerCheck(verifier, worker['id'])
    ledger.require_idle()
    evidence = runtime / ('replay-' + uuid.uuid4().hex)
    evidence.mkdir(mode=0o700)
    env = os.environ.copy()
    env['WCASH_STRATUM_PASSWORD'] = worker['token']
    proc = None
    with private_file(evidence / 'miner.stdout') as stdout, \
         private_file(evidence / 'miner.stderr') as stderr, \
         private_file(evidence / 'transcript.jsonl') as transcript, \
         socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', args.proxy_port))
        listener.listen(1)
        listener.settimeout(30)
        try:
            proc = subprocess.Popen([str(args.miner.resolve()), 'zip301-mine',
                                     f'127.0.0.1:{args.proxy_port}', worker['mining_username'], '256', '0'],
                                    env=env, stdout=stdout, stderr=stderr)
            downstream, peer = listener.accept()
            require(peer[0] == '127.0.0.1', 'proxy client is not loopback')
            with downstream, socket.create_connection(('127.0.0.1', 18237), timeout=10) as upstream:
                downstream.settimeout(10)
                upstream.settimeout(10)
                deadline = time.monotonic() + args.timeout
                exchange = proxy(downstream, upstream, transcript,
                                 lambda request: ledger.await_original(request, deadline=deadline),
                                 lambda: ledger.verify_unchanged(args.observe_seconds),
                                 deadline)
                require(proc.wait(timeout=15) == 0, 'native miner did not finish successfully')
            # Check once more after the real native client has exited.
            ledger.verify_unchanged(0)
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
    report = {'checked_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source': 'real native ZIP-301 miner, same authorized pool connection, live PostgreSQL',
              'network': 'regtest', 'original_accepted': True,
              'identical_submission_params': True, 'new_request_id': True,
              'same_upstream_connection': True, 'replay_rejection_code': exchange.rejection_code,
              'replay_response_mode': exchange.response_mode,
              'shares_before_original': ledger.before['total'],
              'shares_after_original': ledger.projected['total'],
              'shares_after_replay': ledger.projected['total'],
              'original_winners_per_chain': 1, 'winner_allocations_unchanged': True,
              'original_winner_ledger_entries_unchanged': True,
              'unchanged_observation_seconds': args.observe_seconds,
              'retained_uncredited_side_chain_candidates': ledger.retained_side_chain_count,
              'scope': 'same-session replay only; restart/recovery is separate evidence'}
    with private_file(evidence / 'result.json') as output:
        output.write(json.dumps(report, indent=2).encode())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--miner', type=Path, required=True)
    parser.add_argument('--proxy-port', type=int, default=18238)
    parser.add_argument('--timeout', type=int, default=900)
    parser.add_argument('--observe-seconds', type=int, default=3)
    args = parser.parse_args()
    if not 1024 <= args.proxy_port <= 65535 or args.proxy_port == 18237:
        parser.error('--proxy-port must be an unused nonprivileged port other than 18237')
    if not 30 <= args.timeout <= 1800 or not 1 <= args.observe_seconds <= 30:
        parser.error('timeout must be 30..1800 and observation must be 1..30 seconds')
    try:
        print(json.dumps(run(args), indent=2))
    except RuntimeError as error:
        print('FAIL: ' + str(error) + '; no replay certificate emitted.', file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('FAIL: local replay check did not pass; protected diagnostics retained.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
