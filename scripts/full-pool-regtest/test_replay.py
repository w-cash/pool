"""Replay helper boundary fixtures; these are not real mining acceptance."""
import io
import json
from pathlib import Path
import socket
import stat
import tempfile
import threading
import time
import unittest

from replay import LedgerCheck, ReplayExchange, encode, private_file, proxy


SUBMIT = {'id': 4, 'method': 'mining.submit',
          'params': ['test.worker', 'job', 'time', 'nonce2', 'solution']}
ACCEPTED = {'id': 4, 'result': True, 'error': None}


class ReplayBoundaryTests(unittest.TestCase):
    def ready(self):
        exchange = ReplayExchange()
        exchange.request(SUBMIT)
        self.assertEqual(exchange.response(ACCEPTED), 'accepted')
        replay = exchange.replay()
        self.assertNotEqual(replay['id'], SUBMIT['id'])
        self.assertEqual({**replay, 'id': SUBMIT['id']}, SUBMIT)
        return exchange

    def test_exact_params_and_new_id_then_duplicate_or_stale(self):
        for code in (21, 22):
            with self.subTest(code=code):
                exchange = self.ready()
                self.assertEqual(exchange.response({'id': exchange.replay_id, 'result': None,
                                                    'error': [code, 'rejected', None]}), 'replayed')
                self.assertEqual(exchange.rejection_code, code)

    def test_accepts_protocol_permitted_idempotent_response(self):
        exchange = self.ready()
        self.assertEqual(exchange.response({'id': exchange.replay_id, 'result': True,
                                            'error': None}), 'replayed')
        self.assertEqual(exchange.response_mode, 'idempotent_success')

    def test_fails_closed_on_unrelated_failure(self):
        for response in ({'result': False, 'error': [24, 'unauthorized', None]},
                         {'result': False, 'error': None}):
            with self.subTest(response=response):
                exchange = self.ready()
                with self.assertRaisesRegex(RuntimeError, 'neither idempotent success'):
                    exchange.response({'id': exchange.replay_id, **response})

    def test_rejected_original_is_not_replayed(self):
        exchange = ReplayExchange()
        exchange.request(SUBMIT)
        with self.assertRaisesRegex(RuntimeError, 'original real proof was not accepted'):
            exchange.response({'id': 4, 'result': None, 'error': [21, 'stale', None]})
        with self.assertRaisesRegex(RuntimeError, 'invalid replay state'):
            exchange.replay()

    def test_raw_evidence_created_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'evidence'
            with private_file(path) as output:
                output.write(b'private')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                private_file(path)

    def test_unchanged_sql_check_rejects_extra_share_or_credit(self):
        ledger = object.__new__(LedgerCheck)
        ledger.projected = {'total': 103, 'worker': 102}
        ledger.original_facts = [{'chain': 'wcash', 'credit': [1]}]
        ledger.counts = lambda: {'total': 104, 'worker': 103}
        ledger.winner_facts = lambda: ledger.original_facts
        with self.assertRaisesRegex(RuntimeError, 'share count increased'):
            ledger.verify_unchanged(0)
        ledger.counts = lambda: ledger.projected
        ledger.winner_facts = lambda: [{'chain': 'wcash', 'credit': [1, 1]}]
        with self.assertRaisesRegex(RuntimeError, 'reward ledger entries changed'):
            ledger.verify_unchanged(0)
        ledger.winner_facts = lambda: ledger.original_facts
        ledger.verify_unchanged(0)

    def test_proxy_holds_acceptance_and_notifications_on_same_connection(self):
        downstream, miner = socket.socketpair()
        upstream, pool = socket.socketpair()
        results = []
        failures = []
        hooks = []
        transcript = io.BytesIO()
        def run_proxy():
            try:
                results.append(proxy(downstream, upstream, transcript,
                                     lambda request: hooks.append('projected'),
                                     lambda: hooks.append('unchanged'),
                                     time.monotonic() + 5))
            except BaseException as error:
                failures.append(error)
        with downstream, miner, upstream, pool:
            miner.settimeout(2)
            pool.settimeout(2)
            thread = threading.Thread(target=run_proxy)
            thread.start()
            try:
                raw = encode(SUBMIT)
                miner.sendall(raw[:10])
                miner.sendall(raw[10:])
                with pool.makefile('rb') as reader:
                    self.assertEqual(json.loads(reader.readline()), SUBMIT)
                    # This notification must not become the one-shot client's
                    # submit response while the actual acceptance is withheld.
                    pool.sendall(encode(ACCEPTED) + encode({'id': None,
                                  'method': 'mining.notify', 'params': ['new-job']}))
                    replay = json.loads(reader.readline())
                    self.assertEqual({**replay, 'id': 4}, SUBMIT)
                    self.assertEqual(hooks, ['projected'])
                    pool.sendall(encode({'id': replay['id'], 'result': None,
                                         'error': [21, 'stale job', None]}))
                with miner.makefile('rb') as reader:
                    self.assertEqual(json.loads(reader.readline()), ACCEPTED)
            finally:
                thread.join(timeout=6)
            self.assertFalse(thread.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(hooks, ['projected', 'unchanged'])
            self.assertEqual(results[0].rejection_code, 21)
            recorded = [json.loads(line) for line in transcript.getvalue().splitlines()]
            self.assertEqual(sum(row['direction'] == 'proxy-replay-to-pool'
                                 for row in recorded), 1)


if __name__ == '__main__':
    unittest.main()
