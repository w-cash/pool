"""Verifier boundary tests only; fixtures are not mining or payout evidence."""
import unittest

from verify import Verifier, check_settlement, display_block


class CanonicalTransactionTests(unittest.TestCase):
    def check(self, *, confirmations=100, block_hash=None, transactions=None, coinbase=False):
        wire = '0123456789abcdef' * 4
        txid = 'fedcba9876543210' * 4
        verifier = object.__new__(Verifier)
        def rpc(chain, method, params):
            self.assertEqual(chain, 'wcash')
            if method == 'getblockhash':
                self.assertEqual(params, [103])
                return block_hash or display_block(wire)
            self.assertEqual(method, 'getblock')
            self.assertEqual(params, [display_block(wire), 1])
            return {'height': 103, 'confirmations': confirmations,
                    'tx': [txid] if transactions is None else transactions}
        verifier.rpc = rpc
        verifier.canonical_transaction('wcash', 103, wire, txid, 100, coinbase=coinbase)

    def test_checks_wire_block_order_and_display_transaction_order(self):
        self.check()

    def test_rejects_orphaned_confirming_block(self):
        with self.assertRaisesRegex(RuntimeError, 'outside the current best chain'):
            self.check(block_hash='ff' * 32)

    def test_rejects_99_confirmations(self):
        with self.assertRaisesRegex(RuntimeError, 'insufficient independent node confirmations'):
            self.check(confirmations=99)

    def test_rejects_transaction_absent_from_block(self):
        with self.assertRaisesRegex(RuntimeError, 'absent'):
            self.check(transactions=['bb' * 32])

    def test_rejects_non_coinbase_as_winner(self):
        with self.assertRaisesRegex(RuntimeError, 'not the actual coinbase'):
            self.check(transactions=['bb' * 32, 'fedcba9876543210' * 4], coinbase=True)


class SettlementTests(unittest.TestCase):
    def setUp(self):
        self.payouts = [{'id': 'batch', 'account_id': 'miner', 'amount_zat': 900,
                         'liability_amount_zat': 1000, 'network_fee_zat': 50}]
        self.lines = [dict(batch_id='batch', account_id=account, ledger_account=kind, amount_zat=value)
                      for account, kind, value in [('miner', 'payout_pending', 1000),
                                                   (None, 'collector_spendable_asset', -950),
                                                   ('miner', 'miner_payable', -50),
                                                   (None, 'network_fee_expense', 50),
                                                   (None, 'miner_network_fee_contribution', -50)]]

    def test_exact_settlement_and_unused_fee_refund(self):
        check_settlement(self.payouts, self.lines)

    def test_rejects_balanced_wrong_miner_settlement(self):
        self.lines[0]['account_id'] = 'different-miner'
        with self.assertRaisesRegex(RuntimeError, 'settlement account'):
            check_settlement(self.payouts, self.lines)

    def test_rejects_balanced_wrong_amount_settlement(self):
        self.lines[0]['amount_zat'] += 10
        self.lines[1]['amount_zat'] -= 10
        with self.assertRaisesRegex(RuntimeError, 'exact per-miner liabilities'):
            check_settlement(self.payouts, self.lines)


if __name__ == '__main__':
    unittest.main()
