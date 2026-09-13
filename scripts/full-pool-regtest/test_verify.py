"""Verifier boundary tests only; fixtures are not mining or payout evidence."""
import unittest

from verify import Verifier, display_block


class CanonicalTransactionTests(unittest.TestCase):
    def check(self, *, confirmations=100, block_hash=None, transactions=None):
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
        verifier.canonical_transaction('wcash', 103, wire, txid, 100)

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


if __name__ == '__main__':
    unittest.main()
