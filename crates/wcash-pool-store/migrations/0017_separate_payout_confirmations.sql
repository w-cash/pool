-- Coinbase rewards remain subject to `required_confirmations` (100 on public
-- Wcash). Outbound payouts settle sooner because their wallet-owned shielded
-- change is trusted under ZIP 315 and can be reused after three confirmations.
ALTER TABLE chain_policies
    ADD COLUMN payout_confirmations INTEGER NOT NULL DEFAULT 3
        CHECK (payout_confirmations BETWEEN 1 AND required_confirmations),
    ADD COLUMN minimum_payout_zat BIGINT NOT NULL DEFAULT 100000000
        CHECK (minimum_payout_zat > 0),
    ADD COLUMN payout_skip_bps INTEGER NOT NULL DEFAULT 0
        CHECK (payout_skip_bps BETWEEN 0 AND 10000),
    ADD CONSTRAINT chain_policies_random_payout_range
        CHECK (minimum_payout_zat <= maximum_payout_zat);

COMMENT ON COLUMN chain_policies.payout_confirmations IS
    'Best-chain depth required to settle a broadcast payout; independent from coinbase maturity.';

COMMENT ON COLUMN chain_policies.minimum_payout_zat IS
    'Lower bound for the per-cycle randomized gross payout cap.';

COMMENT ON COLUMN chain_policies.payout_skip_bps IS
    'Probability in basis points that an otherwise eligible payout cycle is deferred.';
