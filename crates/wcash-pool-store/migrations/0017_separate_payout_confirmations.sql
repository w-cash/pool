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

-- Existing Wcash launch rows were intentionally append-only. Perform this
-- one reviewed policy transition inside the migration transaction, then
-- restore the append-only fence before any service can observe the schema.
DROP TRIGGER chain_policies_append_only ON chain_policies;
UPDATE chain_policies
SET payout_confirmations = 3,
    maximum_payout_outputs = 1,
    minimum_payout_zat = 100000000,
    maximum_payout_zat = 400000000,
    payout_skip_bps = 5000
WHERE chain = 'wcash';
CREATE TRIGGER chain_policies_append_only
    BEFORE UPDATE OR DELETE ON chain_policies
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();

COMMENT ON COLUMN chain_policies.payout_confirmations IS
    'Best-chain depth required to settle a broadcast payout; independent from coinbase maturity.';

COMMENT ON COLUMN chain_policies.minimum_payout_zat IS
    'Lower bound for the per-cycle randomized gross payout cap.';

COMMENT ON COLUMN chain_policies.payout_skip_bps IS
    'Probability in basis points that an otherwise eligible payout cycle is deferred.';
