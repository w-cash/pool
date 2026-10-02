-- Preserve the existing one-output, 50% privacy deferral policy while
-- increasing the randomized Wcash payout range from 1-4 WEC to 1-10 WEC.
-- This lets the automatic worker reduce large payable balances without
-- increasing shielded transaction frequency or proof-generation load.
DROP TRIGGER chain_policies_append_only ON chain_policies;
UPDATE chain_policies
SET maximum_payout_zat = 1000000000
WHERE chain = 'wcash'
  AND minimum_payout_zat = 100000000
  AND maximum_payout_zat = 400000000
  AND maximum_payout_outputs = 1
  AND payout_skip_bps = 5000;
CREATE TRIGGER chain_policies_append_only
    BEFORE UPDATE OR DELETE ON chain_policies
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();
