-- Keep one shielded output per selected cycle, defer 20% of cycles, and draw
-- the selected payout uniformly from 1-100 WEC. The payout builder separately
-- clamps the draw to the miner's mature unpaid liability.
DROP TRIGGER chain_policies_append_only ON chain_policies;
UPDATE chain_policies
SET maximum_payout_zat = 10000000000,
    payout_skip_bps = 2000
WHERE chain = 'wcash'
  AND minimum_payout_zat = 100000000
  AND maximum_payout_zat = 2000000000
  AND maximum_payout_outputs = 1
  AND payout_skip_bps = 3500;
CREATE TRIGGER chain_policies_append_only
    BEFORE UPDATE OR DELETE ON chain_policies
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();
