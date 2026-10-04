-- Keep one shielded output per selected cycle, defer 70% of cycles, and draw
-- the selected payout uniformly from 1-20 WEC. Compared with the previous
-- 50% / 1-10 WEC policy, expected settlement rises from 2.75 to 3.15 WEC per
-- cycle while payout timing and amounts become less regular.
DROP TRIGGER chain_policies_append_only ON chain_policies;
UPDATE chain_policies
SET maximum_payout_zat = 2000000000,
    payout_skip_bps = 7000
WHERE chain = 'wcash'
  AND minimum_payout_zat = 100000000
  AND maximum_payout_zat = 1000000000
  AND maximum_payout_outputs = 1
  AND payout_skip_bps = 5000;
CREATE TRIGGER chain_policies_append_only
    BEFORE UPDATE OR DELETE ON chain_policies
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();
