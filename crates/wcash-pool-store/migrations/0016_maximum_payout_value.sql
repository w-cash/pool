ALTER TABLE chain_policies
    ADD COLUMN maximum_payout_zat BIGINT NOT NULL DEFAULT 100000000
        CHECK (maximum_payout_zat > 0);

COMMENT ON COLUMN chain_policies.maximum_payout_zat IS
    'Maximum gross liability reserved for one account in one payout transaction; excess remains miner-payable.';
