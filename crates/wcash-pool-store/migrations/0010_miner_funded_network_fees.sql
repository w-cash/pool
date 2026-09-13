-- A zero-fee pool cannot pay transaction fees from undisclosed revenue or an
-- unfunded collector. Reserve the policy-bounded fee from each payout's gross
-- miner liabilities instead. The signed outputs contain the net amounts; when
-- the exact transaction fee is known, unused reserve is returned to each
-- miner's payable balance. This keeps collector assets and miner liabilities
-- solvent even when a batch consumes the collector's entire balance.

-- Stop an old payout worker from creating a legacy in-flight item between the
-- compatibility guard and the schema change.
LOCK TABLE payout_batches, payout_items IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM payout_batches
         WHERE state IN ('draft', 'signing', 'signed', 'broadcasting', 'broadcast')
    ) THEN
        RAISE EXCEPTION
            'cannot install miner-funded network fees with in-flight payout batches'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

-- NULL is retained only as an explicit compatibility representation for
-- terminal batches created by an older release. The INSERT trigger below
-- requires every newly created item to contain its gross liability.
ALTER TABLE payout_items
    ADD COLUMN liability_amount_zat BIGINT,
    ADD CONSTRAINT payout_items_liability_amount_check CHECK (
        liability_amount_zat IS NULL
        OR liability_amount_zat >= amount_zat
    );

ALTER TABLE ledger_entries
    DROP CONSTRAINT ledger_entries_ledger_account_check;
ALTER TABLE ledger_entries
    ADD CONSTRAINT ledger_entries_ledger_account_check CHECK (
        ledger_account IN ('collector_immature_asset',
                           'collector_spendable_asset',
                           'miner_immature', 'miner_payable', 'payout_pending',
                           'pool_fee_unearned', 'pool_equity',
                           'network_fee_expense',
                           'miner_network_fee_contribution')
    );

CREATE OR REPLACE FUNCTION reject_payout_item_after_seal() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    parent_is_open BOOLEAN;
BEGIN
    IF NEW.liability_amount_zat IS NULL
       OR NEW.liability_amount_zat < NEW.amount_zat THEN
        RAISE EXCEPTION 'payout item requires a conserving gross liability';
    END IF;
    SELECT state = 'draft' AND ledger_root IS NULL
      INTO parent_is_open
      FROM payout_batches
     WHERE deployment_id = NEW.deployment_id AND id = NEW.batch_id
     FOR UPDATE;
    IF parent_is_open IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'payout batch % is already sealed', NEW.batch_id;
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION reject_payout_item_after_seal() FROM PUBLIC;
