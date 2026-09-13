-- Make authorization durable before either payout-side external effect.
-- `signing` means the exact immutable signer request may be executed or
-- recovered. `broadcasting` means the exact SQL-bound transaction may be
-- submitted or re-submitted. A later chain freeze cannot revoke an already
-- committed authorization, but it prevents either authorization from being
-- granted for new work.
--
-- A pre-fence `draft` may already have an exact signer-journal artifact, and a
-- pre-fence `signed` row has no durable proof that chain submission was
-- authorized. Refuse that ambiguous in-place upgrade instead of guessing. An
-- operator must drain/cancel these rows with the matching old release before
-- applying this migration. `broadcast` and later states already prove the
-- chain-side effect and are safe to retain.
--
-- Take the table lock before inspecting legacy rows. Otherwise an old payout
-- worker could commit a Draft after the guard's snapshot but before ALTER
-- TABLE obtains its own lock, admitting an unfenced row into the new schema.
LOCK TABLE payout_batches IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM payout_batches WHERE state IN ('draft', 'signed')
    ) THEN
        RAISE EXCEPTION
            'cannot install payout effect fences with legacy draft or signed batches'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

ALTER TABLE payout_batches
    DROP CONSTRAINT payout_batches_state_check;
ALTER TABLE payout_batches
    DROP CONSTRAINT payout_batches_check;
ALTER TABLE payout_batches
    DROP CONSTRAINT payout_batches_check1;

ALTER TABLE payout_batches
    ADD CONSTRAINT payout_batches_state_check
    CHECK (state IN ('draft', 'signing', 'signed', 'broadcasting', 'broadcast',
                     'confirmed', 'reorged', 'cancelled'));
ALTER TABLE payout_batches
    ADD CONSTRAINT payout_batches_signed_facts_check CHECK (
        (state IN ('draft', 'signing', 'cancelled')
         AND unsigned_digest IS NULL AND transaction_id IS NULL
         AND signed_transaction IS NULL AND network_fee_zat IS NULL)
        OR
        (state IN ('signed', 'broadcasting', 'broadcast', 'confirmed', 'reorged')
         AND unsigned_digest IS NOT NULL AND transaction_id IS NOT NULL
         AND signed_transaction IS NOT NULL AND network_fee_zat IS NOT NULL)
    );
ALTER TABLE payout_batches
    ADD CONSTRAINT payout_batches_confirmation_facts_check CHECK (
        (state IN ('confirmed', 'reorged') AND confirmation_block_hash IS NOT NULL
         AND confirmation_height IS NOT NULL AND confirmation_count IS NOT NULL)
        OR (state NOT IN ('confirmed', 'reorged') AND confirmation_block_hash IS NULL
            AND confirmation_height IS NULL AND confirmation_count IS NULL)
    );

CREATE OR REPLACE FUNCTION permit_only_payout_batch_seal() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    item_count BIGINT;
    reconciliation_matches BOOLEAN;
    ledger_fence_matches BOOLEAN;
BEGIN
    IF TG_OP = 'DELETE'
       OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.chain IS DISTINCT FROM OLD.chain
       OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.portal_sequence IS DISTINCT FROM OLD.portal_sequence THEN
        RAISE EXCEPTION 'payout batch identity is immutable';
    END IF;

    IF OLD.reconciliation_id IS NULL THEN
        IF OLD.ledger_root IS NOT NULL OR OLD.ledger_sequence_cutoff IS NOT NULL
           OR OLD.state <> 'draft' OR NEW.state <> 'draft'
           OR NEW.reconciliation_id IS NULL OR NEW.ledger_root IS NULL
           OR NEW.ledger_sequence_cutoff IS NULL THEN
            RAISE EXCEPTION 'invalid initial payout batch seal';
        END IF;
        SELECT COUNT(*) INTO item_count
          FROM payout_items
         WHERE deployment_id = NEW.deployment_id AND batch_id = NEW.id;
        SELECT EXISTS(
            SELECT 1 FROM wallet_reconciliations r
             WHERE r.deployment_id = NEW.deployment_id
               AND r.id = NEW.reconciliation_id
               AND r.chain = NEW.chain AND r.status = 'matched'
        ) INTO reconciliation_matches;
        SELECT EXISTS(
            SELECT 1 FROM ledger_transactions t
             WHERE t.deployment_id = NEW.deployment_id
               AND t.ledger_sequence = NEW.ledger_sequence_cutoff
               AND t.chain = NEW.chain AND t.kind = 'payout_reserved'
               AND t.reference = NEW.id::TEXT AND t.sealed_at IS NOT NULL
        ) INTO ledger_fence_matches;
        IF item_count < 1 OR item_count > 200
           OR NOT reconciliation_matches OR NOT ledger_fence_matches THEN
            RAISE EXCEPTION 'payout batch seal does not match durable facts';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.reconciliation_id IS DISTINCT FROM OLD.reconciliation_id
       OR NEW.ledger_root IS DISTINCT FROM OLD.ledger_root
       OR NEW.ledger_sequence_cutoff IS DISTINCT FROM OLD.ledger_sequence_cutoff THEN
        RAISE EXCEPTION 'payout batch reconciliation seal is immutable';
    END IF;

    IF OLD.state = 'draft' AND NEW.state = 'signing'
       AND NEW.unsigned_digest IS NOT DISTINCT FROM OLD.unsigned_digest
       AND NEW.transaction_id IS NOT DISTINCT FROM OLD.transaction_id
       AND NEW.signed_transaction IS NOT DISTINCT FROM OLD.signed_transaction
       AND NEW.network_fee_zat IS NOT DISTINCT FROM OLD.network_fee_zat
       AND NEW.confirmation_block_hash IS NOT DISTINCT FROM OLD.confirmation_block_hash
       AND NEW.confirmation_height IS NOT DISTINCT FROM OLD.confirmation_height
       AND NEW.confirmation_count IS NOT DISTINCT FROM OLD.confirmation_count THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'signing' AND NEW.state = 'signed' THEN
        IF NEW.confirmation_block_hash IS NOT NULL OR NEW.confirmation_height IS NOT NULL
           OR NEW.confirmation_count IS NOT NULL THEN
            RAISE EXCEPTION 'signed payout cannot contain confirmation evidence';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'signed' AND NEW.state = 'broadcasting'
       OR OLD.state = 'broadcasting' AND NEW.state = 'broadcast' THEN
        IF NEW.unsigned_digest IS DISTINCT FROM OLD.unsigned_digest
           OR NEW.transaction_id IS DISTINCT FROM OLD.transaction_id
           OR NEW.signed_transaction IS DISTINCT FROM OLD.signed_transaction
           OR NEW.network_fee_zat IS DISTINCT FROM OLD.network_fee_zat
           OR NEW.confirmation_block_hash IS DISTINCT FROM OLD.confirmation_block_hash
           OR NEW.confirmation_height IS DISTINCT FROM OLD.confirmation_height
           OR NEW.confirmation_count IS DISTINCT FROM OLD.confirmation_count THEN
            RAISE EXCEPTION 'signed payout facts are immutable';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'broadcast' AND NEW.state = 'confirmed' THEN
        IF NEW.unsigned_digest IS DISTINCT FROM OLD.unsigned_digest
           OR NEW.transaction_id IS DISTINCT FROM OLD.transaction_id
           OR NEW.signed_transaction IS DISTINCT FROM OLD.signed_transaction
           OR NEW.network_fee_zat IS DISTINCT FROM OLD.network_fee_zat THEN
            RAISE EXCEPTION 'broadcast payout facts are immutable';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'confirmed' AND NEW.state = 'reorged' THEN
        IF NEW.unsigned_digest IS DISTINCT FROM OLD.unsigned_digest
           OR NEW.transaction_id IS DISTINCT FROM OLD.transaction_id
           OR NEW.signed_transaction IS DISTINCT FROM OLD.signed_transaction
           OR NEW.network_fee_zat IS DISTINCT FROM OLD.network_fee_zat
           OR NEW.confirmation_block_hash IS DISTINCT FROM OLD.confirmation_block_hash
           OR NEW.confirmation_height IS DISTINCT FROM OLD.confirmation_height
           OR NEW.confirmation_count IS DISTINCT FROM OLD.confirmation_count THEN
            RAISE EXCEPTION 'confirmed payout facts are immutable';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'draft' AND NEW.state = 'cancelled'
       AND NEW.unsigned_digest IS NOT DISTINCT FROM OLD.unsigned_digest
       AND NEW.transaction_id IS NOT DISTINCT FROM OLD.transaction_id
       AND NEW.signed_transaction IS NOT DISTINCT FROM OLD.signed_transaction
       AND NEW.network_fee_zat IS NOT DISTINCT FROM OLD.network_fee_zat
       AND NEW.confirmation_block_hash IS NOT DISTINCT FROM OLD.confirmation_block_hash
       AND NEW.confirmation_height IS NOT DISTINCT FROM OLD.confirmation_height
       AND NEW.confirmation_count IS NOT DISTINCT FROM OLD.confirmation_count THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid payout batch lifecycle transition';
END;
$$;

-- Function bodies execute with the invoker's privileges. Keep the trigger
-- helper unavailable as a directly callable PUBLIC API after replacement.
REVOKE ALL ON FUNCTION permit_only_payout_batch_seal() FROM PUBLIC;
