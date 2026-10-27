-- Quarantine an expired WEC artifact without releasing its reservation.
-- Only finalized non-inclusion can return the full gross liability to payable.
-- Original signed bytes, payout items, destinations and journals are retained.
LOCK TABLE payout_batches IN ACCESS EXCLUSIVE MODE;

ALTER TABLE payout_batches DROP CONSTRAINT payout_batches_state_check;
ALTER TABLE payout_batches ADD CONSTRAINT payout_batches_state_check
    CHECK (state IN ('draft','signing','signed','broadcasting','broadcast',
                     'expiry_pending','expired','confirmed','reorged','cancelled'));
ALTER TABLE payout_batches DROP CONSTRAINT payout_batches_signed_facts_check;
ALTER TABLE payout_batches ADD CONSTRAINT payout_batches_signed_facts_check CHECK (
    (state IN ('draft','signing','cancelled')
     AND unsigned_digest IS NULL AND transaction_id IS NULL
     AND signed_transaction IS NULL AND network_fee_zat IS NULL)
    OR
    (state IN ('signed','broadcasting','broadcast','expiry_pending','expired','confirmed','reorged')
     AND unsigned_digest IS NOT NULL AND transaction_id IS NOT NULL
     AND signed_transaction IS NOT NULL AND network_fee_zat IS NOT NULL)
);
ALTER TABLE payout_batches ADD CONSTRAINT payout_batches_expiry_chain_check
    CHECK (state NOT IN ('expiry_pending','expired') OR chain='wcash');

-- Expiry polling visits only the few active artifacts, never payout history.
CREATE INDEX payout_batches_wcash_expiry_candidates_idx
    ON payout_batches(deployment_id,created_at,id)
    WHERE chain='wcash' AND state IN ('signed','broadcasting','broadcast','expiry_pending');
CREATE INDEX payout_batches_expiry_held_idx
    ON payout_batches(deployment_id,chain)
    WHERE state='expiry_pending';

CREATE TABLE payout_expiry_evidence (
    deployment_id UUID NOT NULL,
    batch_id UUID NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('held','finalized')),
    transaction_id BYTEA NOT NULL CHECK (octet_length(transaction_id)=32),
    signed_transaction_sha256 BYTEA NOT NULL CHECK (octet_length(signed_transaction_sha256)=32),
    expiry_height BIGINT NOT NULL CHECK (expiry_height BETWEEN 1 AND 4294967295),
    tip_hash BYTEA NOT NULL CHECK (octet_length(tip_hash)=32 AND tip_hash<>decode(repeat('00',32),'hex')),
    tip_height BIGINT NOT NULL CHECK (tip_height BETWEEN 1 AND 4294967295 AND tip_height>expiry_height),
    observed_at TIMESTAMPTZ NOT NULL,
    release_transaction_id UUID,
    PRIMARY KEY (deployment_id,batch_id,phase),
    UNIQUE (deployment_id,release_transaction_id),
    FOREIGN KEY (deployment_id,batch_id) REFERENCES payout_batches(deployment_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id,release_transaction_id) REFERENCES ledger_transactions(deployment_id,id) ON DELETE RESTRICT,
    CHECK ((phase='held' AND release_transaction_id IS NULL)
        OR (phase='finalized' AND release_transaction_id IS NOT NULL
            AND tip_height>=expiry_height+1001))
);
CREATE TRIGGER payout_expiry_evidence_append_only
    BEFORE UPDATE OR DELETE ON payout_expiry_evidence
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();

-- This evidence is not a consensus oracle. The isolated worker verifies full
-- canonical non-inclusion; this guard binds that assertion to immutable bytes
-- and to exactly one conserving release, and rejects premature/replayed facts.
CREATE FUNCTION guard_payout_expiry_evidence() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    prior payout_expiry_evidence%ROWTYPE;
    parent payout_batches%ROWTYPE;
    release_matches BOOLEAN;
BEGIN
    SELECT * INTO parent FROM payout_batches
     WHERE deployment_id=NEW.deployment_id AND id=NEW.batch_id FOR UPDATE;
    IF NOT FOUND OR parent.chain<>'wcash'
       OR parent.transaction_id IS DISTINCT FROM NEW.transaction_id
       OR sha256(parent.signed_transaction) IS DISTINCT FROM NEW.signed_transaction_sha256
       OR NEW.observed_at>clock_timestamp()
       OR NEW.observed_at<clock_timestamp()-INTERVAL '5 minutes' THEN
        RAISE EXCEPTION 'invalid bound payout expiry evidence';
    END IF;
    IF NEW.phase='held' THEN
        IF parent.state NOT IN ('signed','broadcasting','broadcast') THEN
            RAISE EXCEPTION 'only an active signed payout can be held';
        END IF;
        RETURN NEW;
    END IF;
    SELECT * INTO prior FROM payout_expiry_evidence
     WHERE deployment_id=NEW.deployment_id AND batch_id=NEW.batch_id AND phase='held';
    IF NOT FOUND OR parent.state<>'expiry_pending'
       OR NEW.transaction_id IS DISTINCT FROM prior.transaction_id
       OR NEW.signed_transaction_sha256 IS DISTINCT FROM prior.signed_transaction_sha256
       OR NEW.expiry_height<>prior.expiry_height
       OR NEW.tip_height<prior.tip_height OR NEW.observed_at<prior.observed_at
       OR NEW.tip_height<NEW.expiry_height+1001 THEN
        RAISE EXCEPTION 'payout expiry lacks finalization evidence';
    END IF;
    SELECT EXISTS(
        SELECT 1 FROM ledger_transactions t
         WHERE t.deployment_id=NEW.deployment_id AND t.id=NEW.release_transaction_id
           AND t.chain='wcash' AND t.kind='payout_released'
           AND t.reference=NEW.batch_id::TEXT AND t.sealed_at IS NOT NULL
    ) INTO release_matches;
    IF NOT release_matches THEN
        RAISE EXCEPTION 'finalized payout expiry lacks a sealed release';
    END IF;
    -- Exact gross pending->payable reversal; no asset debit or network fee.
    IF EXISTS (
        WITH expected AS (
            SELECT account_id,'payout_pending'::TEXT AS ledger_account,
                   COALESCE(liability_amount_zat,amount_zat) AS amount_zat
              FROM payout_items WHERE deployment_id=NEW.deployment_id AND batch_id=NEW.batch_id
            UNION ALL
            SELECT account_id,'miner_payable'::TEXT,-COALESCE(liability_amount_zat,amount_zat)
              FROM payout_items WHERE deployment_id=NEW.deployment_id AND batch_id=NEW.batch_id
        ), actual AS (
            SELECT account_id,ledger_account,amount_zat FROM ledger_entries
             WHERE deployment_id=NEW.deployment_id AND transaction_id=NEW.release_transaction_id
        )
        (SELECT * FROM expected EXCEPT ALL SELECT * FROM actual)
        UNION ALL
        (SELECT * FROM actual EXCEPT ALL SELECT * FROM expected)
    ) THEN
        RAISE EXCEPTION 'payout expiry release does not conserve every liability';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER payout_expiry_evidence_guard
    BEFORE INSERT ON payout_expiry_evidence
    FOR EACH ROW EXECUTE FUNCTION guard_payout_expiry_evidence();
REVOKE ALL ON FUNCTION guard_payout_expiry_evidence() FROM PUBLIC;

CREATE OR REPLACE FUNCTION permit_only_payout_batch_seal() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    item_count BIGINT;
    reconciliation_matches BOOLEAN;
    ledger_fence_matches BOOLEAN;
    release_matches BOOLEAN;
    expiry_matches BOOLEAN;
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
    IF OLD.state IN ('broadcast','expiry_pending') AND NEW.state = 'confirmed' THEN
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
    IF OLD.state IN ('signed','broadcasting','broadcast') AND NEW.state='expiry_pending'
       OR OLD.state='expiry_pending' AND NEW.state='expired' THEN
        IF NEW.chain <> 'wcash'
           OR NEW.unsigned_digest IS DISTINCT FROM OLD.unsigned_digest
           OR NEW.transaction_id IS DISTINCT FROM OLD.transaction_id
           OR NEW.signed_transaction IS DISTINCT FROM OLD.signed_transaction
           OR NEW.network_fee_zat IS DISTINCT FROM OLD.network_fee_zat
           OR NEW.confirmation_block_hash IS DISTINCT FROM OLD.confirmation_block_hash
           OR NEW.confirmation_height IS DISTINCT FROM OLD.confirmation_height
           OR NEW.confirmation_count IS DISTINCT FROM OLD.confirmation_count THEN
            RAISE EXCEPTION 'expired payout signed facts are immutable';
        END IF;
        SELECT EXISTS(
            SELECT 1 FROM payout_expiry_evidence e
             WHERE e.deployment_id=NEW.deployment_id AND e.batch_id=NEW.id
               AND e.phase=CASE WHEN NEW.state='expired' THEN 'finalized' ELSE 'held' END
               AND e.transaction_id=NEW.transaction_id
               AND e.signed_transaction_sha256=sha256(NEW.signed_transaction)
        ) INTO expiry_matches;
        IF NOT expiry_matches THEN
            RAISE EXCEPTION 'payout expiry transition lacks bound evidence';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'signing' AND NEW.state = 'cancelled'
       AND NEW.unsigned_digest IS NULL
       AND NEW.transaction_id IS NULL
       AND NEW.signed_transaction IS NULL
       AND NEW.network_fee_zat IS NULL
       AND NEW.confirmation_block_hash IS NULL
       AND NEW.confirmation_height IS NULL
       AND NEW.confirmation_count IS NULL THEN
        SELECT EXISTS(
            SELECT 1 FROM ledger_transactions t
             WHERE t.deployment_id = NEW.deployment_id
               AND t.chain = NEW.chain AND t.kind = 'payout_released'
               AND t.reference = NEW.id::TEXT AND t.sealed_at IS NOT NULL
        ) INTO release_matches;
        IF NOT release_matches THEN
            RAISE EXCEPTION 'rejected signing payout lacks a sealed liability release';
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
