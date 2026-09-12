-- Public-safe portal read models extend the original accounting schema without
-- creating a second identity or payout database.

ALTER TABLE workers ADD COLUMN revoked_at TIMESTAMPTZ;
UPDATE workers SET revoked_at = created_at WHERE NOT enabled;
ALTER TABLE workers ADD CONSTRAINT workers_revocation_consistent CHECK (
    (enabled AND revoked_at IS NULL)
    OR (NOT enabled AND revoked_at IS NOT NULL AND revoked_at >= created_at)
);

ALTER TABLE payout_destinations ADD COLUMN revision BIGINT;
WITH numbered AS (
    SELECT deployment_id, id,
           ROW_NUMBER() OVER (
               PARTITION BY deployment_id, account_id, chain
               ORDER BY created_at, id
           ) AS revision
      FROM payout_destinations
)
UPDATE payout_destinations AS destination
   SET revision = numbered.revision
  FROM numbered
 WHERE (destination.deployment_id, destination.id) =
       (numbered.deployment_id, numbered.id);
ALTER TABLE payout_destinations ALTER COLUMN revision SET NOT NULL;
ALTER TABLE payout_destinations ADD CONSTRAINT payout_destinations_revision_positive
    CHECK (revision > 0);
CREATE UNIQUE INDEX payout_destinations_revision_idx
    ON payout_destinations(deployment_id, account_id, chain, revision);

ALTER TABLE payout_change_events ADD COLUMN revision BIGINT;
WITH numbered AS (
    SELECT deployment_id, id,
           ROW_NUMBER() OVER (
               PARTITION BY deployment_id, account_id, chain
               ORDER BY requested_at, id
           ) AS revision
      FROM payout_change_events
)
UPDATE payout_change_events AS event
   SET revision = numbered.revision
  FROM numbered
 WHERE (event.deployment_id, event.id) = (numbered.deployment_id, numbered.id);
ALTER TABLE payout_change_events ALTER COLUMN revision SET NOT NULL;
ALTER TABLE payout_change_events ADD CONSTRAINT payout_change_events_revision_positive
    CHECK (revision > 0);
CREATE UNIQUE INDEX payout_change_events_revision_idx
    ON payout_change_events(deployment_id, account_id, chain, revision);

ALTER TABLE payout_batches
    ADD COLUMN portal_sequence BIGINT GENERATED ALWAYS AS IDENTITY;
CREATE UNIQUE INDEX payout_batches_portal_sequence_idx
    ON payout_batches(deployment_id, portal_sequence);

-- A monotonic immutable ledger sequence lets a signer re-derive an exact
-- historic snapshot even after later rewards or batches append new lines.
ALTER TABLE ledger_transactions
    ADD COLUMN ledger_sequence BIGINT GENERATED ALWAYS AS IDENTITY;
CREATE UNIQUE INDEX ledger_transactions_sequence_idx
    ON ledger_transactions(deployment_id, ledger_sequence);

CREATE OR REPLACE FUNCTION preserve_ledger_sequence() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.ledger_sequence IS DISTINCT FROM OLD.ledger_sequence THEN
        RAISE EXCEPTION 'ledger transaction sequence is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER ledger_transactions_sequence_immutable
    BEFORE UPDATE ON ledger_transactions
    FOR EACH ROW EXECUTE FUNCTION preserve_ledger_sequence();

CREATE TABLE wallet_reconciliations (
    deployment_id UUID NOT NULL,
    id UUID NOT NULL,
    chain TEXT NOT NULL CHECK (chain IN ('wcash', 'zcash')),
    ledger_root BYTEA NOT NULL CHECK (octet_length(ledger_root) = 32),
    ledger_transaction_count BIGINT NOT NULL CHECK (ledger_transaction_count >= 0),
    wallet_state_digest BYTEA NOT NULL CHECK (octet_length(wallet_state_digest) = 32),
    wallet_spendable_zat BIGINT NOT NULL CHECK (wallet_spendable_zat >= 0),
    ledger_spendable_zat BIGINT NOT NULL CHECK (ledger_spendable_zat >= 0),
    best_tip_hash BYTEA NOT NULL CHECK (octet_length(best_tip_hash) = 32),
    best_tip_height BIGINT NOT NULL CHECK (best_tip_height > 0),
    observed_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('matched', 'mismatch')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (deployment_id, id),
    FOREIGN KEY (deployment_id, chain)
        REFERENCES chain_policies(deployment_id, chain) ON DELETE RESTRICT,
    CHECK (valid_until > observed_at),
    CHECK (valid_until <= observed_at + INTERVAL '5 minutes'),
    CHECK ((status = 'matched') = (wallet_spendable_zat = ledger_spendable_zat))
);
CREATE INDEX wallet_reconciliations_latest_idx
    ON wallet_reconciliations(deployment_id, chain, observed_at DESC, id DESC);

CREATE TRIGGER wallet_reconciliations_append_only
    BEFORE UPDATE OR DELETE ON wallet_reconciliations
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();

ALTER TABLE payout_batches
    ADD COLUMN reconciliation_id UUID,
    ADD COLUMN ledger_root BYTEA CHECK (
        ledger_root IS NULL OR octet_length(ledger_root) = 32
    ),
    ADD COLUMN ledger_sequence_cutoff BIGINT CHECK (
        ledger_sequence_cutoff IS NULL OR ledger_sequence_cutoff > 0
    ),
    ADD FOREIGN KEY (deployment_id, reconciliation_id)
        REFERENCES wallet_reconciliations(deployment_id, id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (deployment_id, ledger_sequence_cutoff)
        REFERENCES ledger_transactions(deployment_id, ledger_sequence) ON DELETE RESTRICT;
CREATE UNIQUE INDEX payout_batches_one_reconciliation_idx
    ON payout_batches(deployment_id, reconciliation_id)
    WHERE reconciliation_id IS NOT NULL;

-- Every signer output has its own stable idempotency identity. Existing
-- batches predate signer requests, so their already unique destination row is
-- a safe deterministic backfill within each batch.
ALTER TABLE payout_items ADD COLUMN allocation_id UUID;
UPDATE payout_items SET allocation_id = destination_id;
ALTER TABLE payout_items ALTER COLUMN allocation_id SET NOT NULL;
CREATE UNIQUE INDEX payout_items_allocation_idx
    ON payout_items(deployment_id, batch_id, allocation_id);

ALTER TABLE payout_batches ADD CONSTRAINT payout_batches_reconciliation_complete CHECK (
    (reconciliation_id IS NULL AND ledger_root IS NULL AND ledger_sequence_cutoff IS NULL)
    OR (reconciliation_id IS NOT NULL AND ledger_root IS NOT NULL
        AND ledger_sequence_cutoff IS NOT NULL)
);

-- The isolated signer contract has a stricter reviewed transaction bound than
-- the original generic accounting schema. Keep operator policy within it.
ALTER TABLE chain_policies
    DROP CONSTRAINT chain_policies_maximum_payout_outputs_check;
ALTER TABLE chain_policies
    ADD CONSTRAINT chain_policies_maximum_payout_outputs_check
    CHECK (maximum_payout_outputs BETWEEN 1 AND 200);

-- A payout destination may advance through its lifecycle, but its address and
-- parser attestation can never change underneath a reserved payout item.
CREATE OR REPLACE FUNCTION permit_only_destination_lifecycle() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE'
       OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.account_id IS DISTINCT FROM OLD.account_id
       OR NEW.chain IS DISTINCT FROM OLD.chain
       OR NEW.network IS DISTINCT FROM OLD.network
       OR NEW.address IS DISTINCT FROM OLD.address
       OR NEW.receiver_kind IS DISTINCT FROM OLD.receiver_kind
       OR NEW.validated_by IS DISTINCT FROM OLD.validated_by
       OR NEW.validated_at IS DISTINCT FROM OLD.validated_at
       OR NEW.active_after IS DISTINCT FROM OLD.active_after
       OR NEW.address_digest IS DISTINCT FROM OLD.address_digest
       OR NEW.payout_threshold_zat IS DISTINCT FROM OLD.payout_threshold_zat
       OR NEW.automatic IS DISTINCT FROM OLD.automatic
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.revision IS DISTINCT FROM OLD.revision THEN
        RAISE EXCEPTION 'payout destination facts are immutable';
    END IF;
    IF NOT (
        (OLD.state = 'pending' AND NEW.state = 'active' AND NEW.disabled_at IS NULL)
        OR (OLD.state IN ('pending','active') AND NEW.state = 'disabled'
            AND NEW.disabled_at IS NOT NULL)
    ) THEN
        RAISE EXCEPTION 'invalid payout destination lifecycle transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER payout_destinations_lifecycle_only
    BEFORE UPDATE OR DELETE ON payout_destinations
    FOR EACH ROW EXECUTE FUNCTION permit_only_destination_lifecycle();

-- Payout items are open only while their draft parent has no reconciliation
-- seal. The batch's one permitted sealing update validates both the item set
-- and the exact payout-reservation ledger fence.
CREATE OR REPLACE FUNCTION reject_payout_item_after_seal() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    parent_is_open BOOLEAN;
BEGIN
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

CREATE TRIGGER payout_items_require_open_parent
    BEFORE INSERT ON payout_items
    FOR EACH ROW EXECUTE FUNCTION reject_payout_item_after_seal();
CREATE TRIGGER payout_items_append_only
    BEFORE UPDATE OR DELETE ON payout_items
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();

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
    IF OLD.state = 'draft' AND NEW.state = 'signed' THEN
        IF NEW.confirmation_block_hash IS NOT NULL OR NEW.confirmation_height IS NOT NULL
           OR NEW.confirmation_count IS NOT NULL THEN
            RAISE EXCEPTION 'signed payout cannot contain confirmation evidence';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'signed' AND NEW.state = 'broadcast' THEN
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

CREATE TRIGGER payout_batches_seal_only
    BEFORE UPDATE OR DELETE ON payout_batches
    FOR EACH ROW EXECUTE FUNCTION permit_only_payout_batch_seal();
