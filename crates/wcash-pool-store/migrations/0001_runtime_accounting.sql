-- Every row is scoped to an explicit deployment. Testnet and Mainnet may share
-- a PostgreSQL cluster, but never a cursor, account, nonce range, or balance.

CREATE TABLE deployments (
    id UUID PRIMARY KEY,
    network TEXT NOT NULL CHECK (network IN ('testnet', 'mainnet')),
    wcash_genesis BYTEA NOT NULL CHECK (octet_length(wcash_genesis) = 32),
    zcash_genesis BYTEA NOT NULL CHECK (octet_length(zcash_genesis) = 32),
    chain_id BIGINT NOT NULL CHECK (chain_id BETWEEN 1 AND 4294967295),
    wcash_payout_commitment BYTEA NOT NULL CHECK (octet_length(wcash_payout_commitment) = 32),
    zcash_payout_commitment BYTEA NOT NULL CHECK (octet_length(zcash_payout_commitment) = 32),
    backend_instance UUID NOT NULL,
    journal_stream UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (backend_instance <> journal_stream),
    UNIQUE (wcash_genesis, zcash_genesis, chain_id, wcash_payout_commitment,
            zcash_payout_commitment, backend_instance, journal_stream)
);

CREATE TABLE backend_cursors (
    deployment_id UUID PRIMARY KEY REFERENCES deployments(id) ON DELETE RESTRICT,
    last_event_seq BIGINT NOT NULL DEFAULT 0 CHECK (last_event_seq >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE accounts (
    deployment_id UUID NOT NULL REFERENCES deployments(id) ON DELETE RESTRICT,
    id UUID NOT NULL,
    login TEXT NOT NULL CHECK (login ~ '^[a-z0-9_-]{1,64}$'),
    password_verifier TEXT CHECK (password_verifier IS NULL OR password_verifier LIKE '$argon2id$%'),
    totp_secret_sealed BYTEA,
    totp_pending_sealed BYTEA,
    totp_pending_expires_at TIMESTAMPTZ,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
    locked_until TIMESTAMPTZ,
    security_version BIGINT NOT NULL DEFAULT 1 CHECK (security_version > 0),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (deployment_id, id),
    UNIQUE (deployment_id, login)
);

CREATE TABLE workers (
    deployment_id UUID NOT NULL,
    id UUID NOT NULL,
    account_id UUID NOT NULL,
    label TEXT NOT NULL CHECK (label ~ '^[a-z0-9_-]{1,63}$'),
    canonical_login TEXT NOT NULL CHECK (length(canonical_login) BETWEEN 3 AND 128),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (deployment_id, id),
    UNIQUE (deployment_id, account_id, label),
    UNIQUE (deployment_id, canonical_login),
    FOREIGN KEY (deployment_id, account_id)
        REFERENCES accounts(deployment_id, id) ON DELETE RESTRICT
);

CREATE TABLE mining_tokens (
    deployment_id UUID NOT NULL,
    id UUID NOT NULL,
    worker_id UUID NOT NULL,
    verifier TEXT NOT NULL CHECK (verifier LIKE '$argon2id$%'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (deployment_id, id),
    FOREIGN KEY (deployment_id, worker_id)
        REFERENCES workers(deployment_id, id) ON DELETE RESTRICT,
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX mining_tokens_worker_idx ON mining_tokens(deployment_id, worker_id);

CREATE TABLE portal_sessions (
    deployment_id UUID NOT NULL,
    token_digest BYTEA NOT NULL CHECK (octet_length(token_digest) = 32),
    csrf_digest BYTEA NOT NULL CHECK (octet_length(csrf_digest) = 32),
    account_id UUID NOT NULL,
    security_version BIGINT NOT NULL CHECK (security_version > 0),
    authenticated_at TIMESTAMPTZ NOT NULL,
    second_factor_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (deployment_id, token_digest),
    FOREIGN KEY (deployment_id, account_id)
        REFERENCES accounts(deployment_id, id) ON DELETE RESTRICT,
    CHECK (expires_at > authenticated_at),
    CHECK (idle_expires_at <= expires_at)
);
CREATE INDEX portal_sessions_account_idx ON portal_sessions(deployment_id, account_id);

CREATE TABLE chain_policies (
    deployment_id UUID NOT NULL REFERENCES deployments(id) ON DELETE RESTRICT,
    chain TEXT NOT NULL CHECK (chain IN ('wcash', 'zcash')),
    pplns_window_work NUMERIC(78, 0) NOT NULL CHECK (pplns_window_work > 0),
    fee_bps INTEGER NOT NULL CHECK (fee_bps BETWEEN 0 AND 1000),
    payout_threshold_zat BIGINT NOT NULL CHECK (payout_threshold_zat > 0),
    required_confirmations INTEGER NOT NULL CHECK (required_confirmations BETWEEN 100 AND 1000000),
    maximum_payout_outputs INTEGER NOT NULL CHECK (maximum_payout_outputs BETWEEN 1 AND 1000),
    maximum_network_fee_zat BIGINT NOT NULL CHECK (maximum_network_fee_zat >= 0),
    maximum_network_fee_bps INTEGER NOT NULL CHECK (maximum_network_fee_bps BETWEEN 1 AND 1000),
    policy_version BIGINT NOT NULL CHECK (policy_version > 0),
    PRIMARY KEY (deployment_id, chain),
    UNIQUE (deployment_id, chain, policy_version)
);

CREATE TABLE chain_safety_state (
    deployment_id UUID NOT NULL,
    chain TEXT NOT NULL CHECK (chain IN ('wcash', 'zcash')),
    payouts_frozen BOOLEAN NOT NULL DEFAULT FALSE,
    frozen_by_backend_event_seq BIGINT,
    freeze_reason TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (deployment_id, chain),
    FOREIGN KEY (deployment_id, chain)
        REFERENCES chain_policies(deployment_id, chain) ON DELETE RESTRICT,
    CHECK (
        (NOT payouts_frozen AND frozen_by_backend_event_seq IS NULL AND freeze_reason IS NULL)
        OR (payouts_frozen AND length(freeze_reason) BETWEEN 1 AND 128)
    )
);

CREATE TABLE payout_destinations (
    deployment_id UUID NOT NULL,
    id UUID NOT NULL,
    account_id UUID NOT NULL,
    chain TEXT NOT NULL CHECK (chain IN ('wcash', 'zcash')),
    network TEXT NOT NULL CHECK (network IN ('testnet', 'mainnet')),
    address TEXT NOT NULL CHECK (length(address) BETWEEN 8 AND 512),
    receiver_kind TEXT NOT NULL CHECK (receiver_kind IN ('transparent', 'ironwood')),
    validated_by TEXT NOT NULL CHECK (length(validated_by) BETWEEN 1 AND 128),
    validated_at TIMESTAMPTZ NOT NULL,
    active_after TIMESTAMPTZ NOT NULL,
    address_digest BYTEA NOT NULL CHECK (octet_length(address_digest) = 32),
    payout_threshold_zat BIGINT NOT NULL CHECK (payout_threshold_zat > 0),
    automatic BOOLEAN NOT NULL DEFAULT TRUE,
    state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'disabled')),
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (deployment_id, id),
    FOREIGN KEY (deployment_id, account_id)
        REFERENCES accounts(deployment_id, id) ON DELETE RESTRICT,
    CHECK ((state = 'disabled') = (disabled_at IS NOT NULL)),
    CHECK (disabled_at IS NULL OR disabled_at >= created_at)
);
CREATE UNIQUE INDEX payout_destinations_one_active_idx
    ON payout_destinations(deployment_id, account_id, chain)
    WHERE state = 'active';
CREATE UNIQUE INDEX payout_destinations_one_pending_idx
    ON payout_destinations(deployment_id, account_id, chain)
    WHERE state = 'pending';

CREATE TABLE payout_change_events (
    deployment_id UUID NOT NULL,
    id UUID NOT NULL,
    account_id UUID NOT NULL,
    chain TEXT NOT NULL CHECK (chain IN ('wcash', 'zcash')),
    address_digest BYTEA NOT NULL CHECK (octet_length(address_digest) = 32),
    payout_threshold_zat BIGINT NOT NULL CHECK (payout_threshold_zat > 0),
    automatic BOOLEAN NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    active_after TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (deployment_id, id),
    FOREIGN KEY (deployment_id, account_id)
        REFERENCES accounts(deployment_id, id) ON DELETE RESTRICT
);

CREATE TABLE nonce_cursors (
    deployment_id UUID NOT NULL REFERENCES deployments(id) ON DELETE RESTRICT,
    profile SMALLINT NOT NULL CHECK (profile IN (4, 8)),
    namespace SMALLINT NOT NULL CHECK (namespace BETWEEN 1 AND 127),
    next_counter BIGINT NOT NULL CHECK (next_counter >= 0),
    PRIMARY KEY (deployment_id, profile, namespace)
);

CREATE TABLE nonce_range_leases (
    deployment_id UUID NOT NULL,
    id UUID NOT NULL,
    pool_instance UUID NOT NULL,
    profile SMALLINT NOT NULL,
    namespace SMALLINT NOT NULL,
    range_start BIGINT NOT NULL CHECK (range_start >= 0),
    range_end BIGINT NOT NULL CHECK (range_end > range_start),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (deployment_id, id),
    FOREIGN KEY (deployment_id, profile, namespace)
        REFERENCES nonce_cursors(deployment_id, profile, namespace) ON DELETE RESTRICT,
    UNIQUE (deployment_id, profile, namespace, range_start, range_end)
);

CREATE TABLE backend_events (
    deployment_id UUID NOT NULL,
    event_seq BIGINT NOT NULL CHECK (event_seq > 0),
    event_kind TEXT NOT NULL,
    payload JSONB NOT NULL,
    payload_sha256 BYTEA NOT NULL CHECK (octet_length(payload_sha256) = 32),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (deployment_id, event_seq),
    FOREIGN KEY (deployment_id) REFERENCES deployments(id) ON DELETE RESTRICT
);

ALTER TABLE chain_safety_state
    ADD FOREIGN KEY (deployment_id, frozen_by_backend_event_seq)
    REFERENCES backend_events(deployment_id, event_seq) ON DELETE RESTRICT;

CREATE TABLE jobs (
    deployment_id UUID NOT NULL,
    job_id BYTEA NOT NULL CHECK (octet_length(job_id) = 32),
    activation_event_seq BIGINT NOT NULL,
    descriptor JSONB NOT NULL,
    PRIMARY KEY (deployment_id, job_id),
    FOREIGN KEY (deployment_id, activation_event_seq)
        REFERENCES backend_events(deployment_id, event_seq) ON DELETE RESTRICT
);

CREATE TABLE shares (
    deployment_id UUID NOT NULL,
    share_id BYTEA NOT NULL CHECK (octet_length(share_id) = 32),
    event_seq BIGINT NOT NULL,
    job_id BYTEA NOT NULL CHECK (octet_length(job_id) = 32),
    account_id UUID NOT NULL,
    worker_id UUID NOT NULL,
    target_le BYTEA NOT NULL CHECK (octet_length(target_le) = 32),
    work NUMERIC(78, 0) NOT NULL CHECK (work > 0),
    parent_hash_le BYTEA NOT NULL CHECK (octet_length(parent_hash_le) = 32),
    PRIMARY KEY (deployment_id, share_id),
    UNIQUE (deployment_id, event_seq),
    FOREIGN KEY (deployment_id, event_seq)
        REFERENCES backend_events(deployment_id, event_seq) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, job_id)
        REFERENCES jobs(deployment_id, job_id) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, account_id)
        REFERENCES accounts(deployment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, worker_id)
        REFERENCES workers(deployment_id, id) ON DELETE RESTRICT
);
CREATE INDEX shares_pplns_idx ON shares(deployment_id, event_seq DESC);

CREATE TABLE winners (
    deployment_id UUID NOT NULL,
    chain TEXT NOT NULL CHECK (chain IN ('wcash', 'zcash')),
    block_hash_le BYTEA NOT NULL CHECK (octet_length(block_hash_le) = 32),
    share_id BYTEA NOT NULL CHECK (octet_length(share_id) = 32),
    job_id BYTEA NOT NULL CHECK (octet_length(job_id) = 32),
    height BIGINT NOT NULL CHECK (height > 0),
    coinbase_txid_le BYTEA NOT NULL CHECK (octet_length(coinbase_txid_le) = 32),
    reward_zat BIGINT NOT NULL CHECK (reward_zat > 0),
    maturity_confirmations INTEGER NOT NULL CHECK (maturity_confirmations BETWEEN 1 AND 1000000),
    state TEXT NOT NULL CHECK (state IN ('submitted', 'observed', 'matured', 'quarantined', 'requeued', 'orphaned')),
    active_observation_event_seq BIGINT,
    active_maturity_event_seq BIGINT,
    PRIMARY KEY (deployment_id, chain, block_hash_le),
    FOREIGN KEY (deployment_id, share_id)
        REFERENCES shares(deployment_id, share_id) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, job_id)
        REFERENCES jobs(deployment_id, job_id) ON DELETE RESTRICT
);

CREATE TABLE winner_allocations (
    deployment_id UUID NOT NULL,
    chain TEXT NOT NULL,
    block_hash_le BYTEA NOT NULL,
    observation_event_seq BIGINT NOT NULL,
    policy_version BIGINT NOT NULL,
    account_id UUID NOT NULL,
    selected_work NUMERIC(78, 0) NOT NULL CHECK (selected_work > 0),
    amount_zat BIGINT NOT NULL CHECK (amount_zat >= 0),
    PRIMARY KEY (deployment_id, chain, block_hash_le, observation_event_seq, account_id),
    FOREIGN KEY (deployment_id, chain, block_hash_le)
        REFERENCES winners(deployment_id, chain, block_hash_le) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, chain, policy_version)
        REFERENCES chain_policies(deployment_id, chain, policy_version) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, account_id)
        REFERENCES accounts(deployment_id, id) ON DELETE RESTRICT
);

CREATE TABLE ledger_transactions (
    deployment_id UUID NOT NULL,
    id UUID NOT NULL,
    chain TEXT NOT NULL CHECK (chain IN ('wcash', 'zcash')),
    kind TEXT NOT NULL CHECK (kind IN ('winner_observed', 'winner_matured', 'winner_orphaned',
                                      'winner_quarantined',
                                      'payout_reserved', 'payout_released', 'payout_confirmed',
                                      'payout_reorged', 'operator_capital_funded')),
    backend_event_seq BIGINT,
    reference TEXT NOT NULL CHECK (length(reference) BETWEEN 1 AND 256),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    sealed_at TIMESTAMPTZ,
    sealed_entry_count INTEGER,
    PRIMARY KEY (deployment_id, id),
    UNIQUE (deployment_id, backend_event_seq),
    FOREIGN KEY (deployment_id) REFERENCES deployments(id) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, backend_event_seq)
        REFERENCES backend_events(deployment_id, event_seq) ON DELETE RESTRICT,
    CHECK (
        (sealed_at IS NULL AND sealed_entry_count IS NULL)
        OR (sealed_at IS NOT NULL AND sealed_entry_count >= 2)
    )
);

CREATE TABLE ledger_entries (
    deployment_id UUID NOT NULL,
    transaction_id UUID NOT NULL,
    line_no INTEGER NOT NULL CHECK (line_no > 0),
    account_id UUID,
    ledger_account TEXT NOT NULL CHECK (ledger_account IN ('collector_immature_asset',
                                                            'collector_spendable_asset',
                                                            'miner_immature',
                                                            'miner_payable', 'payout_pending',
                                                            'pool_fee_unearned', 'pool_equity',
                                                            'network_fee_expense')),
    amount_zat BIGINT NOT NULL CHECK (amount_zat <> 0),
    PRIMARY KEY (deployment_id, transaction_id, line_no),
    FOREIGN KEY (deployment_id, transaction_id)
        REFERENCES ledger_transactions(deployment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, account_id)
        REFERENCES accounts(deployment_id, id) ON DELETE RESTRICT,
    CHECK ((ledger_account IN ('miner_immature', 'miner_payable', 'payout_pending')) = (account_id IS NOT NULL))
);
CREATE INDEX ledger_account_balance_idx
    ON ledger_entries(deployment_id, ledger_account, account_id);

CREATE TABLE payout_batches (
    deployment_id UUID NOT NULL,
    id UUID NOT NULL,
    chain TEXT NOT NULL CHECK (chain IN ('wcash', 'zcash')),
    policy_version BIGINT NOT NULL,
    idempotency_key UUID NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('draft', 'signed', 'broadcast', 'confirmed', 'reorged', 'cancelled')),
    unsigned_digest BYTEA CHECK (unsigned_digest IS NULL OR octet_length(unsigned_digest) = 32),
    transaction_id BYTEA CHECK (transaction_id IS NULL OR octet_length(transaction_id) = 32),
    signed_transaction BYTEA CHECK (
        signed_transaction IS NULL OR octet_length(signed_transaction) BETWEEN 1 AND 4194304
    ),
    network_fee_zat BIGINT CHECK (network_fee_zat IS NULL OR network_fee_zat >= 0),
    confirmation_block_hash BYTEA CHECK (
        confirmation_block_hash IS NULL OR octet_length(confirmation_block_hash) = 32
    ),
    confirmation_height BIGINT CHECK (confirmation_height IS NULL OR confirmation_height > 0),
    confirmation_count INTEGER CHECK (confirmation_count IS NULL OR confirmation_count > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (deployment_id, id),
    UNIQUE (deployment_id, idempotency_key),
    FOREIGN KEY (deployment_id) REFERENCES deployments(id) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, chain, policy_version)
        REFERENCES chain_policies(deployment_id, chain, policy_version) ON DELETE RESTRICT,
    CHECK (
        (state IN ('draft', 'cancelled')
         AND unsigned_digest IS NULL AND transaction_id IS NULL
         AND signed_transaction IS NULL AND network_fee_zat IS NULL)
        OR
        (state IN ('signed', 'broadcast', 'confirmed', 'reorged')
         AND unsigned_digest IS NOT NULL AND transaction_id IS NOT NULL
         AND signed_transaction IS NOT NULL AND network_fee_zat IS NOT NULL)
    ),
    CHECK (
        (state IN ('confirmed', 'reorged') AND confirmation_block_hash IS NOT NULL
         AND confirmation_height IS NOT NULL AND confirmation_count IS NOT NULL)
        OR (state NOT IN ('confirmed', 'reorged') AND confirmation_block_hash IS NULL
            AND confirmation_height IS NULL AND confirmation_count IS NULL)
    )
);

CREATE TABLE payout_items (
    deployment_id UUID NOT NULL,
    batch_id UUID NOT NULL,
    account_id UUID NOT NULL,
    destination_id UUID NOT NULL,
    amount_zat BIGINT NOT NULL CHECK (amount_zat > 0),
    PRIMARY KEY (deployment_id, batch_id, account_id),
    FOREIGN KEY (deployment_id, batch_id)
        REFERENCES payout_batches(deployment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, account_id)
        REFERENCES accounts(deployment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, destination_id)
        REFERENCES payout_destinations(deployment_id, id) ON DELETE RESTRICT
);

CREATE TABLE payout_reorg_events (
    deployment_id UUID NOT NULL,
    id UUID NOT NULL,
    batch_id UUID NOT NULL,
    prior_block_hash BYTEA NOT NULL CHECK (octet_length(prior_block_hash) = 32),
    prior_block_height BIGINT NOT NULL CHECK (prior_block_height > 0),
    prior_confirmations INTEGER NOT NULL CHECK (prior_confirmations > 0),
    replacement_tip_hash BYTEA NOT NULL CHECK (octet_length(replacement_tip_hash) = 32),
    replacement_tip_height BIGINT NOT NULL CHECK (replacement_tip_height > 0),
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (deployment_id, id),
    UNIQUE (deployment_id, batch_id, prior_block_hash, replacement_tip_hash),
    FOREIGN KEY (deployment_id, batch_id)
        REFERENCES payout_batches(deployment_id, id) ON DELETE RESTRICT,
    CHECK (prior_block_hash <> replacement_tip_hash)
);

CREATE UNIQUE INDEX payout_batches_chain_transaction_idx
    ON payout_batches(deployment_id, chain, transaction_id)
    WHERE transaction_id IS NOT NULL;

CREATE OR REPLACE FUNCTION reject_append_only_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER backend_events_append_only
    BEFORE UPDATE OR DELETE ON backend_events
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();
CREATE TRIGGER chain_policies_append_only
    BEFORE UPDATE OR DELETE ON chain_policies
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();
CREATE TRIGGER ledger_entries_append_only
    BEFORE UPDATE OR DELETE ON ledger_entries
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();
CREATE TRIGGER winner_allocations_append_only
    BEFORE UPDATE OR DELETE ON winner_allocations
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();
CREATE TRIGGER payout_change_events_append_only
    BEFORE UPDATE OR DELETE ON payout_change_events
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();
CREATE TRIGGER payout_reorg_events_append_only
    BEFORE UPDATE OR DELETE ON payout_reorg_events
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();

-- A ledger transaction has one permitted mutation: atomically sealing its
-- already-balanced lines. Every other update and all deletes are rejected.
CREATE OR REPLACE FUNCTION permit_only_ledger_seal() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    actual_count BIGINT;
    balance NUMERIC(78, 0);
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'ledger transaction is immutable and cannot be deleted';
    END IF;
    IF OLD.sealed_at IS NOT NULL
       OR NEW.sealed_at IS NULL
       OR NEW.sealed_entry_count IS NULL
       OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.chain IS DISTINCT FROM OLD.chain
       OR NEW.kind IS DISTINCT FROM OLD.kind
       OR NEW.backend_event_seq IS DISTINCT FROM OLD.backend_event_seq
       OR NEW.reference IS DISTINCT FROM OLD.reference
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'ledger transaction is immutable except for its initial seal';
    END IF;
    SELECT COUNT(*), COALESCE(SUM(amount_zat), 0)
      INTO actual_count, balance
      FROM ledger_entries
     WHERE deployment_id = OLD.deployment_id
       AND transaction_id = OLD.id;
    IF actual_count < 2 OR balance <> 0 OR actual_count <> NEW.sealed_entry_count THEN
        RAISE EXCEPTION 'cannot seal incomplete ledger transaction % (entries %, recorded %, sum %)',
            OLD.id, actual_count, NEW.sealed_entry_count, balance;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER ledger_transactions_seal_only
    BEFORE UPDATE OR DELETE ON ledger_transactions
    FOR EACH ROW EXECUTE FUNCTION permit_only_ledger_seal();

-- Lock the parent row before every append. A concurrent seal therefore wins
-- or waits deterministically, and no entry can commit after the completion
-- fence becomes visible.
CREATE OR REPLACE FUNCTION reject_entry_after_ledger_seal() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    parent_is_open BOOLEAN;
BEGIN
    SELECT sealed_at IS NULL
      INTO parent_is_open
      FROM ledger_transactions
     WHERE deployment_id = NEW.deployment_id
       AND id = NEW.transaction_id
     FOR UPDATE;
    IF parent_is_open IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'ledger transaction % is already sealed', NEW.transaction_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER ledger_entries_require_open_parent
    BEFORE INSERT ON ledger_entries
    FOR EACH ROW EXECUTE FUNCTION reject_entry_after_ledger_seal();

CREATE OR REPLACE FUNCTION require_balanced_ledger_transaction() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    target_deployment UUID;
    target_transaction UUID;
    balance NUMERIC(78, 0);
BEGIN
    target_deployment := NEW.deployment_id;
    target_transaction := NEW.transaction_id;
    SELECT COALESCE(SUM(amount_zat), 0)
      INTO balance
      FROM ledger_entries
     WHERE deployment_id = target_deployment
       AND transaction_id = target_transaction;
    IF balance <> 0 THEN
        RAISE EXCEPTION 'unbalanced ledger transaction % (sum %)', target_transaction, balance;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER ledger_entries_balanced
    AFTER INSERT ON ledger_entries
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION require_balanced_ledger_transaction();

-- An entry trigger never fires for an empty ledger transaction. Check the
-- parent row at commit as well, which also proves that multi-row inserts have
-- reached their final, conserved state.
CREATE OR REPLACE FUNCTION require_complete_ledger_transaction() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    entry_count BIGINT;
    recorded_entry_count INTEGER;
    completion_time TIMESTAMPTZ;
    balance NUMERIC(78, 0);
BEGIN
    SELECT sealed_entry_count, sealed_at
      INTO recorded_entry_count, completion_time
      FROM ledger_transactions
     WHERE deployment_id = NEW.deployment_id
       AND id = NEW.id;
    SELECT COUNT(*), COALESCE(SUM(amount_zat), 0)
      INTO entry_count, balance
      FROM ledger_entries
     WHERE deployment_id = NEW.deployment_id
       AND transaction_id = NEW.id;
    IF completion_time IS NULL OR recorded_entry_count IS NULL
       OR entry_count < 2 OR balance <> 0 OR entry_count <> recorded_entry_count THEN
        RAISE EXCEPTION 'incomplete or unsealed ledger transaction % (entries %, recorded %, sum %)',
            NEW.id, entry_count, recorded_entry_count, balance;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER ledger_transactions_complete
    AFTER INSERT OR UPDATE ON ledger_transactions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION require_complete_ledger_transaction();
