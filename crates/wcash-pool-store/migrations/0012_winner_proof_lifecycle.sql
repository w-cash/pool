-- One Wcash candidate may have several valid AuxPoW witnesses with the same
-- proof-independent block ID. Keep their lifecycle separate from its one
-- economic reward and immutable original winning share/PPLNS allocation.
-- SQLx runs this whole migration atomically; the lock fences old projectors
-- before their current winner states are copied.
LOCK TABLE public.backend_cursors IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.winners IN ACCESS EXCLUSIVE MODE;

-- A committed, independently validated Zcash side chain remains retained
-- without a reward, including after the node eventually prunes its fork.
ALTER TABLE public.winners DROP CONSTRAINT winners_state_check;
ALTER TABLE public.winners ADD CONSTRAINT winners_state_check CHECK (state IN
    ('submitted', 'side_chain', 'observed', 'matured', 'quarantined', 'requeued', 'orphaned'));

ALTER TABLE public.winners ADD CONSTRAINT winners_side_chain_profile_check
    CHECK (state <> 'side_chain' OR chain = 'zcash');

ALTER TABLE public.shares ADD CONSTRAINT shares_committed_job_key
    UNIQUE (deployment_id, share_id, job_id);

CREATE TABLE public.winner_proofs (
    deployment_id UUID NOT NULL,
    chain TEXT NOT NULL CHECK (chain IN ('wcash', 'zcash')),
    block_hash_le BYTEA NOT NULL CHECK (octet_length(block_hash_le) = 32),
    share_id BYTEA NOT NULL CHECK (octet_length(share_id) = 32),
    job_id BYTEA NOT NULL CHECK (octet_length(job_id) = 32),
    state TEXT NOT NULL CHECK (state IN
        ('submitted', 'side_chain', 'observed', 'matured', 'quarantined', 'requeued', 'orphaned')),
    CHECK (state <> 'side_chain' OR chain = 'zcash'),
    PRIMARY KEY (deployment_id, chain, block_hash_le, share_id),
    UNIQUE (deployment_id, chain, share_id),
    FOREIGN KEY (deployment_id, chain, block_hash_le)
        REFERENCES public.winners(deployment_id, chain, block_hash_le) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, share_id, job_id)
        REFERENCES public.shares(deployment_id, share_id, job_id) ON DELETE RESTRICT
);

INSERT INTO public.winner_proofs
    (deployment_id, chain, block_hash_le, share_id, job_id, state)
SELECT deployment_id, chain, block_hash_le, share_id, job_id, state
FROM public.winners;

ALTER TABLE public.winners ADD COLUMN active_proof_share_id BYTEA
    CHECK (active_proof_share_id IS NULL OR octet_length(active_proof_share_id) = 32);
UPDATE public.winners SET active_proof_share_id = share_id
WHERE state IN ('observed', 'matured');
ALTER TABLE public.winners ADD CONSTRAINT winners_canonical_proof_fkey
    FOREIGN KEY (deployment_id, chain, block_hash_le, share_id)
    REFERENCES public.winner_proofs(deployment_id, chain, block_hash_le, share_id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE public.winners ADD CONSTRAINT winners_active_proof_fkey
    FOREIGN KEY (deployment_id, chain, block_hash_le, active_proof_share_id)
    REFERENCES public.winner_proofs(deployment_id, chain, block_hash_le, share_id)
    ON DELETE RESTRICT;

-- A fresh maturity observation can restore a reward conservatively reversed
-- by another witness. Both typed movements belong to that one atomic event.
-- Their individual kinds, not event sequence alone, identify reversal sources.
ALTER TABLE public.ledger_transactions
    DROP CONSTRAINT ledger_transactions_deployment_id_backend_event_seq_key;
ALTER TABLE public.ledger_transactions ADD CONSTRAINT ledger_backend_event_kind_key
    UNIQUE (deployment_id, backend_event_seq, kind);

CREATE FUNCTION public.guard_winner_proof_identity_v1() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'winner proof cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF (NEW.deployment_id, NEW.chain, NEW.block_hash_le, NEW.share_id, NEW.job_id)
        IS DISTINCT FROM
       (OLD.deployment_id, OLD.chain, OLD.block_hash_le, OLD.share_id, OLD.job_id)
    THEN
        RAISE EXCEPTION 'winner proof identity is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER winner_proofs_identity_immutable
    BEFORE UPDATE OR DELETE ON public.winner_proofs
    FOR EACH ROW EXECUTE FUNCTION public.guard_winner_proof_identity_v1();
REVOKE ALL ON FUNCTION public.guard_winner_proof_identity_v1() FROM PUBLIC;

CREATE FUNCTION public.guard_winner_candidate_identity_v1() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF (NEW.deployment_id, NEW.chain, NEW.block_hash_le, NEW.share_id, NEW.job_id,
        NEW.height, NEW.coinbase_txid_le, NEW.reward_zat, NEW.maturity_confirmations)
        IS DISTINCT FROM
       (OLD.deployment_id, OLD.chain, OLD.block_hash_le, OLD.share_id, OLD.job_id,
        OLD.height, OLD.coinbase_txid_le, OLD.reward_zat, OLD.maturity_confirmations)
    THEN
        RAISE EXCEPTION 'winner candidate and original winning share are immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER winners_candidate_identity_immutable
    BEFORE UPDATE ON public.winners
    FOR EACH ROW EXECUTE FUNCTION public.guard_winner_candidate_identity_v1();
REVOKE ALL ON FUNCTION public.guard_winner_candidate_identity_v1() FROM PUBLIC;
