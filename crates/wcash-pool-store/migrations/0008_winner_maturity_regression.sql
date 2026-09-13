-- Preserve a canonical winner's original PPLNS allocation when a reorg above
-- it temporarily drops confirmation depth below coinbase maturity.
ALTER TABLE ledger_transactions
    DROP CONSTRAINT ledger_transactions_kind_check;

ALTER TABLE ledger_transactions
    ADD CONSTRAINT ledger_transactions_kind_check
    CHECK (kind IN ('winner_observed', 'winner_matured', 'winner_dematured',
                    'winner_orphaned', 'winner_quarantined',
                    'payout_reserved', 'payout_released', 'payout_confirmed',
                    'payout_reorged', 'operator_capital_funded'));

-- Migration 0006 deliberately whitelists every accepted freeze cause. Extend
-- that definer boundary for a still-canonical winner whose confirmation depth
-- falls back below maturity.
CREATE OR REPLACE FUNCTION public.freeze_chain_payouts_v1(
    p_deployment_id UUID,
    p_chain TEXT,
    p_backend_event_seq BIGINT,
    p_reason TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF p_deployment_id IS NULL
        OR p_deployment_id = '00000000-0000-0000-0000-000000000000'::UUID
        OR p_chain NOT IN ('wcash', 'zcash')
        OR p_reason NOT IN (
            'wallet_reconciliation_mismatch',
            'confirmed_payout_reorg',
            'matured_winner_reorg',
            'matured_winner_depth_regression'
        )
        OR (p_reason IN (
                'matured_winner_reorg',
                'matured_winner_depth_regression'
            )) <> (p_backend_event_seq IS NOT NULL)
        OR (p_backend_event_seq IS NOT NULL AND p_backend_event_seq <= 0)
    THEN
        RAISE EXCEPTION 'invalid payout freeze request' USING ERRCODE = '22023';
    END IF;

    UPDATE public.chain_safety_state
       SET payouts_frozen = TRUE,
           frozen_by_backend_event_seq = CASE
               WHEN payouts_frozen THEN frozen_by_backend_event_seq
               ELSE p_backend_event_seq
           END,
           freeze_reason = CASE WHEN payouts_frozen THEN freeze_reason ELSE p_reason END,
           updated_at = clock_timestamp()
     WHERE deployment_id = p_deployment_id AND chain = p_chain;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'chain safety state not found' USING ERRCODE = 'P0002';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.freeze_chain_payouts_v1(UUID,TEXT,BIGINT,TEXT)
FROM PUBLIC;

-- Earlier binaries accepted a backend maturity requirement below the sealed
-- pool policy and applied the larger value only at promotion time. Refuse an
-- in-place upgrade if any retained immutable job or winner carries that old
-- mismatch: silently rewriting journal-derived facts would be unsafe, while
-- accepting them would make a later confirmation-depth regression ambiguous.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM public.jobs AS j
          CROSS JOIN (
              VALUES
                  ('wcash'::TEXT, 'wcash_maturity_confirmations'::TEXT),
                  ('zcash'::TEXT, 'zcash_maturity_confirmations'::TEXT)
          ) AS required(chain, descriptor_field)
          LEFT JOIN public.chain_policies AS policy
            ON policy.deployment_id = j.deployment_id
           AND policy.chain = required.chain
         WHERE policy.required_confirmations IS NULL
            OR CASE
                   WHEN (j.descriptor ->> required.descriptor_field) ~ '^[0-9]+$'
                   THEN (j.descriptor ->> required.descriptor_field)::NUMERIC
                   ELSE NULL
               END IS DISTINCT FROM policy.required_confirmations::NUMERIC
    ) THEN
        RAISE EXCEPTION
            'retained job maturity requirements do not match sealed chain policy'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM public.winners AS winner
          LEFT JOIN public.chain_policies AS policy
            ON policy.deployment_id = winner.deployment_id
           AND policy.chain = winner.chain
         WHERE policy.required_confirmations IS NULL
            OR winner.maturity_confirmations <> policy.required_confirmations
    ) THEN
        RAISE EXCEPTION
            'retained winner maturity requirements do not match sealed chain policy'
            USING ERRCODE = '23514';
    END IF;
END;
$$;
