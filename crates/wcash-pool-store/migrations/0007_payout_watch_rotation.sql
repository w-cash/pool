-- Confirmed payouts remain reorganization-sensitive indefinitely. Persist one
-- independent cursor per deployment and chain so a bounded observer rotates
-- through the complete confirmed history instead of permanently polling only
-- the newest rows.

CREATE TABLE payout_watch_cursors (
    deployment_id UUID NOT NULL,
    chain TEXT NOT NULL CHECK (chain IN ('wcash', 'zcash')),
    last_confirmed_batch_id UUID,
    generation BIGINT NOT NULL DEFAULT 0 CHECK (generation >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (deployment_id, chain),
    FOREIGN KEY (deployment_id, chain)
        REFERENCES chain_policies(deployment_id, chain) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, last_confirmed_batch_id)
        REFERENCES payout_batches(deployment_id, id) ON DELETE RESTRICT
);

INSERT INTO payout_watch_cursors (deployment_id, chain)
SELECT deployment_id, chain FROM chain_policies
ON CONFLICT (deployment_id, chain) DO NOTHING;

-- Only the isolated payout worker may acknowledge a page, and only with an
-- exact compare-and-swap against the cursor it read. A stale or concurrent
-- observer cannot rewind or skip the durable rotation point.
CREATE FUNCTION public.advance_confirmed_payout_watch_cursor_v1(
    p_deployment_id UUID,
    p_chain TEXT,
    p_expected_generation BIGINT,
    p_expected_before UUID,
    p_checked_through UUID
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF p_deployment_id IS NULL
        OR p_deployment_id = '00000000-0000-0000-0000-000000000000'::UUID
        OR p_chain NOT IN ('wcash', 'zcash')
        OR p_expected_generation IS NULL
        OR p_expected_generation < 0
        OR p_expected_before = '00000000-0000-0000-0000-000000000000'::UUID
        OR p_checked_through IS NULL
        OR p_checked_through = '00000000-0000-0000-0000-000000000000'::UUID
    THEN
        RAISE EXCEPTION 'invalid confirmed payout watch cursor request'
            USING ERRCODE = '22023';
    END IF;

    PERFORM 1
      FROM public.payout_batches
     WHERE deployment_id = p_deployment_id
       AND id = p_checked_through
       AND chain = p_chain
       AND state = 'confirmed';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'confirmed payout watch endpoint not found'
            USING ERRCODE = 'P0002';
    END IF;

    UPDATE public.payout_watch_cursors
       SET last_confirmed_batch_id = p_checked_through,
           generation = generation + 1,
           updated_at = clock_timestamp()
     WHERE deployment_id = p_deployment_id
       AND chain = p_chain
       AND generation = p_expected_generation
       AND last_confirmed_batch_id IS NOT DISTINCT FROM p_expected_before;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'stale confirmed payout watch cursor'
            USING ERRCODE = '40001';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.advance_confirmed_payout_watch_cursor_v1(
    UUID,TEXT,BIGINT,UUID,UUID
) FROM PUBLIC;
