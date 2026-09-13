-- The Internet-facing role has no direct authority over payout destinations
-- or accounting projection. These narrowly scoped, migration-owned routines
-- retain database-enforced invariants when called through an untrusted role.

CREATE FUNCTION public.configure_payout_destination_v1(
    p_deployment_id UUID,
    p_account_id UUID,
    p_chain TEXT,
    p_network TEXT,
    p_address TEXT,
    p_receiver_kind TEXT,
    p_address_digest BYTEA,
    p_payout_threshold_zat BIGINT,
    p_automatic BOOLEAN
) RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_database_now TIMESTAMPTZ;
    v_destination_id UUID;
    v_deployment_network TEXT;
    v_revision BIGINT;
BEGIN
    IF p_deployment_id IS NULL
        OR p_deployment_id = '00000000-0000-0000-0000-000000000000'::UUID
        OR p_account_id IS NULL
        OR p_account_id = '00000000-0000-0000-0000-000000000000'::UUID
        OR p_chain NOT IN ('wcash', 'zcash')
        OR p_network <> 'testnet'
        OR p_address IS NULL
        OR length(p_address) NOT BETWEEN 8 AND 512
        OR p_receiver_kind NOT IN ('transparent', 'ironwood')
        OR p_address_digest IS NULL
        OR octet_length(p_address_digest) <> 32
        OR p_address_digest = decode(repeat('00', 32), 'hex')
        OR p_payout_threshold_zat NOT BETWEEN 1 AND 2100000000000000
        OR p_automatic IS NULL
    THEN
        RAISE EXCEPTION 'invalid payout destination request' USING ERRCODE = '22023';
    END IF;

    -- This key is byte-for-byte identical to payout batch creation. A caller
    -- cannot race a new destination around batch selection.
    PERFORM pg_advisory_xact_lock(
        hashtextextended('zecwec:' || p_deployment_id::TEXT || ':' || p_chain, 0)
    );

    SELECT network INTO v_deployment_network
      FROM public.deployments
     WHERE id = p_deployment_id;
    IF NOT FOUND OR v_deployment_network <> p_network THEN
        RAISE EXCEPTION 'deployment network mismatch' USING ERRCODE = '22023';
    END IF;

    PERFORM 1
      FROM public.accounts
     WHERE deployment_id = p_deployment_id AND id = p_account_id AND enabled
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'enabled payout account not found' USING ERRCODE = 'P0002';
    END IF;

    v_database_now := clock_timestamp();
    SELECT COALESCE(MAX(revision), 0) + 1 INTO v_revision
      FROM public.payout_change_events
     WHERE deployment_id = p_deployment_id
       AND account_id = p_account_id
       AND chain = p_chain;

    -- Replacing an unexpired request restarts the full hold. Active rows are
    -- never changed here; only the isolated payout role may promote a due row.
    UPDATE public.payout_destinations
       SET state = 'disabled', disabled_at = v_database_now
     WHERE deployment_id = p_deployment_id
       AND account_id = p_account_id
       AND chain = p_chain
       AND state = 'pending';

    v_destination_id := gen_random_uuid();
    INSERT INTO public.payout_destinations (
        deployment_id,id,account_id,chain,network,address,receiver_kind,
        validated_by,validated_at,active_after,address_digest,
        payout_threshold_zat,automatic,state,created_at,revision
    ) VALUES (
        p_deployment_id,v_destination_id,p_account_id,p_chain,p_network,p_address,
        p_receiver_kind,'portal-authoritative-address-v1',v_database_now,
        v_database_now + INTERVAL '48 hours',p_address_digest,
        p_payout_threshold_zat,p_automatic,'pending',v_database_now,v_revision
    );

    INSERT INTO public.payout_change_events (
        deployment_id,id,account_id,chain,address_digest,payout_threshold_zat,
        automatic,requested_at,active_after,revision
    ) VALUES (
        p_deployment_id,gen_random_uuid(),p_account_id,p_chain,p_address_digest,
        p_payout_threshold_zat,p_automatic,v_database_now,
        v_database_now + INTERVAL '48 hours',v_revision
    );

    RETURN v_destination_id;
END;
$$;

REVOKE ALL ON FUNCTION public.configure_payout_destination_v1(
    UUID,UUID,TEXT,TEXT,TEXT,TEXT,BYTEA,BIGINT,BOOLEAN
) FROM PUBLIC;

-- Only the isolated payout role may call this routine. Even that credential
-- cannot alter destination facts or promote a hold before the database clock
-- reaches its fixed activation time.
CREATE FUNCTION public.activate_due_payout_destinations_v1(
    p_deployment_id UUID,
    p_chain TEXT
) RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_database_now TIMESTAMPTZ;
    v_deployment_network TEXT;
    v_pending RECORD;
    v_promoted BIGINT := 0;
BEGIN
    IF p_deployment_id IS NULL
        OR p_deployment_id = '00000000-0000-0000-0000-000000000000'::UUID
        OR p_chain NOT IN ('wcash', 'zcash')
    THEN
        RAISE EXCEPTION 'invalid payout activation request' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended('zecwec:' || p_deployment_id::TEXT || ':' || p_chain, 0)
    );
    SELECT network INTO v_deployment_network
      FROM public.deployments
     WHERE id = p_deployment_id;
    IF NOT FOUND OR v_deployment_network <> 'testnet' THEN
        RAISE EXCEPTION 'testnet deployment not found' USING ERRCODE = 'P0002';
    END IF;

    v_database_now := clock_timestamp();
    FOR v_pending IN
        SELECT id, account_id
          FROM public.payout_destinations
         WHERE deployment_id = p_deployment_id
           AND chain = p_chain
           AND state = 'pending'
           AND active_after <= v_database_now
         ORDER BY account_id,id
         FOR UPDATE
    LOOP
        UPDATE public.payout_destinations
           SET state = 'disabled', disabled_at = v_database_now
         WHERE deployment_id = p_deployment_id
           AND account_id = v_pending.account_id
           AND chain = p_chain
           AND state = 'active';
        UPDATE public.payout_destinations
           SET state = 'active'
         WHERE deployment_id = p_deployment_id
           AND id = v_pending.id
           AND state = 'pending';
        IF NOT FOUND THEN
            RAISE EXCEPTION 'payout destination activation conflict' USING ERRCODE = '40001';
        END IF;
        v_promoted := v_promoted + 1;
    END LOOP;
    RETURN v_promoted;
END;
$$;

REVOKE ALL ON FUNCTION public.activate_due_payout_destinations_v1(UUID,TEXT)
FROM PUBLIC;

-- Freezing is monotonic. Projector and payout credentials can fail closed but
-- cannot clear a prior safety event or rewrite its first recorded cause.
CREATE FUNCTION public.freeze_chain_payouts_v1(
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
            'matured_winner_reorg'
        )
        OR (p_reason = 'matured_winner_reorg') <> (p_backend_event_seq IS NOT NULL)
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

-- Row locks that serialize payout accounting with the projector require
-- UPDATE privilege in PostgreSQL even though the payout worker never updates
-- these rows. Keep that privilege inside migration-owned routines.
CREATE FUNCTION public.lock_backend_projection_v1(
    p_deployment_id UUID
) RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_last_event_seq BIGINT;
BEGIN
    SELECT last_event_seq INTO v_last_event_seq
      FROM public.backend_cursors
     WHERE deployment_id = p_deployment_id
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'backend cursor not found' USING ERRCODE = 'P0002';
    END IF;
    RETURN v_last_event_seq;
END;
$$;

REVOKE ALL ON FUNCTION public.lock_backend_projection_v1(UUID) FROM PUBLIC;

CREATE FUNCTION public.lock_chain_safety_v1(
    p_deployment_id UUID,
    p_chain TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_frozen BOOLEAN;
BEGIN
    IF p_chain NOT IN ('wcash', 'zcash') THEN
        RAISE EXCEPTION 'invalid chain safety lock request' USING ERRCODE = '22023';
    END IF;
    SELECT payouts_frozen INTO v_frozen
      FROM public.chain_safety_state
     WHERE deployment_id = p_deployment_id AND chain = p_chain
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'chain safety state not found' USING ERRCODE = 'P0002';
    END IF;
    RETURN v_frozen;
END;
$$;

REVOKE ALL ON FUNCTION public.lock_chain_safety_v1(UUID,TEXT) FROM PUBLIC;

-- Historical replay may refer to an identity created before this portal
-- existed. The projector can create only inert, credential-less attribution
-- rows and cannot mutate portal accounts or workers directly.
CREATE FUNCTION public.ensure_projected_worker_v1(
    p_deployment_id UUID,
    p_account_id UUID,
    p_worker_id UUID,
    p_canonical_login TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_account_login TEXT;
    v_worker_label TEXT;
BEGIN
    IF p_deployment_id IS NULL
        OR p_deployment_id = '00000000-0000-0000-0000-000000000000'::UUID
        OR p_account_id IS NULL
        OR p_account_id = '00000000-0000-0000-0000-000000000000'::UUID
        OR p_worker_id IS NULL
        OR p_worker_id = '00000000-0000-0000-0000-000000000000'::UUID
        OR p_canonical_login IS NULL
        OR p_canonical_login !~ '^[a-z0-9_-]{1,64}\.[a-z0-9_-]{1,63}$'
    THEN
        RAISE EXCEPTION 'invalid projected worker identity' USING ERRCODE = '22023';
    END IF;

    v_account_login := 'imported_' || substring(replace(p_account_id::TEXT, '-', '') FROM 1 FOR 16);
    v_worker_label := 'legacy_' || substring(replace(p_worker_id::TEXT, '-', '') FROM 1 FOR 16);

    INSERT INTO public.accounts (deployment_id,id,login,enabled)
    VALUES (p_deployment_id,p_account_id,v_account_login,FALSE)
    ON CONFLICT (deployment_id,id) DO NOTHING;

    INSERT INTO public.workers (
        deployment_id,id,account_id,label,canonical_login,enabled,revoked_at
    ) VALUES (
        p_deployment_id,p_worker_id,p_account_id,v_worker_label,
        p_canonical_login,FALSE,clock_timestamp()
    )
    ON CONFLICT (deployment_id,id) DO NOTHING;

    PERFORM 1
      FROM public.workers
     WHERE deployment_id = p_deployment_id
       AND id = p_worker_id
       AND account_id = p_account_id
       AND canonical_login = p_canonical_login;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'projected worker attribution conflict' USING ERRCODE = '23505';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.ensure_projected_worker_v1(UUID,UUID,UUID,TEXT)
FROM PUBLIC;
