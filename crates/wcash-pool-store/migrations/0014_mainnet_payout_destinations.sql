-- Enable the already-configured Mainnet deployment in the same guarded payout
-- destination lifecycle used by Testnet and explicit Regtest. Address parsing,
-- deployment matching, reauthentication, fixed holds, and role separation remain
-- enforced; this migration only removes the stale Testnet-only network gate.

CREATE OR REPLACE FUNCTION public.configure_payout_destination_v2(
    p_deployment_id UUID,
    p_account_id UUID,
    p_chain TEXT,
    p_network TEXT,
    p_address TEXT,
    p_receiver_kind TEXT,
    p_address_digest BYTEA,
    p_payout_threshold_zat BIGINT,
    p_automatic BOOLEAN,
    p_hold_secs BIGINT
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
        OR p_network NOT IN ('testnet', 'mainnet', 'regtest')
        OR p_address IS NULL
        OR length(p_address) NOT BETWEEN 8 AND 512
        OR p_receiver_kind NOT IN ('transparent', 'ironwood')
        OR p_address_digest IS NULL
        OR octet_length(p_address_digest) <> 32
        OR p_address_digest = decode(repeat('00', 32), 'hex')
        OR p_payout_threshold_zat NOT BETWEEN 1 AND 2100000000000000
        OR p_automatic IS NULL
        OR p_hold_secs IS NULL
        OR p_hold_secs < (CASE WHEN p_network = 'regtest' THEN 1 ELSE 60 END)
        OR p_hold_secs > 604800
    THEN
        RAISE EXCEPTION 'invalid payout destination request' USING ERRCODE = '22023';
    END IF;

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
        p_receiver_kind,'portal-authoritative-address-v2',v_database_now,
        v_database_now + p_hold_secs * INTERVAL '1 second',p_address_digest,
        p_payout_threshold_zat,p_automatic,'pending',v_database_now,v_revision
    );

    INSERT INTO public.payout_change_events (
        deployment_id,id,account_id,chain,address_digest,payout_threshold_zat,
        automatic,requested_at,active_after,revision
    ) VALUES (
        p_deployment_id,gen_random_uuid(),p_account_id,p_chain,p_address_digest,
        p_payout_threshold_zat,p_automatic,v_database_now,
        v_database_now + p_hold_secs * INTERVAL '1 second',v_revision
    );

    RETURN v_destination_id;
END;
$$;

REVOKE ALL ON FUNCTION public.configure_payout_destination_v2(
    UUID,UUID,TEXT,TEXT,TEXT,TEXT,BYTEA,BIGINT,BOOLEAN,BIGINT
) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.configure_payout_destination_v1(
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
        OR p_network NOT IN ('testnet', 'mainnet', 'regtest')
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
        v_database_now + CASE WHEN p_network = 'regtest' THEN INTERVAL '1 second' ELSE INTERVAL '48 hours' END,p_address_digest,
        p_payout_threshold_zat,p_automatic,'pending',v_database_now,v_revision
    );

    INSERT INTO public.payout_change_events (
        deployment_id,id,account_id,chain,address_digest,payout_threshold_zat,
        automatic,requested_at,active_after,revision
    ) VALUES (
        p_deployment_id,gen_random_uuid(),p_account_id,p_chain,p_address_digest,
        p_payout_threshold_zat,p_automatic,v_database_now,
        v_database_now + CASE WHEN p_network = 'regtest' THEN INTERVAL '1 second' ELSE INTERVAL '48 hours' END,v_revision
    );

    RETURN v_destination_id;
END;
$$;

REVOKE ALL ON FUNCTION public.configure_payout_destination_v1(
    UUID,UUID,TEXT,TEXT,TEXT,TEXT,BYTEA,BIGINT,BOOLEAN
) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.activate_due_payout_destinations_v1(
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
    IF NOT FOUND OR v_deployment_network NOT IN ('testnet', 'mainnet', 'regtest') THEN
        RAISE EXCEPTION 'supported deployment not found' USING ERRCODE = 'P0002';
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
