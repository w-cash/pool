-- Nonce prefixes are part of the backend journal's global mining namespace.
-- A deployment UUID is an accounting boundary, not a uniqueness boundary, so
-- the original deployment-scoped cursors cannot safely fence rolling deploys.

CREATE TABLE nonce_namespace_fences (
    backend_instance UUID NOT NULL,
    journal_stream UUID NOT NULL,
    profile SMALLINT NOT NULL CHECK (profile IN (4, 8)),
    namespace SMALLINT NOT NULL CHECK (namespace BETWEEN 1 AND 127),
    next_counter BIGINT NOT NULL CHECK (next_counter >= 0),
    lease_generation BIGINT NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    holder_id UUID,
    holder_deployment_id UUID REFERENCES deployments(id) ON DELETE RESTRICT,
    lease_acquired_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    last_released_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (backend_instance, journal_stream, profile, namespace),
    CHECK (backend_instance <> journal_stream),
    CHECK (
        (holder_id IS NULL
         AND holder_deployment_id IS NULL
         AND lease_acquired_at IS NULL
         AND lease_expires_at IS NULL)
        OR
        (holder_id IS NOT NULL
         AND holder_deployment_id IS NOT NULL
         AND lease_acquired_at IS NOT NULL
         AND lease_expires_at IS NOT NULL
         AND lease_expires_at > lease_acquired_at)
    ),
    CHECK (holder_id IS NULL OR lease_generation > 0)
);

-- Preserve the highest durable cursor from pre-fencing deployments. Old
-- deployment-scoped reservations may have overlapped, but no range allocated
-- after this migration can move below their highest committed endpoint.
INSERT INTO nonce_namespace_fences
       (backend_instance, journal_stream, profile, namespace, next_counter)
SELECT d.backend_instance, d.journal_stream, c.profile, c.namespace,
       MAX(GREATEST(c.next_counter, COALESCE(r.maximum_range_end, 0)))
  FROM nonce_cursors c
  JOIN deployments d ON d.id = c.deployment_id
  LEFT JOIN (
      SELECT deployment_id, profile, namespace, MAX(range_end) AS maximum_range_end
        FROM nonce_range_leases
       GROUP BY deployment_id, profile, namespace
  ) r ON (r.deployment_id, r.profile, r.namespace) =
         (c.deployment_id, c.profile, c.namespace)
 GROUP BY d.backend_instance, d.journal_stream, c.profile, c.namespace;

CREATE TABLE nonce_namespace_claim_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    backend_instance UUID NOT NULL,
    journal_stream UUID NOT NULL,
    profile SMALLINT NOT NULL,
    namespace SMALLINT NOT NULL,
    deployment_id UUID NOT NULL REFERENCES deployments(id) ON DELETE RESTRICT,
    holder_id UUID NOT NULL,
    lease_generation BIGINT NOT NULL CHECK (lease_generation > 0),
    event_kind TEXT NOT NULL CHECK (event_kind IN ('claimed', 'renewed', 'released')),
    lease_expires_at TIMESTAMPTZ,
    next_counter BIGINT NOT NULL CHECK (next_counter >= 0),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (backend_instance, journal_stream, profile, namespace)
        REFERENCES nonce_namespace_fences
            (backend_instance, journal_stream, profile, namespace)
        ON DELETE RESTRICT,
    CHECK (
        (event_kind = 'released' AND lease_expires_at IS NULL)
        OR (event_kind IN ('claimed', 'renewed') AND lease_expires_at IS NOT NULL)
    )
);
CREATE INDEX nonce_namespace_claim_events_namespace_idx
    ON nonce_namespace_claim_events
       (backend_instance, journal_stream, profile, namespace, event_id);

CREATE TABLE nonce_global_range_reservations (
    backend_instance UUID NOT NULL,
    journal_stream UUID NOT NULL,
    profile SMALLINT NOT NULL,
    namespace SMALLINT NOT NULL,
    id UUID NOT NULL,
    deployment_id UUID NOT NULL REFERENCES deployments(id) ON DELETE RESTRICT,
    holder_id UUID NOT NULL,
    lease_generation BIGINT NOT NULL CHECK (lease_generation > 0),
    range_start BIGINT NOT NULL CHECK (range_start >= 0),
    range_end BIGINT NOT NULL CHECK (range_end > range_start),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (backend_instance, journal_stream, profile, namespace, id),
    FOREIGN KEY (backend_instance, journal_stream, profile, namespace)
        REFERENCES nonce_namespace_fences
            (backend_instance, journal_stream, profile, namespace)
        ON DELETE RESTRICT,
    UNIQUE (backend_instance, journal_stream, profile, namespace, range_start),
    UNIQUE (backend_instance, journal_stream, profile, namespace, range_end)
);

CREATE OR REPLACE FUNCTION preserve_nonce_namespace_fence() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'nonce namespace fence cannot be deleted';
    END IF;
    IF (NEW.backend_instance, NEW.journal_stream, NEW.profile, NEW.namespace) IS DISTINCT FROM
       (OLD.backend_instance, OLD.journal_stream, OLD.profile, OLD.namespace) THEN
        RAISE EXCEPTION 'nonce namespace identity is immutable';
    END IF;
    IF NEW.next_counter < OLD.next_counter THEN
        RAISE EXCEPTION 'nonce namespace cursor cannot rewind';
    END IF;
    IF NEW.lease_generation < OLD.lease_generation THEN
        RAISE EXCEPTION 'nonce namespace lease generation cannot rewind';
    END IF;
    IF NEW.next_counter > OLD.next_counter AND NOT EXISTS (
        SELECT 1
          FROM nonce_global_range_reservations reservation
         WHERE reservation.backend_instance = OLD.backend_instance
           AND reservation.journal_stream = OLD.journal_stream
           AND reservation.profile = OLD.profile
           AND reservation.namespace = OLD.namespace
           AND reservation.range_start = OLD.next_counter
           AND reservation.range_end = NEW.next_counter
    ) THEN
        RAISE EXCEPTION 'nonce namespace cursor advance lacks an exact reservation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER nonce_namespace_fence_monotonic
    BEFORE UPDATE OR DELETE ON nonce_namespace_fences
    FOR EACH ROW EXECUTE FUNCTION preserve_nonce_namespace_fence();

CREATE OR REPLACE FUNCTION validate_nonce_global_reservation() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    fence nonce_namespace_fences%ROWTYPE;
    capacity BIGINT;
BEGIN
    SELECT * INTO STRICT fence
      FROM nonce_namespace_fences
     WHERE backend_instance = NEW.backend_instance
       AND journal_stream = NEW.journal_stream
       AND profile = NEW.profile
       AND namespace = NEW.namespace;
    IF fence.holder_id IS DISTINCT FROM NEW.holder_id
       OR fence.holder_deployment_id IS DISTINCT FROM NEW.deployment_id
       OR fence.lease_generation <> NEW.lease_generation
       OR fence.lease_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'nonce reservation does not own an active namespace lease';
    END IF;
    IF NEW.range_start <> fence.next_counter THEN
        RAISE EXCEPTION 'nonce reservation is not contiguous with the global cursor';
    END IF;
    capacity := CASE NEW.profile WHEN 4 THEN 16777216 ELSE 72057594037927936 END;
    IF NEW.range_end > capacity THEN
        RAISE EXCEPTION 'nonce reservation exceeds profile capacity';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER nonce_global_range_reservation_valid
    BEFORE INSERT ON nonce_global_range_reservations
    FOR EACH ROW EXECUTE FUNCTION validate_nonce_global_reservation();

CREATE TRIGGER nonce_namespace_claim_events_append_only
    BEFORE UPDATE OR DELETE ON nonce_namespace_claim_events
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();
CREATE TRIGGER nonce_global_range_reservations_append_only
    BEFORE UPDATE OR DELETE ON nonce_global_range_reservations
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();
