-- Security-critical runtime state introduced after the initial portal and
-- accounting schema. Every time decision below is evaluated by PostgreSQL.

CREATE INDEX portal_sessions_expiry_cleanup_idx
    ON portal_sessions(deployment_id, expires_at, idle_expires_at, token_digest);

CREATE INDEX payout_destinations_due_pending_idx
    ON payout_destinations(deployment_id, chain, active_after, account_id, id)
    WHERE state = 'pending';

-- Exactly one isolated payout worker may own a deployment. The stored expiry
-- makes heartbeat and takeover decisions atomic even across process restarts.
CREATE TABLE payout_worker_leases (
    deployment_id UUID PRIMARY KEY REFERENCES deployments(id) ON DELETE RESTRICT,
    worker_instance UUID NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    ready_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    lease_ttl_seconds INTEGER NOT NULL CHECK (lease_ttl_seconds BETWEEN 1 AND 3600),
    CHECK (heartbeat_at >= acquired_at),
    CHECK (ready_at IS NULL OR ready_at >= acquired_at),
    CHECK (expires_at > heartbeat_at),
    CHECK (expires_at <= heartbeat_at + INTERVAL '1 hour')
);

CREATE INDEX payout_worker_leases_live_idx
    ON payout_worker_leases(deployment_id, expires_at, worker_instance);
