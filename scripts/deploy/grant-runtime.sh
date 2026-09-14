#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

die() {
    printf 'grant-runtime: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 5 ]] \
    || die "usage: grant-runtime.sh <migrator-url-file> <migrator-role> <public-role> <projector-role> <payout-role>"
url_file=$1
migrator_role=$2
public_role=$3
projector_role=$4
payout_role=$5
[[ $url_file == /* && -f $url_file && ! -L $url_file ]] || die "migrator URL is unavailable"
command -v python3 >/dev/null 2>&1 || die "python3 is unavailable"
for role in "$migrator_role" "$public_role" "$projector_role" "$payout_role"; do
    [[ $role =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || die "database role is unsafe"
done
[[ $migrator_role != "$public_role" && $migrator_role != "$projector_role" \
    && $migrator_role != "$payout_role" \
    && $public_role != "$projector_role" && $public_role != "$payout_role" \
    && $projector_role != "$payout_role" ]] \
    || die "migrator, public, projector, and payout roles must be distinct"

python3 "$script_dir/psql-with-url-file.py" "$url_file" \
    --no-psqlrc --set=ON_ERROR_STOP=1 \
    --set="migrator_role=$migrator_role" --set="public_role=$public_role" \
    --set="projector_role=$projector_role" \
    --set="payout_role=$payout_role" <<'SQL'
GRANT USAGE ON SCHEMA public TO :"public_role", :"projector_role", :"payout_role";

-- Remove broad grants left by an older deployment before installing the
-- reviewed least-authority matrix.
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
    REVOKE ALL PRIVILEGES ON TABLES
    FROM :"public_role", :"projector_role", :"payout_role";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
    REVOKE ALL PRIVILEGES ON TABLES
    FROM :"public_role", :"projector_role", :"payout_role";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
    REVOKE ALL PRIVILEGES ON SEQUENCES
    FROM :"public_role", :"projector_role", :"payout_role";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
    REVOKE ALL PRIVILEGES ON SEQUENCES
    FROM :"public_role", :"projector_role", :"payout_role";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM :"public_role", :"projector_role", :"payout_role";
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM :"public_role", :"projector_role", :"payout_role";
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON FUNCTION public.configure_payout_destination_v1(
    UUID,UUID,TEXT,TEXT,TEXT,TEXT,BYTEA,BIGINT,BOOLEAN
) FROM :"public_role", :"projector_role", :"payout_role";
REVOKE ALL ON FUNCTION public.configure_payout_destination_v2(
    UUID,UUID,TEXT,TEXT,TEXT,TEXT,BYTEA,BIGINT,BOOLEAN,BIGINT
) FROM :"public_role", :"projector_role", :"payout_role";
REVOKE ALL ON FUNCTION public.ensure_projected_worker_v1(UUID,UUID,UUID,TEXT)
FROM :"public_role", :"projector_role", :"payout_role";
REVOKE ALL ON FUNCTION public.activate_due_payout_destinations_v1(UUID,TEXT)
FROM :"public_role", :"projector_role", :"payout_role";
REVOKE ALL ON FUNCTION public.freeze_chain_payouts_v1(UUID,TEXT,BIGINT,TEXT)
FROM :"public_role", :"projector_role", :"payout_role";
REVOKE ALL ON FUNCTION public.lock_backend_projection_v1(UUID)
FROM :"public_role", :"projector_role", :"payout_role";
REVOKE ALL ON FUNCTION public.lock_chain_safety_v1(UUID,TEXT)
FROM :"public_role", :"projector_role", :"payout_role";
REVOKE ALL ON FUNCTION public.advance_confirmed_payout_watch_cursor_v1(
    UUID,TEXT,BIGINT,UUID,UUID
) FROM :"public_role", :"projector_role", :"payout_role";

GRANT SELECT ON TABLE
    deployments,
    backend_cursors,
    backend_events,
    chain_policies,
    chain_safety_state,
    accounts,
    workers,
    mining_tokens,
    portal_sessions,
    payout_destinations,
    payout_change_events,
    nonce_cursors,
    nonce_range_leases,
    nonce_namespace_fences,
    nonce_namespace_claim_events,
    nonce_global_range_reservations,
    jobs,
    shares,
    winners,
    winner_allocations,
    ledger_transactions,
    ledger_entries,
    wallet_reconciliations,
    payout_batches,
    payout_items,
    payout_reorg_events,
    payout_worker_leases
TO :"public_role";
GRANT INSERT (deployment_id, id, login, password_verifier, created_at)
ON TABLE accounts TO :"public_role";
GRANT INSERT (deployment_id, id, account_id, label, canonical_login, created_at)
ON TABLE workers TO :"public_role";
GRANT INSERT (deployment_id, id, worker_id, verifier, created_at)
ON TABLE mining_tokens TO :"public_role";
GRANT INSERT (
    deployment_id,
    token_digest,
    csrf_digest,
    account_id,
    security_version,
    authenticated_at,
    second_factor_at,
    expires_at,
    idle_expires_at
) ON TABLE portal_sessions TO :"public_role";
GRANT UPDATE (
    failed_login_attempts,
    locked_until,
    totp_secret_sealed,
    totp_pending_sealed,
    totp_pending_expires_at,
    security_version
) ON TABLE accounts TO :"public_role";
GRANT UPDATE (enabled, revoked_at) ON TABLE workers TO :"public_role";
GRANT UPDATE (revoked_at) ON TABLE mining_tokens TO :"public_role";
GRANT UPDATE (idle_expires_at) ON TABLE portal_sessions TO :"public_role";
GRANT INSERT, UPDATE ON TABLE
    nonce_cursors,
    nonce_range_leases,
    nonce_namespace_fences
TO :"public_role";
GRANT SELECT, INSERT ON TABLE
    nonce_namespace_claim_events,
    nonce_global_range_reservations
TO :"public_role";
GRANT DELETE ON TABLE portal_sessions TO :"public_role";

GRANT EXECUTE ON FUNCTION public.configure_payout_destination_v1(
    UUID,UUID,TEXT,TEXT,TEXT,TEXT,BYTEA,BIGINT,BOOLEAN
) TO :"public_role";
GRANT EXECUTE ON FUNCTION public.configure_payout_destination_v2(
    UUID,UUID,TEXT,TEXT,TEXT,TEXT,BYTEA,BIGINT,BOOLEAN,BIGINT
) TO :"public_role";

-- Only this no-listener role can advance Wolf's journal projection and the
-- derived monetary ledger. It cannot create portal credentials or payouts.
GRANT SELECT ON TABLE
    deployments,
    backend_cursors,
    backend_events,
    chain_policies,
    chain_safety_state,
    jobs,
    shares,
    winners,
    winner_proofs,
    winner_allocations,
    ledger_transactions,
    ledger_entries,
    payout_batches
TO :"projector_role";
GRANT INSERT ON TABLE
    backend_events,
    jobs,
    shares,
    winners,
    winner_proofs,
    winner_allocations,
    ledger_transactions,
    ledger_entries
TO :"projector_role";
GRANT UPDATE (last_event_seq, updated_at) ON TABLE backend_cursors TO :"projector_role";
GRANT UPDATE (state, active_observation_event_seq, active_maturity_event_seq, active_proof_share_id)
ON TABLE winners TO :"projector_role";
GRANT UPDATE (state) ON TABLE winner_proofs TO :"projector_role";
GRANT UPDATE (sealed_at, sealed_entry_count)
ON TABLE ledger_transactions TO :"projector_role";
GRANT EXECUTE ON FUNCTION public.ensure_projected_worker_v1(UUID,UUID,UUID,TEXT)
TO :"projector_role";
GRANT EXECUTE ON FUNCTION public.freeze_chain_payouts_v1(UUID,TEXT,BIGINT,TEXT)
TO :"projector_role";
GRANT EXECUTE ON FUNCTION public.lock_chain_safety_v1(UUID,TEXT)
TO :"projector_role";

GRANT SELECT ON TABLE
    deployments,
    backend_cursors,
    chain_policies,
    chain_safety_state,
    payout_destinations,
    ledger_transactions,
    ledger_entries,
    wallet_reconciliations,
    payout_batches,
    payout_items,
    payout_reorg_events,
    payout_watch_cursors,
    payout_worker_leases
TO :"payout_role";
GRANT SELECT (deployment_id, event_seq, payload_sha256)
ON TABLE backend_events TO :"payout_role";
GRANT INSERT ON TABLE
    wallet_reconciliations,
    ledger_transactions,
    ledger_entries,
    payout_batches,
    payout_items,
    payout_reorg_events,
    payout_worker_leases
TO :"payout_role";
GRANT UPDATE (sealed_at, sealed_entry_count)
ON TABLE ledger_transactions TO :"payout_role";
GRANT UPDATE (
    state,
    reconciliation_id,
    ledger_root,
    ledger_sequence_cutoff,
    unsigned_digest,
    transaction_id,
    signed_transaction,
    network_fee_zat,
    confirmation_block_hash,
    confirmation_height,
    confirmation_count,
    updated_at
) ON TABLE payout_batches TO :"payout_role";
GRANT UPDATE (
    worker_instance,
    acquired_at,
    heartbeat_at,
    ready_at,
    expires_at,
    lease_ttl_seconds
) ON TABLE payout_worker_leases TO :"payout_role";
GRANT DELETE ON TABLE payout_worker_leases TO :"payout_role";
GRANT EXECUTE ON FUNCTION public.activate_due_payout_destinations_v1(UUID,TEXT)
TO :"payout_role";
GRANT EXECUTE ON FUNCTION public.freeze_chain_payouts_v1(UUID,TEXT,BIGINT,TEXT)
TO :"payout_role";
GRANT EXECUTE ON FUNCTION public.lock_backend_projection_v1(UUID)
TO :"payout_role";
GRANT EXECUTE ON FUNCTION public.lock_chain_safety_v1(UUID,TEXT)
TO :"payout_role";
GRANT EXECUTE ON FUNCTION public.advance_confirmed_payout_watch_cursor_v1(
    UUID,TEXT,BIGINT,UUID,UUID
) TO :"payout_role";

GRANT USAGE, SELECT ON SEQUENCE
    nonce_namespace_claim_events_event_id_seq
TO :"public_role";
GRANT USAGE, SELECT ON SEQUENCE
    winners_portal_sequence_seq,
    ledger_transactions_ledger_sequence_seq
TO :"projector_role";
GRANT USAGE, SELECT ON SEQUENCE
    ledger_transactions_ledger_sequence_seq,
    payout_batches_portal_sequence_seq
TO :"payout_role";
SQL
