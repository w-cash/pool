//! Concrete miner-portal adapter over the deployment-fenced PostgreSQL store.

use std::sync::{Arc, RwLock};

use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;
use wcash_pool_portal::{
    mask_destination, AccountCredential, Asset, AuthenticatedSession, ChainNetwork,
    MinerBlockSummary, MinerPayoutSummary, NewSession, Page, PageRequest, PayoutPreferenceChange,
    PayoutSettingSummary, PoolDataSource, PoolOverview, PortalRepository, ProvisionedWorker,
    ReceiverKind as PortalReceiverKind, RepositoryError, RepositoryFuture, RewardSummary,
    ValidatedDestination, WorkerSummary,
};
use wcash_pool_protocol::JobDescriptor;

use crate::{
    postgres::{unix_i64, unix_u64},
    Chain, DeploymentNetwork, NewPortalSessionRecord, PostgresStore, StoreError,
};

const MINIMUM_REPLACEMENT_HOLD_SECS: u64 = 24 * 60 * 60;
const MAXIMUM_REPLACEMENT_HOLD_SECS: u64 = 72 * 60 * 60;
const MAXIMUM_MONEY_ZAT: u64 = 2_100_000_000_000_000;
const MAXIMUM_WORKERS_PER_ACCOUNT: i64 = 100;

impl PortalRepository for PostgresStore {
    fn readiness(&self) -> RepositoryFuture<'_, ()> {
        Box::pin(async move {
            let row = sqlx::query(
                "SELECT d.network,COUNT(p.chain)::BIGINT AS policy_count, \
                        COALESCE(BOOL_AND(p.fee_bps=0 AND p.required_confirmations>=100),FALSE) \
                            AS safe_policies \
                 FROM deployments d \
                 JOIN backend_cursors c ON c.deployment_id=d.id \
                 LEFT JOIN chain_policies p ON p.deployment_id=d.id \
                 WHERE d.id=$1 GROUP BY d.network",
            )
            .bind(self.identity.id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .ok_or(RepositoryError::Unavailable)?;
            let network = row
                .try_get::<String, _>("network")
                .map_err(|_| RepositoryError::InvalidState)?;
            let policy_count = row
                .try_get::<i64, _>("policy_count")
                .map_err(|_| RepositoryError::InvalidState)?;
            let safe_policies = row
                .try_get::<bool, _>("safe_policies")
                .map_err(|_| RepositoryError::InvalidState)?;
            if network == self.identity.network.as_str() && policy_count == 2 && safe_policies {
                Ok(())
            } else {
                Err(RepositoryError::InvalidState)
            }
        })
    }

    fn create_account<'a>(
        &'a self,
        id: Uuid,
        username: &'a str,
        password_hash: &'a str,
        now: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.create_portal_account(id, username, password_hash, now)
                .await
                .map_err(repository_error)
        })
    }

    fn account_by_username<'a>(
        &'a self,
        username: &'a str,
    ) -> RepositoryFuture<'a, Option<AccountCredential>> {
        Box::pin(async move {
            self.portal_account_by_login(username)
                .await
                .map(|account| {
                    account.map(|account| AccountCredential {
                        id: account.id,
                        username: account.login,
                        password_hash: account.password_verifier,
                        totp_secret: account.totp_secret_sealed,
                        totp_pending: account.totp_pending_sealed,
                        totp_pending_expires_at: account.totp_pending_expires_at,
                        locked_until: account.locked_until,
                        security_version: account.security_version,
                    })
                })
                .map_err(repository_error)
        })
    }

    fn record_failed_login(
        &self,
        account_id: Uuid,
        maximum_attempts: u32,
        locked_until: u64,
    ) -> RepositoryFuture<'_, ()> {
        Box::pin(async move {
            self.record_failed_portal_login(account_id, maximum_attempts, locked_until)
                .await
                .map_err(repository_error)
        })
    }

    fn clear_failed_login(&self, account_id: Uuid) -> RepositoryFuture<'_, ()> {
        Box::pin(async move {
            self.clear_failed_portal_login(account_id)
                .await
                .map_err(repository_error)
        })
    }

    fn create_session(&self, session: NewSession<'_>) -> RepositoryFuture<'_, ()> {
        let token_digest = *session.token_digest;
        let csrf_digest = *session.csrf_digest;
        let account_id = session.account_id;
        let security_version = session.security_version;
        let authenticated_at = session.authenticated_at;
        let second_factor_at = session.second_factor_at;
        let expires_at = session.expires_at;
        let idle_expires_at = session.idle_expires_at;
        Box::pin(async move {
            self.create_portal_session(NewPortalSessionRecord {
                token_digest: &token_digest,
                csrf_digest: &csrf_digest,
                account_id,
                security_version,
                authenticated_at,
                second_factor_at,
                expires_at,
                idle_expires_at,
            })
            .await
            .map_err(repository_error)
        })
    }

    fn authenticate_session<'a>(
        &'a self,
        token_digest: &'a [u8; 32],
        now: u64,
        new_idle_expiry: u64,
    ) -> RepositoryFuture<'a, Option<AuthenticatedSession>> {
        Box::pin(async move {
            self.authenticate_portal_session(token_digest, now, new_idle_expiry)
                .await
                .map(|session| {
                    session.map(|session| AuthenticatedSession {
                        account_id: session.account_id,
                        username: session.login,
                        csrf_digest: session.csrf_digest,
                        authenticated_at: session.authenticated_at,
                    })
                })
                .map_err(repository_error)
        })
    }

    fn delete_session<'a>(&'a self, token_digest: &'a [u8; 32]) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.delete_portal_session(token_digest)
                .await
                .map_err(repository_error)
        })
    }

    fn delete_account_sessions(&self, account_id: Uuid) -> RepositoryFuture<'_, ()> {
        Box::pin(async move {
            PostgresStore::delete_account_sessions(self, account_id)
                .await
                .map_err(repository_error)
        })
    }

    fn save_pending_totp<'a>(
        &'a self,
        account_id: Uuid,
        sealed_secret: &'a [u8],
        expires_at: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            PostgresStore::save_pending_totp(self, account_id, sealed_secret, expires_at)
                .await
                .map_err(repository_error)
        })
    }

    fn activate_pending_totp(&self, account_id: Uuid, now: u64) -> RepositoryFuture<'_, bool> {
        Box::pin(async move {
            PostgresStore::activate_pending_totp(self, account_id, now)
                .await
                .map_err(repository_error)
        })
    }

    fn provision_worker<'a>(
        &'a self,
        account_id: Uuid,
        account_login: &'a str,
        worker_label: &'a str,
        now: u64,
    ) -> RepositoryFuture<'a, ProvisionedWorker> {
        Box::pin(async move {
            let (worker_id, token) =
                provision_worker_at(self, account_id, account_login, worker_label, now)
                    .await
                    .map_err(repository_error)?;
            Ok(ProvisionedWorker {
                account_id,
                worker_id,
                canonical_login: format!("{account_login}.{worker_label}"),
                token: token.expose_secret().to_owned(),
            })
        })
    }

    fn list_workers<'a>(
        &'a self,
        account_id: Uuid,
        account_login: &'a str,
    ) -> RepositoryFuture<'a, Vec<WorkerSummary>> {
        Box::pin(async move { list_workers(self, account_id, account_login).await })
    }

    fn revoke_worker(
        &self,
        account_id: Uuid,
        worker_id: Uuid,
        now: u64,
    ) -> RepositoryFuture<'_, bool> {
        Box::pin(async move {
            revoke_worker_at(self, account_id, worker_id, now)
                .await
                .map_err(repository_error)
        })
    }

    fn configure_payout(
        &self,
        change: PayoutPreferenceChange<'_>,
    ) -> RepositoryFuture<'_, PayoutSettingSummary> {
        let change = OwnedPayoutPreference {
            account_id: change.account_id,
            asset: change.destination.asset(),
            network: change.destination.network(),
            canonical_address: change.destination.canonical_address().to_owned(),
            receiver_kind: change.destination.receiver_kind(),
            threshold_zat: change.threshold_zat,
            automatic: change.automatic,
            changed_at: change.changed_at,
            replacement_hold_secs: change.replacement_hold_secs,
            address_digest: *change.address_digest,
        };
        Box::pin(async move { configure_payout(self, change).await })
    }

    fn payout_settings(
        &self,
        account_id: Uuid,
        network: ChainNetwork,
        now: u64,
    ) -> RepositoryFuture<'_, Vec<PayoutSettingSummary>> {
        Box::pin(async move { payout_settings(self, account_id, network, now).await })
    }

    fn active_payout_destination(
        &self,
        account_id: Uuid,
        asset: Asset,
        network: ChainNetwork,
        now: u64,
    ) -> RepositoryFuture<'_, Option<ValidatedDestination>> {
        Box::pin(
            async move { active_payout_destination(self, account_id, asset, network, now).await },
        )
    }

    fn reward_history(
        &self,
        account_id: Uuid,
        page: PageRequest,
    ) -> RepositoryFuture<'_, Page<RewardSummary>> {
        Box::pin(async move { reward_history(self, account_id, page).await })
    }

    fn found_blocks(
        &self,
        account_id: Uuid,
        page: PageRequest,
    ) -> RepositoryFuture<'_, Page<MinerBlockSummary>> {
        Box::pin(async move { found_blocks(self, account_id, page).await })
    }

    fn payout_history(
        &self,
        account_id: Uuid,
        page: PageRequest,
    ) -> RepositoryFuture<'_, Page<MinerPayoutSummary>> {
        Box::pin(async move { payout_history(self, account_id, page).await })
    }
}

async fn provision_worker_at(
    store: &PostgresStore,
    account_id: Uuid,
    account_login: &str,
    worker_label: &str,
    now: u64,
) -> Result<(Uuid, crate::MiningToken), StoreError> {
    super::postgres::validate_component(account_login, 64)?;
    super::postgres::validate_component(worker_label, 63)?;
    let worker_id = Uuid::new_v4();
    let canonical_login = format!("{account_login}.{worker_label}");
    let token = crate::generate_mining_token()?;
    let verifier = crate::hash_mining_token(&token)?;
    let mut transaction = store.pool.begin().await?;
    let persisted_login = sqlx::query_scalar::<_, String>(
        "SELECT login FROM accounts WHERE deployment_id=$1 AND id=$2 AND enabled FOR UPDATE",
    )
    .bind(store.identity.id)
    .bind(account_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(StoreError::UnknownAccount)?;
    if persisted_login != account_login {
        return Err(StoreError::AccountOwnershipMismatch);
    }
    let worker_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::BIGINT FROM workers WHERE deployment_id=$1 AND account_id=$2",
    )
    .bind(store.identity.id)
    .bind(account_id)
    .fetch_one(&mut *transaction)
    .await?;
    if worker_count >= MAXIMUM_WORKERS_PER_ACCOUNT {
        return Err(StoreError::WorkerLimitReached);
    }
    let created_at = unix_i64(now)?;
    sqlx::query(
        "INSERT INTO workers \
         (deployment_id,id,account_id,label,canonical_login,created_at) \
         VALUES ($1,$2,$3,$4,$5,to_timestamp($6))",
    )
    .bind(store.identity.id)
    .bind(worker_id)
    .bind(account_id)
    .bind(worker_label)
    .bind(canonical_login)
    .bind(created_at)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO mining_tokens \
         (deployment_id,id,worker_id,verifier,created_at) \
         VALUES ($1,$2,$3,$4,to_timestamp($5))",
    )
    .bind(store.identity.id)
    .bind(token.id())
    .bind(worker_id)
    .bind(verifier)
    .bind(created_at)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok((worker_id, token))
}

async fn list_workers(
    store: &PostgresStore,
    account_id: Uuid,
    account_login: &str,
) -> Result<Vec<WorkerSummary>, RepositoryError> {
    super::postgres::validate_component(account_login, 64).map_err(repository_error)?;
    let rows = sqlx::query(
        "SELECT w.id,w.label,w.canonical_login, \
                EXTRACT(EPOCH FROM w.created_at)::BIGINT AS created_at, \
                EXTRACT(EPOCH FROM w.revoked_at)::BIGINT AS revoked_at \
         FROM workers w JOIN accounts a \
           ON (a.deployment_id,a.id)=(w.deployment_id,w.account_id) \
         WHERE w.deployment_id=$1 AND w.account_id=$2 AND a.login=$3 AND a.enabled \
         ORDER BY w.created_at,w.id LIMIT 101",
    )
    .bind(store.identity.id)
    .bind(account_id)
    .bind(account_login)
    .fetch_all(&store.pool)
    .await
    .map_err(repository_error)?;
    if rows.len() > usize::try_from(MAXIMUM_WORKERS_PER_ACCOUNT).unwrap_or(usize::MAX) {
        return Err(RepositoryError::InvalidState);
    }
    rows.into_iter()
        .map(|row| {
            Ok(WorkerSummary {
                id: row
                    .try_get("id")
                    .map_err(|_| RepositoryError::InvalidState)?,
                label: row
                    .try_get("label")
                    .map_err(|_| RepositoryError::InvalidState)?,
                mining_username: row
                    .try_get("canonical_login")
                    .map_err(|_| RepositoryError::InvalidState)?,
                created_at: unix_u64(
                    row.try_get("created_at")
                        .map_err(|_| RepositoryError::InvalidState)?,
                )
                .map_err(repository_error)?,
                revoked_at: row
                    .try_get::<Option<i64>, _>("revoked_at")
                    .map_err(|_| RepositoryError::InvalidState)?
                    .map(unix_u64)
                    .transpose()
                    .map_err(repository_error)?,
            })
        })
        .collect()
}

async fn revoke_worker_at(
    store: &PostgresStore,
    account_id: Uuid,
    worker_id: Uuid,
    now: u64,
) -> Result<bool, StoreError> {
    let mut transaction = store.pool.begin().await?;
    let result = sqlx::query(
        "UPDATE workers SET enabled=FALSE,revoked_at=to_timestamp($4) \
         WHERE deployment_id=$1 AND id=$2 AND account_id=$3 AND enabled",
    )
    .bind(store.identity.id)
    .bind(worker_id)
    .bind(account_id)
    .bind(unix_i64(now)?)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        transaction.rollback().await?;
        return Ok(false);
    }
    sqlx::query(
        "UPDATE mining_tokens SET revoked_at=to_timestamp($3) \
         WHERE deployment_id=$1 AND worker_id=$2 AND revoked_at IS NULL",
    )
    .bind(store.identity.id)
    .bind(worker_id)
    .bind(unix_i64(now)?)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(true)
}

struct OwnedPayoutPreference {
    account_id: Uuid,
    asset: Asset,
    network: ChainNetwork,
    canonical_address: String,
    receiver_kind: PortalReceiverKind,
    threshold_zat: u64,
    automatic: bool,
    changed_at: u64,
    replacement_hold_secs: u64,
    address_digest: [u8; 32],
}

async fn configure_payout(
    store: &PostgresStore,
    change: OwnedPayoutPreference,
) -> Result<PayoutSettingSummary, RepositoryError> {
    if change.account_id.is_nil()
        || change.changed_at == 0
        || change.threshold_zat == 0
        || change.threshold_zat > MAXIMUM_MONEY_ZAT
        || change.address_digest.iter().all(|byte| *byte == 0)
    {
        return Err(RepositoryError::InvalidState);
    }
    require_network(store, change.network)?;
    let chain = chain_for_asset(change.asset);
    let mut transaction = store.pool.begin().await.map_err(repository_error)?;
    sqlx::query(
        "SELECT id FROM accounts \
         WHERE deployment_id=$1 AND id=$2 AND enabled FOR UPDATE",
    )
    .bind(store.identity.id)
    .bind(change.account_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(repository_error)?
    .ok_or(RepositoryError::NotFound)?;
    let next_revision = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(MAX(revision),0)+1 FROM payout_change_events \
         WHERE deployment_id=$1 AND account_id=$2 AND chain=$3",
    )
    .bind(store.identity.id)
    .bind(change.account_id)
    .bind(chain.as_str())
    .fetch_one(&mut *transaction)
    .await
    .map_err(repository_error)?;
    let has_active = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM payout_destinations \
         WHERE deployment_id=$1 AND account_id=$2 AND chain=$3 AND state='active')",
    )
    .bind(store.identity.id)
    .bind(change.account_id)
    .bind(chain.as_str())
    .fetch_one(&mut *transaction)
    .await
    .map_err(repository_error)?;
    let (state, active_after) = if has_active {
        if !(MINIMUM_REPLACEMENT_HOLD_SECS..=MAXIMUM_REPLACEMENT_HOLD_SECS)
            .contains(&change.replacement_hold_secs)
        {
            return Err(RepositoryError::InvalidState);
        }
        (
            "pending",
            change
                .changed_at
                .checked_add(change.replacement_hold_secs)
                .ok_or(RepositoryError::InvalidState)?,
        )
    } else {
        ("active", change.changed_at)
    };
    sqlx::query(
        "UPDATE payout_destinations SET state='disabled',disabled_at=to_timestamp($4) \
         WHERE deployment_id=$1 AND account_id=$2 AND chain=$3 AND state='pending'",
    )
    .bind(store.identity.id)
    .bind(change.account_id)
    .bind(chain.as_str())
    .bind(unix_i64(change.changed_at).map_err(repository_error)?)
    .execute(&mut *transaction)
    .await
    .map_err(repository_error)?;
    let destination_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO payout_destinations \
         (deployment_id,id,account_id,chain,network,address,receiver_kind,validated_by, \
          validated_at,active_after,address_digest,payout_threshold_zat,automatic,state, \
          created_at,revision) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,'portal-authoritative-address-v1', \
                 to_timestamp($8),to_timestamp($9),$10,$11,$12,$13,to_timestamp($8),$14)",
    )
    .bind(store.identity.id)
    .bind(destination_id)
    .bind(change.account_id)
    .bind(chain.as_str())
    .bind(change.network.as_str())
    .bind(&change.canonical_address)
    .bind(portal_receiver_name(change.receiver_kind))
    .bind(unix_i64(change.changed_at).map_err(repository_error)?)
    .bind(unix_i64(active_after).map_err(repository_error)?)
    .bind(change.address_digest.as_slice())
    .bind(i64::try_from(change.threshold_zat).map_err(|_| RepositoryError::InvalidState)?)
    .bind(change.automatic)
    .bind(state)
    .bind(next_revision)
    .execute(&mut *transaction)
    .await
    .map_err(repository_error)?;
    sqlx::query(
        "INSERT INTO payout_change_events \
         (deployment_id,id,account_id,chain,address_digest,payout_threshold_zat,automatic, \
          requested_at,active_after,revision) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,to_timestamp($8),to_timestamp($9),$10)",
    )
    .bind(store.identity.id)
    .bind(Uuid::new_v4())
    .bind(change.account_id)
    .bind(chain.as_str())
    .bind(change.address_digest.as_slice())
    .bind(i64::try_from(change.threshold_zat).map_err(|_| RepositoryError::InvalidState)?)
    .bind(change.automatic)
    .bind(unix_i64(change.changed_at).map_err(repository_error)?)
    .bind(unix_i64(active_after).map_err(repository_error)?)
    .bind(next_revision)
    .execute(&mut *transaction)
    .await
    .map_err(repository_error)?;
    let setting = payout_setting_in_transaction(
        &mut transaction,
        store.identity.id,
        change.account_id,
        chain,
        change.network,
    )
    .await?;
    transaction.commit().await.map_err(repository_error)?;
    setting.ok_or(RepositoryError::InvalidState)
}

async fn payout_settings(
    store: &PostgresStore,
    account_id: Uuid,
    network: ChainNetwork,
    now: u64,
) -> Result<Vec<PayoutSettingSummary>, RepositoryError> {
    require_network(store, network)?;
    if account_id.is_nil() {
        return Err(RepositoryError::NotFound);
    }
    for chain in [Chain::Wcash, Chain::Zcash] {
        store
            .activate_due_payout_destinations(chain, now)
            .await
            .map_err(repository_error)?;
    }
    let mut transaction = store.pool.begin().await.map_err(repository_error)?;
    let mut settings = Vec::with_capacity(2);
    for chain in [Chain::Wcash, Chain::Zcash] {
        if let Some(setting) = payout_setting_in_transaction(
            &mut transaction,
            store.identity.id,
            account_id,
            chain,
            network,
        )
        .await?
        {
            settings.push(setting);
        }
    }
    transaction.commit().await.map_err(repository_error)?;
    Ok(settings)
}

async fn active_payout_destination(
    store: &PostgresStore,
    account_id: Uuid,
    asset: Asset,
    network: ChainNetwork,
    now: u64,
) -> Result<Option<ValidatedDestination>, RepositoryError> {
    require_network(store, network)?;
    let chain = chain_for_asset(asset);
    store
        .activate_due_payout_destinations(chain, now)
        .await
        .map_err(repository_error)?;
    let row = sqlx::query(
        "SELECT address,receiver_kind,network FROM payout_destinations \
         WHERE deployment_id=$1 AND account_id=$2 AND chain=$3 AND state='active'",
    )
    .bind(store.identity.id)
    .bind(account_id)
    .bind(chain.as_str())
    .fetch_optional(&store.pool)
    .await
    .map_err(repository_error)?;
    row.map(|row| {
        let persisted_network = row
            .try_get::<String, _>("network")
            .map_err(|_| RepositoryError::InvalidState)?;
        if persisted_network != network.as_str() {
            return Err(RepositoryError::InvalidState);
        }
        let receiver = portal_receiver_from_name(
            &row.try_get::<String, _>("receiver_kind")
                .map_err(|_| RepositoryError::InvalidState)?,
        )?;
        ValidatedDestination::from_authoritative_validation(
            asset,
            network,
            row.try_get("address")
                .map_err(|_| RepositoryError::InvalidState)?,
            receiver,
        )
        .map_err(|_| RepositoryError::InvalidState)
    })
    .transpose()
}

async fn payout_setting_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    account_id: Uuid,
    chain: Chain,
    network: ChainNetwork,
) -> Result<Option<PayoutSettingSummary>, RepositoryError> {
    let rows = sqlx::query(
        "SELECT address,receiver_kind,state, \
                EXTRACT(EPOCH FROM active_after)::BIGINT AS active_after, \
                payout_threshold_zat,automatic,revision \
         FROM payout_destinations \
         WHERE deployment_id=$1 AND account_id=$2 AND chain=$3 \
           AND state IN ('active','pending') ORDER BY revision",
    )
    .bind(deployment_id)
    .bind(account_id)
    .bind(chain.as_str())
    .fetch_all(&mut **transaction)
    .await
    .map_err(repository_error)?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut active_destination = None;
    let mut active_receiver = None;
    let mut pending_destination = None;
    let mut pending_effective_at = None;
    let mut threshold_zat = 0;
    let mut automatic = false;
    let mut revision = 0;
    for row in rows {
        let state = row
            .try_get::<String, _>("state")
            .map_err(|_| RepositoryError::InvalidState)?;
        let address = row
            .try_get::<String, _>("address")
            .map_err(|_| RepositoryError::InvalidState)?;
        let receiver = portal_receiver_from_name(
            &row.try_get::<String, _>("receiver_kind")
                .map_err(|_| RepositoryError::InvalidState)?,
        )?;
        let row_revision = u64::try_from(
            row.try_get::<i64, _>("revision")
                .map_err(|_| RepositoryError::InvalidState)?,
        )
        .map_err(|_| RepositoryError::InvalidState)?;
        if row_revision >= revision {
            revision = row_revision;
            threshold_zat = u64::try_from(
                row.try_get::<i64, _>("payout_threshold_zat")
                    .map_err(|_| RepositoryError::InvalidState)?,
            )
            .map_err(|_| RepositoryError::InvalidState)?;
            automatic = row
                .try_get("automatic")
                .map_err(|_| RepositoryError::InvalidState)?;
        }
        match state.as_str() {
            "active" => {
                active_destination = Some(mask_destination(&address));
                active_receiver = Some(receiver);
            }
            "pending" => {
                pending_destination = Some(mask_destination(&address));
                pending_effective_at = Some(
                    unix_u64(
                        row.try_get("active_after")
                            .map_err(|_| RepositoryError::InvalidState)?,
                    )
                    .map_err(repository_error)?,
                );
            }
            _ => return Err(RepositoryError::InvalidState),
        }
    }
    Ok(Some(PayoutSettingSummary {
        asset: asset_for_chain(chain),
        network,
        active_destination,
        active_receiver,
        pending_destination,
        pending_effective_at,
        threshold_zat,
        automatic,
        revision,
    }))
}

async fn reward_history(
    store: &PostgresStore,
    account_id: Uuid,
    page: PageRequest,
) -> Result<Page<RewardSummary>, RepositoryError> {
    validate_page(account_id, page)?;
    let rows = sqlx::query(
        "SELECT a.observation_event_seq,a.chain,w.height,w.block_hash_le,a.amount_zat,w.state \
         FROM winner_allocations a JOIN winners w \
           ON (w.deployment_id,w.chain,w.block_hash_le)= \
              (a.deployment_id,a.chain,a.block_hash_le) \
         WHERE a.deployment_id=$1 AND a.account_id=$2 \
           AND ($3::BIGINT IS NULL OR a.observation_event_seq < $3) \
         ORDER BY a.observation_event_seq DESC LIMIT $4",
    )
    .bind(store.identity.id)
    .bind(account_id)
    .bind(page_cursor(page)?)
    .bind(i64::from(page.limit) + 1)
    .fetch_all(&store.pool)
    .await
    .map_err(repository_error)?;
    let mut items = rows
        .into_iter()
        .map(|row| {
            Ok(RewardSummary {
                cursor: positive_u64(&row, "observation_event_seq")?,
                asset: asset_from_row(&row)?,
                block_height: positive_u64(&row, "height")?,
                block_hash: display_hash(
                    row.try_get("block_hash_le")
                        .map_err(|_| RepositoryError::InvalidState)?,
                )?,
                amount_zat: nonnegative_u64(&row, "amount_zat")?,
                state: safe_state(&row)?,
            })
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    Ok(paginate(&mut items, usize::from(page.limit), |item| {
        item.cursor
    }))
}

async fn found_blocks(
    store: &PostgresStore,
    account_id: Uuid,
    page: PageRequest,
) -> Result<Page<MinerBlockSummary>, RepositoryError> {
    validate_page(account_id, page)?;
    let rows = sqlx::query(
        "SELECT DISTINCT a.observation_event_seq,w.chain,w.height,w.block_hash_le,w.reward_zat,w.state \
         FROM winner_allocations a \
         JOIN winners w ON (w.deployment_id,w.chain,w.block_hash_le)= \
                           (a.deployment_id,a.chain,a.block_hash_le) \
         JOIN shares s ON (s.deployment_id,s.share_id)=(w.deployment_id,w.share_id) \
         WHERE a.deployment_id=$1 AND s.account_id=$2 \
           AND ($3::BIGINT IS NULL OR a.observation_event_seq < $3) \
         ORDER BY a.observation_event_seq DESC LIMIT $4",
    )
    .bind(store.identity.id)
    .bind(account_id)
    .bind(page_cursor(page)?)
    .bind(i64::from(page.limit) + 1)
    .fetch_all(&store.pool)
    .await
    .map_err(repository_error)?;
    let mut items = rows
        .into_iter()
        .map(|row| {
            Ok(MinerBlockSummary {
                cursor: positive_u64(&row, "observation_event_seq")?,
                asset: asset_from_row(&row)?,
                height: positive_u64(&row, "height")?,
                block_hash: display_hash(
                    row.try_get("block_hash_le")
                        .map_err(|_| RepositoryError::InvalidState)?,
                )?,
                reward_zat: positive_u64(&row, "reward_zat")?,
                state: safe_state(&row)?,
            })
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    Ok(paginate(&mut items, usize::from(page.limit), |item| {
        item.cursor
    }))
}

async fn payout_history(
    store: &PostgresStore,
    account_id: Uuid,
    page: PageRequest,
) -> Result<Page<MinerPayoutSummary>, RepositoryError> {
    validate_page(account_id, page)?;
    let rows = sqlx::query(
        "SELECT b.portal_sequence,b.id,b.chain,i.amount_zat,b.state,b.transaction_id, \
                b.confirmation_height \
         FROM payout_items i JOIN payout_batches b \
           ON (b.deployment_id,b.id)=(i.deployment_id,i.batch_id) \
         WHERE i.deployment_id=$1 AND i.account_id=$2 \
           AND ($3::BIGINT IS NULL OR b.portal_sequence < $3) \
         ORDER BY b.portal_sequence DESC LIMIT $4",
    )
    .bind(store.identity.id)
    .bind(account_id)
    .bind(page_cursor(page)?)
    .bind(i64::from(page.limit) + 1)
    .fetch_all(&store.pool)
    .await
    .map_err(repository_error)?;
    let mut items = rows
        .into_iter()
        .map(|row| {
            let transaction_id = row
                .try_get::<Option<Vec<u8>>, _>("transaction_id")
                .map_err(|_| RepositoryError::InvalidState)?
                .map(exact_hash)
                .transpose()?
                .map(hex::encode);
            Ok(MinerPayoutSummary {
                cursor: positive_u64(&row, "portal_sequence")?,
                batch_id: row
                    .try_get("id")
                    .map_err(|_| RepositoryError::InvalidState)?,
                asset: asset_from_row(&row)?,
                amount_zat: positive_u64(&row, "amount_zat")?,
                state: safe_state(&row)?,
                transaction_id,
                confirmation_height: row
                    .try_get::<Option<i64>, _>("confirmation_height")
                    .map_err(|_| RepositoryError::InvalidState)?
                    .map(|height| u64::try_from(height).map_err(|_| RepositoryError::InvalidState))
                    .transpose()?,
            })
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    Ok(paginate(&mut items, usize::from(page.limit), |item| {
        item.cursor
    }))
}

fn validate_page(account_id: Uuid, page: PageRequest) -> Result<(), RepositoryError> {
    if account_id.is_nil() || !page.validate() {
        Err(RepositoryError::InvalidState)
    } else {
        Ok(())
    }
}

fn page_cursor(page: PageRequest) -> Result<Option<i64>, RepositoryError> {
    page.before
        .map(i64::try_from)
        .transpose()
        .map_err(|_| RepositoryError::InvalidState)
}

fn paginate<T>(items: &mut Vec<T>, limit: usize, cursor: impl Fn(&T) -> u64) -> Page<T> {
    let next_before = if items.len() > limit {
        items.truncate(limit);
        items.last().map(cursor)
    } else {
        None
    };
    Page {
        items: std::mem::take(items),
        next_before,
    }
}

fn positive_u64(row: &sqlx::postgres::PgRow, column: &str) -> Result<u64, RepositoryError> {
    let value = nonnegative_u64(row, column)?;
    if value == 0 {
        Err(RepositoryError::InvalidState)
    } else {
        Ok(value)
    }
}

fn nonnegative_u64(row: &sqlx::postgres::PgRow, column: &str) -> Result<u64, RepositoryError> {
    u64::try_from(
        row.try_get::<i64, _>(column)
            .map_err(|_| RepositoryError::InvalidState)?,
    )
    .map_err(|_| RepositoryError::InvalidState)
}

fn asset_from_row(row: &sqlx::postgres::PgRow) -> Result<Asset, RepositoryError> {
    Chain::parse(
        &row.try_get::<String, _>("chain")
            .map_err(|_| RepositoryError::InvalidState)?,
    )
    .map(asset_for_chain)
    .map_err(repository_error)
}

fn safe_state(row: &sqlx::postgres::PgRow) -> Result<String, RepositoryError> {
    let state = row
        .try_get::<String, _>("state")
        .map_err(|_| RepositoryError::InvalidState)?;
    if state.is_empty()
        || state.len() > 32
        || !state
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        Err(RepositoryError::InvalidState)
    } else {
        Ok(state)
    }
}

fn exact_hash(value: Vec<u8>) -> Result<[u8; 32], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::InvalidState)
}

fn display_hash(value: Vec<u8>) -> Result<String, RepositoryError> {
    let mut hash = exact_hash(value)?;
    hash.reverse();
    Ok(hex::encode(hash))
}

/// Cached public-safe overview refreshed from the same PostgreSQL projection.
#[derive(Clone, Debug)]
pub struct PostgresPoolDataSource {
    store: PostgresStore,
    snapshot: Arc<RwLock<PoolOverview>>,
}

impl PostgresPoolDataSource {
    /// Creates an unavailable snapshot until the first successful refresh.
    pub fn new(store: PostgresStore) -> Self {
        Self {
            store,
            snapshot: Arc::new(RwLock::new(PoolOverview::default())),
        }
    }

    /// Refreshes public chain, worker, and immutable fee-policy state.
    pub async fn refresh(&self) -> Result<(), StoreError> {
        let policies = sqlx::query(
            "SELECT chain,fee_bps,policy_version FROM chain_policies \
             WHERE deployment_id=$1 ORDER BY chain",
        )
        .bind(self.store.identity.id)
        .fetch_all(&self.store.pool)
        .await?;
        if policies.len() != 2 {
            return Err(StoreError::CorruptDatabaseState("portal fee policies"));
        }
        let mut wec_fee_bps = None;
        let mut zec_fee_bps = None;
        let mut fee_policy_revision = None;
        for row in policies {
            let fee = u16::try_from(row.try_get::<i32, _>("fee_bps")?)
                .map_err(|_| StoreError::CorruptDatabaseState("portal pool fee"))?;
            let revision = u64::try_from(row.try_get::<i64, _>("policy_version")?)
                .map_err(|_| StoreError::CorruptDatabaseState("portal fee revision"))?;
            match Chain::parse(&row.try_get::<String, _>("chain")?)? {
                Chain::Wcash => wec_fee_bps = Some(fee),
                Chain::Zcash => zec_fee_bps = Some(fee),
            }
            fee_policy_revision = match fee_policy_revision {
                None => Some(revision),
                Some(previous) if previous == revision => Some(previous),
                Some(_) => return Err(StoreError::CorruptDatabaseState("portal fee revision")),
            };
        }
        let active_workers = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT s.worker_id)::BIGINT \
             FROM shares s JOIN backend_events e \
               ON (e.deployment_id,e.event_seq)=(s.deployment_id,s.event_seq) \
             WHERE s.deployment_id=$1 AND e.recorded_at >= clock_timestamp()-INTERVAL '5 minutes'",
        )
        .bind(self.store.identity.id)
        .fetch_one(&self.store.pool)
        .await?;
        let latest_job = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT descriptor FROM jobs WHERE deployment_id=$1 \
             ORDER BY activation_event_seq DESC LIMIT 1",
        )
        .bind(self.store.identity.id)
        .fetch_optional(&self.store.pool)
        .await?
        .map(serde_json::from_value::<JobDescriptor>)
        .transpose()
        .map_err(|_| StoreError::CorruptDatabaseState("portal latest job"))?;
        let updated_at =
            sqlx::query_scalar::<_, i64>("SELECT EXTRACT(EPOCH FROM clock_timestamp())::BIGINT")
                .fetch_one(&self.store.pool)
                .await?;
        let snapshot = PoolOverview {
            available: true,
            updated_at: Some(unix_u64(updated_at)?),
            // Work-to-sol/s normalization belongs to a separately reviewed
            // telemetry projector; never label share count as hashrate.
            hashrate_sol_s: None,
            active_workers: Some(
                u64::try_from(active_workers)
                    .map_err(|_| StoreError::CorruptDatabaseState("active workers"))?,
            ),
            wcash_height: latest_job
                .as_ref()
                .map(|job| u64::from(job.wcash_height.saturating_sub(1))),
            zcash_height: latest_job
                .as_ref()
                .map(|job| u64::from(job.zcash_height.saturating_sub(1))),
            wec_fee_bps,
            zec_fee_bps,
            fee_policy_revision,
        };
        *self
            .snapshot
            .write()
            .map_err(|_| StoreError::CorruptDatabaseState("portal overview lock"))? = snapshot;
        Ok(())
    }
}

impl PoolDataSource for PostgresPoolDataSource {
    fn overview(&self) -> PoolOverview {
        self.snapshot
            .read()
            .map_or_else(|_| PoolOverview::default(), |snapshot| snapshot.clone())
    }
}

fn repository_error<Error>(error: Error) -> RepositoryError
where
    StoreError: From<Error>,
{
    let error = StoreError::from(error);
    match error {
        StoreError::UnknownAccount | StoreError::AccountOwnershipMismatch => {
            RepositoryError::NotFound
        }
        StoreError::WorkerLimitReached => RepositoryError::Conflict,
        StoreError::Database(sqlx::Error::Database(database)) if database.is_unique_violation() => {
            RepositoryError::Conflict
        }
        StoreError::Database(_) | StoreError::Migration(_) => RepositoryError::Unavailable,
        _ => RepositoryError::InvalidState,
    }
}

fn require_network(store: &PostgresStore, network: ChainNetwork) -> Result<(), RepositoryError> {
    let matches = matches!(
        (store.identity.network, network),
        (DeploymentNetwork::Testnet, ChainNetwork::Testnet)
            | (DeploymentNetwork::Mainnet, ChainNetwork::Mainnet)
    );
    if matches {
        Ok(())
    } else {
        Err(RepositoryError::InvalidState)
    }
}

const fn chain_for_asset(asset: Asset) -> Chain {
    match asset {
        Asset::Wec => Chain::Wcash,
        Asset::Zec => Chain::Zcash,
    }
}

const fn asset_for_chain(chain: Chain) -> Asset {
    match chain {
        Chain::Wcash => Asset::Wec,
        Chain::Zcash => Asset::Zec,
    }
}

const fn portal_receiver_name(receiver: PortalReceiverKind) -> &'static str {
    match receiver {
        PortalReceiverKind::Transparent => "transparent",
        PortalReceiverKind::Ironwood => "ironwood",
    }
}

fn portal_receiver_from_name(value: &str) -> Result<PortalReceiverKind, RepositoryError> {
    match value {
        "transparent" => Ok(PortalReceiverKind::Transparent),
        "ironwood" => Ok(PortalReceiverKind::Ironwood),
        _ => Err(RepositoryError::InvalidState),
    }
}
