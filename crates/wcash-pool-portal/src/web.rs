//! Axum router for the authenticated miner portal.

use std::{str::FromStr, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{
        header::{
            CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, ORIGIN, REFERRER_POLICY,
            SET_COOKIE, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
        },
        HeaderMap, HeaderValue, Request, StatusCode,
    },
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    security::{
        constant_time_digest_eq, decrypt_totp_secret, encode_totp_secret, encrypt_totp_secret,
        hash_password, keyed_digest, new_totp_secret, random_token, verify_password, verify_totp,
        SecurityError,
    },
    AccountSummary, AddressValidationError, AddressValidator, Asset, Clock, ConfigError,
    MinerTelemetrySource, NewSession, PageRequest, PayoutPreferenceChange, PayoutSettingSummary,
    PoolDataSource, PortalConfig, PortalRepository, PortalSecrets, RepositoryError, SignerError,
    SystemClock, TestnetPayoutBoundary, UnavailableMinerTelemetry,
};

const SESSION_COOKIE: &str = "__Host-zecwec_session";
const CSRF_COOKIE: &str = "__Host-zecwec_csrf";
const SESSION_DIGEST_DOMAIN: &[u8] = b"zecwec/portal/session/v1";
const CSRF_DIGEST_DOMAIN: &[u8] = b"zecwec/portal/csrf/v1";
const ADDRESS_DIGEST_DOMAIN: &[u8] = b"zecwec/payout/address/v1";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const TOTP_ENROLLMENT_TTL_SECS: u64 = 10 * 60;
const READINESS_TIMEOUT: Duration = Duration::from_millis(500);

/// Complete dependency set for the portal router.
#[derive(Clone)]
pub struct PortalApp {
    state: Arc<AppState>,
}

struct AppState {
    config: PortalConfig,
    secrets: PortalSecrets,
    store: Arc<dyn PortalRepository>,
    validator: Arc<dyn AddressValidator>,
    pool_data: Arc<dyn PoolDataSource>,
    miner_telemetry: Arc<dyn MinerTelemetrySource>,
    payout: Arc<TestnetPayoutBoundary>,
    clock: Arc<dyn Clock>,
    argon2_slots: Arc<Semaphore>,
    dummy_password_hash: String,
}

impl PortalApp {
    /// Creates a Testnet portal with explicit address and data authorities.
    pub fn new(
        config: PortalConfig,
        secrets: PortalSecrets,
        store: Arc<dyn PortalRepository>,
        validator: Arc<dyn AddressValidator>,
        pool_data: Arc<dyn PoolDataSource>,
        payout: Arc<TestnetPayoutBoundary>,
    ) -> Result<Self, PortalBuildError> {
        Self::new_with_telemetry(
            config,
            secrets,
            store,
            validator,
            pool_data,
            Arc::new(UnavailableMinerTelemetry),
            payout,
        )
    }

    /// Creates a Testnet portal with authenticated live miner telemetry.
    pub fn new_with_telemetry(
        config: PortalConfig,
        secrets: PortalSecrets,
        store: Arc<dyn PortalRepository>,
        validator: Arc<dyn AddressValidator>,
        pool_data: Arc<dyn PoolDataSource>,
        miner_telemetry: Arc<dyn MinerTelemetrySource>,
        payout: Arc<TestnetPayoutBoundary>,
    ) -> Result<Self, PortalBuildError> {
        Self::with_clock_and_telemetry(
            config,
            secrets,
            store,
            validator,
            pool_data,
            miner_telemetry,
            payout,
            Arc::new(SystemClock),
        )
    }

    /// Creates a portal with an injected clock for deterministic integration tests.
    pub fn with_clock(
        config: PortalConfig,
        secrets: PortalSecrets,
        store: Arc<dyn PortalRepository>,
        validator: Arc<dyn AddressValidator>,
        pool_data: Arc<dyn PoolDataSource>,
        payout: Arc<TestnetPayoutBoundary>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PortalBuildError> {
        Self::with_clock_and_telemetry(
            config,
            secrets,
            store,
            validator,
            pool_data,
            Arc::new(UnavailableMinerTelemetry),
            payout,
            clock,
        )
    }

    /// Creates a portal with deterministic time and live miner telemetry.
    #[allow(clippy::too_many_arguments)]
    pub fn with_clock_and_telemetry(
        config: PortalConfig,
        secrets: PortalSecrets,
        store: Arc<dyn PortalRepository>,
        validator: Arc<dyn AddressValidator>,
        pool_data: Arc<dyn PoolDataSource>,
        miner_telemetry: Arc<dyn MinerTelemetrySource>,
        payout: Arc<TestnetPayoutBoundary>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PortalBuildError> {
        config.validate()?;
        secrets.validate()?;
        if config.network == crate::ChainNetwork::Mainnet
            && payout.execution() != crate::PayoutExecution::Deferred
        {
            return Err(PortalBuildError::MainnetDisabled);
        }
        let dummy_password_hash = hash_password("dummy credential never authenticates")?;
        let argon2_slots = Arc::new(Semaphore::new(config.argon2_operation_slots));
        Ok(Self {
            state: Arc::new(AppState {
                config,
                secrets,
                store,
                validator,
                pool_data,
                miner_telemetry,
                payout,
                clock,
                argon2_slots,
                dummy_password_hash,
            }),
        })
    }

    /// Builds the bounded same-origin HTTP router.
    pub fn router(self) -> Router {
        Router::new()
            .route("/", get(index))
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz))
            .route("/assets/app.css", get(styles))
            .route("/assets/forms.css", get(form_styles))
            .route("/assets/app.js", get(script))
            .route("/api/v1/overview", get(overview))
            .route("/api/v1/balances", get(balances))
            .route("/api/v1/telemetry", get(miner_telemetry))
            .route("/api/v1/rewards", get(reward_history))
            .route("/api/v1/blocks", get(found_blocks))
            .route("/api/v1/payouts", get(payout_history))
            .route("/api/v1/auth/register", post(register))
            .route("/api/v1/auth/login", post(login))
            .route("/api/v1/auth/logout", post(logout))
            .route("/api/v1/me", get(me))
            .route("/api/v1/workers", get(list_workers).post(create_worker))
            .route("/api/v1/workers/{worker_id}", delete(revoke_worker))
            .route("/api/v1/settings/payouts", get(list_payout_settings))
            .route(
                "/api/v1/settings/payouts/{asset}",
                put(update_payout_setting),
            )
            .route("/api/v1/security/totp/begin", post(begin_totp))
            .route("/api/v1/security/totp/confirm", post(confirm_totp))
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
            .layer(middleware::from_fn(security_headers))
            .with_state(self.state)
    }
}

/// Serves the portal on a caller-created listener, normally loopback behind nginx.
pub async fn serve(listener: TcpListener, app: PortalApp) -> std::io::Result<()> {
    axum::serve(listener, app.router()).await
}

/// Serves the portal until the process-wide shutdown signal is observed, then
/// drains in-flight HTTP requests before returning.
pub async fn serve_until_shutdown(
    listener: TcpListener,
    app: PortalApp,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    axum::serve(listener, app.router())
        .with_graceful_shutdown(async move {
            if !*shutdown.borrow() {
                let _ = shutdown.changed().await;
            }
        })
        .await
}

/// Portal construction failure.
#[derive(Debug, thiserror::Error)]
pub enum PortalBuildError {
    /// Runtime policy is invalid.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Dummy credential initialization failed.
    #[error(transparent)]
    Security(#[from] SecurityError),
    /// This alpha service must not expose monetary Mainnet accounts.
    #[error("mainnet portal serving is disabled in this release")]
    MainnetDisabled,
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn readyz(State(state): State<Arc<AppState>>) -> Result<Json<Value>, AppError> {
    if !state.pool_data.mining_ready() {
        return Err(AppError::Unavailable);
    }
    state.store.readiness().await?;
    if state.payout.execution() == crate::PayoutExecution::Enabled
        && !state.store.payout_worker_is_live().await?
    {
        return Err(AppError::Unavailable);
    }
    address_validator_readiness(&state, Asset::Wec).await?;
    address_validator_readiness(&state, Asset::Zec).await?;
    state.payout.readiness_bounded(READINESS_TIMEOUT).await?;
    // Mining can pause while the other dependency checks are awaiting I/O.
    if !state.pool_data.mining_ready() {
        return Err(AppError::Unavailable);
    }
    Ok(Json(json!({
        "ready": true,
        "component": "miner-portal",
        "network": state.config.network,
        "payout_execution": state.payout.execution().as_str()
    })))
}

async fn index(State(state): State<Arc<AppState>>) -> Html<String> {
    Html(render_index(&state.config))
}

fn render_index(config: &PortalConfig) -> String {
    let mut page = include_str!("../assets/index.html").to_owned();
    if config.network == crate::ChainNetwork::Mainnet {
        page = page
        .replace("Testnet", "Mainnet")
        .replace("TESTNET", "MAINNET")
        .replace("TWC", "WEC")
        .replace("Two test networks.", "Two main networks.")
        .replace("· no monetary value", "· automatic payout")
        .replace("<option value=\"tls\">TLS · preferred</option>", "")
        .replace("<option value=\"tcp\">TCP · hardware compatibility</option>", "<option value=\"tcp\">TCP · ASIC compatible</option>")
        .replace("stratum+ssl://testnet-mine.zecwec.com:3443", "stratum+tcp://mainnet.zecwec.com:3334")
        .replace("Use TLS when your ASIC firmware supports it.", "This account pool uses a separate Stratum endpoint. Existing invited workers remain on port 3333.");
    }
    if !config.allow_registration {
        page = page
            .replace("<li>Create an account</li>", "<li>Sign in to an invited account</li>")
            .replace("<button class=\"segment\" data-auth-mode=\"register\" type=\"button\" aria-pressed=\"false\">Create account</button>", "");
    }
    if config.mining_password_ignored {
        page = page
            .replace(
                "Your ASIC uses a separate mining-only token.",
                "Your ASIC uses its exact mining username and password x.",
            )
            .replace(
                "Keep this separate from your worker token.",
                "This password protects your portal account and payout settings.",
            )
            .replace("Create worker token", "Create worker");
    }
    page
}

async fn styles() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../assets/app.css"),
    )
}

async fn form_styles() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../assets/forms.css"),
    )
}

async fn script(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let source = render_script(&state.config);
    (
        [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
        source,
    )
}

fn render_script(config: &PortalConfig) -> String {
    let mut source = include_str!("../assets/app.js").to_owned();
    if config.network == crate::ChainNetwork::Mainnet {
        source = source
            .replace("testnet-mine.zecwec.com:3443", "mainnet.zecwec.com:3334")
            .replace("testnet-mine.zecwec.com:3333", "mainnet.zecwec.com:3334")
            .replace("Testnet", "Mainnet")
            .replace("TWC", "WEC")
            .replace(
                "const AUTOMATIC_PAYOUT_ENABLED = { wec: true, zec: true };",
                "const AUTOMATIC_PAYOUT_ENABLED = { wec: true, zec: false };",
            )
            .replace(
                "const TLS_STRATUM_AVAILABLE = true;",
                "const TLS_STRATUM_AVAILABLE = false;",
            );
    }
    if config.mining_password_ignored {
        source = source.replace(
            "const MINING_PASSWORD_IGNORED = false;",
            "const MINING_PASSWORD_IGNORED = true;",
        );
    }
    source
}

async fn overview(State(state): State<Arc<AppState>>) -> Json<crate::PoolOverview> {
    Json(state.pool_data.overview())
}

async fn balances(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let auth = authenticate(&state, &headers).await?;
    let balances = state.store.balances(auth.session.account_id).await?;
    Ok(Json(json!({ "balances": balances })))
}

async fn miner_telemetry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<crate::MinerTelemetrySummary>, AppError> {
    let auth = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .miner_telemetry
            .account_snapshot(auth.session.account_id),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryQuery {
    before: Option<u64>,
    limit: Option<u16>,
}

impl HistoryQuery {
    fn page(&self) -> Result<PageRequest, AppError> {
        let page = PageRequest {
            before: self.before,
            limit: self.limit.unwrap_or(50),
        };
        if page.validate() {
            Ok(page)
        } else {
            Err(AppError::Validation("invalid page"))
        }
    }
}

async fn reward_history(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let auth = authenticate(&state, &headers).await?;
    let page = state
        .store
        .reward_history(auth.session.account_id, query.page()?)
        .await?;
    Ok(Json(json!(page)))
}

async fn found_blocks(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let auth = authenticate(&state, &headers).await?;
    let page = state
        .store
        .found_blocks(auth.session.account_id, query.page()?)
        .await?;
    Ok(Json(json!(page)))
}

async fn payout_history(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let auth = authenticate(&state, &headers).await?;
    let page = state
        .store
        .payout_history(auth.session.account_id, query.page()?)
        .await?;
    Ok(Json(json!(page)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    username: String,
    password: String,
}

async fn register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_origin(&state, &headers)?;
    if !state.config.allow_registration {
        return Err(AppError::Forbidden);
    }
    let username = canonical_username(&request.username)?;
    let password = Zeroizing::new(request.password);
    let password_hash =
        run_password_operation(&state, move || hash_password(password.as_str())).await??;
    let account_id = Uuid::new_v4();
    state
        .store
        .create_account(account_id, &username, &password_hash, state.clock.now())
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "account": { "id": account_id, "username": username } })),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    username: String,
    password: String,
    totp_code: Option<String>,
}

#[derive(Serialize)]
struct LoginResponse {
    account: AccountSummary,
    csrf_token: String,
}

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<Response, AppError> {
    require_origin(&state, &headers)?;
    let username = canonical_username(&request.username);
    let account = match username {
        Ok(username) => state.store.account_by_username(&username).await?,
        Err(_) => None,
    };
    let encoded = account.as_ref().map_or_else(
        || state.dummy_password_hash.clone(),
        |value| value.password_hash.clone(),
    );
    let password = Zeroizing::new(request.password);
    let password_valid =
        run_password_operation(&state, move || verify_password(password.as_str(), &encoded))
            .await?;
    let now = state.clock.now();

    let Some(account) = account else {
        return Err(AppError::InvalidCredentials);
    };
    let locked = account.locked_until.is_some_and(|until| until > now);
    let mut totp_code = request.totp_code;
    let totp_valid = if let Some(sealed) = account.totp_secret.as_deref() {
        let secret = decrypt_totp_secret(
            state.secrets.totp_encryption_key(),
            account.id.as_bytes(),
            sealed,
        )?;
        totp_code
            .as_deref()
            .is_some_and(|code| verify_totp(&secret, code, now))
    } else {
        true
    };
    totp_code.zeroize();
    if locked || !password_valid || !totp_valid {
        if !locked {
            state
                .store
                .record_failed_login(
                    account.id,
                    state.config.max_login_attempts,
                    now.saturating_add(state.config.login_lock_secs),
                )
                .await?;
        }
        return Err(AppError::InvalidCredentials);
    }
    state.store.clear_failed_login(account.id).await?;

    let session_token = random_token("zs_")?;
    let csrf_token = random_token("zc_")?;
    let session_digest = keyed_digest(
        state.secrets.token_pepper(),
        SESSION_DIGEST_DOMAIN,
        &session_token,
    );
    let csrf_digest = keyed_digest(
        state.secrets.token_pepper(),
        CSRF_DIGEST_DOMAIN,
        &csrf_token,
    );
    let second_factor_time = account.totp_secret.as_ref().map(|_| now);
    state
        .store
        .create_session(NewSession {
            token_digest: &session_digest,
            csrf_digest: &csrf_digest,
            account_id: account.id,
            security_version: account.security_version,
            authenticated_at: now,
            second_factor_at: second_factor_time,
            expires_at: now.saturating_add(state.config.session_ttl_secs),
            idle_expires_at: now.saturating_add(state.config.session_idle_secs),
        })
        .await?;

    let response = LoginResponse {
        account: AccountSummary {
            id: account.id,
            username: account.username,
            totp_enabled: account.totp_secret.is_some(),
        },
        csrf_token: csrf_token.clone(),
    };
    let mut response = Json(response).into_response();
    response.headers_mut().append(
        SET_COOKIE,
        HeaderValue::from_str(&session_cookie(
            &session_token,
            state.config.session_ttl_secs,
        ))
        .map_err(|_| AppError::Internal)?,
    );
    response.headers_mut().append(
        SET_COOKIE,
        HeaderValue::from_str(&csrf_cookie(&csrf_token, state.config.session_ttl_secs))
            .map_err(|_| AppError::Internal)?,
    );
    Ok(response)
}

async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let auth = authenticate(&state, &headers).await?;
    require_mutation(&state, &headers, &auth)?;
    state.store.delete_session(&auth.session_digest).await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static(
            "__Host-zecwec_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    response.headers_mut().append(
        SET_COOKIE,
        HeaderValue::from_static("__Host-zecwec_csrf=; Path=/; Secure; SameSite=Strict; Max-Age=0"),
    );
    Ok(response)
}

async fn me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<AccountSummary>, AppError> {
    let auth = authenticate(&state, &headers).await?;
    let account = state
        .store
        .account_by_username(&auth.session.username)
        .await?
        .ok_or(AppError::Unauthorized)?;
    Ok(Json(AccountSummary {
        id: account.id,
        username: account.username,
        totp_enabled: account.totp_secret.is_some(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerRequest {
    label: String,
}

async fn create_worker(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<WorkerRequest>,
) -> Result<impl IntoResponse, AppError> {
    let auth = authenticate(&state, &headers).await?;
    require_mutation(&state, &headers, &auth)?;
    let label = canonical_worker_label(&request.label)?;
    // Transfer one shared Argon2 admission slot into the repository's blocking
    // verifier task. Saturation fails immediately, and HTTP cancellation
    // cannot release the slot before memory-hard work actually exits.
    let argon2_permit = argon2_operation_slot(&state.argon2_slots)?;
    let worker = state
        .store
        .provision_worker(
            auth.session.account_id,
            &auth.session.username,
            &label,
            state.clock.now(),
            argon2_permit,
        )
        .await?;
    if worker.account_id != auth.session.account_id
        || worker.canonical_login != format!("{}.{}", auth.session.username, label)
        || !valid_mining_token_shape(&worker.token)
    {
        return Err(AppError::Internal);
    }
    let worker_json = if state.config.mining_password_ignored {
        json!({
            "id": worker.worker_id,
            "label": label,
            "mining_username": worker.canonical_login,
            "password": "x",
            "password_ignored": true
        })
    } else {
        json!({
            "id": worker.worker_id,
            "label": label,
            "mining_username": worker.canonical_login,
            "token": worker.token,
            "token_displayed_once": true
        })
    };
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "worker": worker_json
        })),
    ))
}

async fn list_workers(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let auth = authenticate(&state, &headers).await?;
    let workers = state
        .store
        .list_workers(auth.session.account_id, &auth.session.username)
        .await?;
    Ok(Json(json!({ "workers": workers })))
}

async fn revoke_worker(
    State(state): State<Arc<AppState>>,
    Path(worker_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let auth = authenticate(&state, &headers).await?;
    require_mutation(&state, &headers, &auth)?;
    if !state
        .store
        .revoke_worker(auth.session.account_id, worker_id, state.clock.now())
        .await?
    {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn list_payout_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let auth = authenticate(&state, &headers).await?;
    let configured = state
        .store
        .payout_settings(
            auth.session.account_id,
            state.config.network,
            state.clock.now(),
        )
        .await?;
    let mut settings = Vec::with_capacity(2);
    for asset in [Asset::Wec, Asset::Zec] {
        settings.push(
            configured
                .iter()
                .find(|value| value.asset == asset)
                .cloned()
                .unwrap_or(PayoutSettingSummary {
                    asset,
                    network: state.config.network,
                    active_destination: None,
                    active_receiver: None,
                    pending_destination: None,
                    pending_effective_at: None,
                    threshold_zat: 0,
                    automatic: false,
                    revision: 0,
                    pending_threshold_zat: None,
                    pending_automatic: None,
                    pending_revision: None,
                }),
        );
    }
    Ok(Json(json!({
        "settings": settings,
        "payout_change_hold_secs": state.config.payout_change_hold_secs,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PayoutSettingRequest {
    destination: String,
    threshold_zat: u64,
    automatic: bool,
    password: String,
    totp_code: Option<String>,
}

async fn update_payout_setting(
    State(state): State<Arc<AppState>>,
    Path(asset): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PayoutSettingRequest>,
) -> Result<Json<PayoutSettingSummary>, AppError> {
    let auth = authenticate(&state, &headers).await?;
    require_mutation(&state, &headers, &auth)?;
    let PayoutSettingRequest {
        destination: candidate,
        threshold_zat,
        automatic,
        password,
        totp_code,
    } = request;
    require_reauthentication(&state, &auth, password, totp_code).await?;
    let asset = Asset::from_str(&asset).map_err(|_| AppError::NotFound)?;
    if threshold_zat == 0 || threshold_zat > 2_100_000_000_000_000 {
        return Err(AppError::Validation("invalid payout threshold"));
    }
    if state.config.network == crate::ChainNetwork::Mainnet && asset == Asset::Zec && automatic {
        return Err(AppError::Validation(
            "automatic ZEC payouts are not enabled",
        ));
    }
    let destination = validate_payout_destination(&state, asset, candidate).await?;
    if destination.asset() != asset || destination.network() != state.config.network {
        return Err(AppError::Validation(
            "address authority returned inconsistent data",
        ));
    }
    let address_digest = keyed_digest(
        state.secrets.token_pepper(),
        ADDRESS_DIGEST_DOMAIN,
        destination.canonical_address(),
    );
    let setting = state
        .store
        .configure_payout(PayoutPreferenceChange {
            account_id: auth.session.account_id,
            destination: &destination,
            threshold_zat,
            automatic,
            changed_at: state.clock.now(),
            replacement_hold_secs: state.config.payout_change_hold_secs,
            address_digest: &address_digest,
        })
        .await?;
    Ok(Json(setting))
}

async fn address_validator_readiness(state: &Arc<AppState>, asset: Asset) -> Result<(), AppError> {
    let validator = Arc::clone(&state.validator);
    let network = state.config.network;
    tokio::task::spawn_blocking(move || validator.readiness(asset, network))
        .await
        .map_err(|_| AppError::Internal)??;
    Ok(())
}

async fn validate_payout_destination(
    state: &Arc<AppState>,
    asset: Asset,
    candidate: String,
) -> Result<crate::ValidatedDestination, AppError> {
    let validator = Arc::clone(&state.validator);
    let network = state.config.network;
    tokio::task::spawn_blocking(move || validator.validate(asset, network, candidate.trim()))
        .await
        .map_err(|_| AppError::Internal)?
        .map_err(AppError::from)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReauthenticationRequest {
    password: String,
    totp_code: Option<String>,
}

async fn begin_totp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ReauthenticationRequest>,
) -> Result<Json<Value>, AppError> {
    let auth = authenticate(&state, &headers).await?;
    require_mutation(&state, &headers, &auth)?;
    require_reauthentication(&state, &auth, request.password, request.totp_code).await?;
    let secret = new_totp_secret()?;
    let sealed = encrypt_totp_secret(
        state.secrets.totp_encryption_key(),
        auth.session.account_id.as_bytes(),
        &secret,
    )?;
    let now = state.clock.now();
    state
        .store
        .save_pending_totp(
            auth.session.account_id,
            &sealed,
            now.saturating_add(TOTP_ENROLLMENT_TTL_SECS),
        )
        .await?;
    let encoded = encode_totp_secret(&secret);
    Ok(Json(json!({
        "secret_base32": encoded,
        "otpauth_uri": format!(
            "otpauth://totp/ZecWec:{}?secret={}&issuer=ZecWec&algorithm=SHA1&digits=6&period=30",
            auth.session.username, encoded
        ),
        "expires_at": now.saturating_add(TOTP_ENROLLMENT_TTL_SECS)
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmTotpRequest {
    code: String,
}

async fn confirm_totp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ConfirmTotpRequest>,
) -> Result<Response, AppError> {
    let auth = authenticate(&state, &headers).await?;
    require_mutation(&state, &headers, &auth)?;
    let account = state
        .store
        .account_by_username(&auth.session.username)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let now = state.clock.now();
    let pending = account
        .totp_pending
        .ok_or(AppError::Validation("no pending enrollment"))?;
    if account
        .totp_pending_expires_at
        .is_none_or(|expires| expires <= now)
    {
        return Err(AppError::Validation("TOTP enrollment expired"));
    }
    let secret = decrypt_totp_secret(
        state.secrets.totp_encryption_key(),
        account.id.as_bytes(),
        &pending,
    )?;
    if !verify_totp(&secret, &request.code, now) {
        return Err(AppError::InvalidCredentials);
    }
    if !state.store.activate_pending_totp(account.id, now).await? {
        return Err(AppError::Conflict);
    }
    state.store.delete_account_sessions(account.id).await?;
    let mut response =
        Json(json!({ "enabled": true, "reauthentication_required": true })).into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static(
            "__Host-zecwec_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    response.headers_mut().append(
        SET_COOKIE,
        HeaderValue::from_static("__Host-zecwec_csrf=; Path=/; Secure; SameSite=Strict; Max-Age=0"),
    );
    Ok(response)
}

async fn require_reauthentication(
    state: &AppState,
    auth: &Authenticated,
    password: String,
    mut totp_code: Option<String>,
) -> Result<(), AppError> {
    let account = state
        .store
        .account_by_username(&auth.session.username)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let encoded = account.password_hash.clone();
    let password = Zeroizing::new(password);
    let password_valid =
        run_password_operation(state, move || verify_password(password.as_str(), &encoded)).await?;
    let now = state.clock.now();
    let locked = account.locked_until.is_some_and(|until| until > now);
    let totp_valid = if let Some(sealed) = account.totp_secret.as_deref() {
        let secret = decrypt_totp_secret(
            state.secrets.totp_encryption_key(),
            account.id.as_bytes(),
            sealed,
        )?;
        let valid = totp_code
            .as_deref()
            .is_some_and(|code| verify_totp(&secret, code, now));
        valid
    } else {
        true
    };
    totp_code.zeroize();
    if locked || !password_valid || !totp_valid {
        if !locked {
            state
                .store
                .record_failed_login(
                    account.id,
                    state.config.max_login_attempts,
                    now.saturating_add(state.config.login_lock_secs),
                )
                .await?;
        }
        return Err(AppError::InvalidCredentials);
    }
    state.store.clear_failed_login(account.id).await?;
    Ok(())
}

struct Authenticated {
    session_digest: [u8; 32],
    session: crate::AuthenticatedSession,
}

async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Authenticated, AppError> {
    let token = cookie_value(headers, SESSION_COOKIE).ok_or(AppError::Unauthorized)?;
    let digest = keyed_digest(state.secrets.token_pepper(), SESSION_DIGEST_DOMAIN, token);
    let now = state.clock.now();
    let session = state
        .store
        .authenticate_session(
            &digest,
            now,
            now.saturating_add(state.config.session_idle_secs),
        )
        .await?
        .ok_or(AppError::Unauthorized)?;
    Ok(Authenticated {
        session_digest: digest,
        session,
    })
}

fn require_origin(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    let origin = headers
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Forbidden)?;
    if origin != state.config.canonical_origin {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

async fn run_password_operation<T, Operation>(
    state: &AppState,
    operation: Operation,
) -> Result<T, AppError>
where
    T: Send + 'static,
    Operation: FnOnce() -> T + Send + 'static,
{
    let permit = argon2_operation_slot(&state.argon2_slots)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await
    .map_err(|_| AppError::Internal)
}

fn argon2_operation_slot(slots: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit, AppError> {
    Arc::clone(slots)
        .try_acquire_owned()
        .map_err(|_| AppError::Busy)
}

fn require_mutation(
    state: &AppState,
    headers: &HeaderMap,
    auth: &Authenticated,
) -> Result<(), AppError> {
    require_origin(state, headers)?;
    let supplied = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Forbidden)?;
    let digest = keyed_digest(state.secrets.token_pepper(), CSRF_DIGEST_DOMAIN, supplied);
    if !constant_time_digest_eq(&digest, &auth.session.csrf_digest) {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(key, value)| (key == name && !value.is_empty()).then_some(value))
}

fn canonical_username(candidate: &str) -> Result<String, AppError> {
    let value = candidate.trim().to_ascii_lowercase();
    let mut bytes = value.bytes();
    let first = bytes
        .next()
        .ok_or(AppError::Validation("invalid account name"))?;
    if !(3..=32).contains(&value.len())
        || !first.is_ascii_lowercase()
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(AppError::Validation("invalid account name"));
    }
    Ok(value)
}

fn canonical_worker_label(candidate: &str) -> Result<String, AppError> {
    let value = candidate.trim().to_ascii_lowercase();
    if !(1..=32).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(AppError::Validation("invalid worker label"));
    }
    Ok(value)
}

fn valid_mining_token_shape(token: &str) -> bool {
    let mut fields = token.split('.');
    let valid = matches!(fields.next(), Some("zw1"))
        && fields.next().is_some_and(|selector| {
            selector.len() == 32
                && selector
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        && fields.next().is_some_and(|secret| {
            secret.len() == 64
                && secret
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    valid && fields.next().is_none()
}

fn session_cookie(token: &str, max_age: u64) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={max_age}"
    )
}

fn csrf_cookie(token: &str, max_age: u64) -> String {
    format!("{CSRF_COOKIE}={token}; Path=/; Secure; SameSite=Strict; Max-Age={max_age}")
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers
        .entry("permissions-policy")
        .or_insert(HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=()",
        ));
    response
}

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("invalid request")]
    Validation(&'static str),
    #[error("service unavailable")]
    Unavailable,
    #[error("credential service busy")]
    Busy,
    #[error("internal error")]
    Internal,
}

impl From<RepositoryError> for AppError {
    fn from(error: RepositoryError) -> Self {
        match error {
            RepositoryError::Conflict => Self::Conflict,
            RepositoryError::NotFound => Self::NotFound,
            RepositoryError::Unavailable => Self::Unavailable,
            RepositoryError::InvalidState => Self::Internal,
        }
    }
}

impl From<SecurityError> for AppError {
    fn from(error: SecurityError) -> Self {
        match error {
            SecurityError::PasswordPolicy => Self::Validation("password policy not met"),
            SecurityError::Random
            | SecurityError::PasswordHash
            | SecurityError::AuthenticatorSecret => Self::Internal,
        }
    }
}

impl From<AddressValidationError> for AppError {
    fn from(error: AddressValidationError) -> Self {
        match error {
            AddressValidationError::AuthorityUnavailable => Self::Unavailable,
            AddressValidationError::Malformed
            | AddressValidationError::WrongAsset
            | AddressValidationError::WrongNetwork
            | AddressValidationError::UnsupportedReceiver => {
                Self::Validation("invalid payout destination")
            }
        }
    }
}

impl From<SignerError> for AppError {
    fn from(_error: SignerError) -> Self {
        Self::Unavailable
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let retry_after = matches!(&self, Self::Busy);
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Sign in required.",
            ),
            Self::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "Credentials were not accepted.",
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "Request was not authorized.",
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "Resource was not found.",
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "conflict",
                "The requested value already exists.",
            ),
            Self::Validation(message) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "invalid_request", message)
            }
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "Required validation service is unavailable.",
            ),
            Self::Busy => (
                StatusCode::TOO_MANY_REQUESTS,
                "busy",
                "Credential capacity is busy. Retry shortly.",
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "The request could not be completed.",
            ),
        };
        let mut response =
            (status, Json(json!({ "error": code, "message": message }))).into_response();
        if retry_after {
            response
                .headers_mut()
                .insert("retry-after", HeaderValue::from_static("1"));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_portal_shows_wcash_automatic_and_zcash_manual() {
        let mut config = PortalConfig::testnet();
        config.network = crate::ChainNetwork::Mainnet;
        config.allow_registration = false;
        let page = render_index(&config);
        let script = render_script(&config);

        assert!(page.contains("ZecWec Pool — Mainnet"));
        assert!(page.contains("· automatic payout"));
        assert!(page.contains("mainnet.zecwec.com:3334"));
        assert!(!page.contains("data-auth-mode=\"register\""));
        assert!(!page.contains("<option value=\"tls\">"));
        assert!(!page.contains("testnet-mine.zecwec.com"));
        assert!(script.contains("const AUTOMATIC_PAYOUT_ENABLED = { wec: true, zec: false };"));
        assert!(script.contains("const TLS_STRATUM_AVAILABLE = false;"));
        assert!(script.contains("stratum+tcp://mainnet.zecwec.com:3334"));
        assert!(!script.contains("testnet-mine.zecwec.com"));

        config.mining_password_ignored = true;
        assert!(render_index(&config).contains("password x"));
        assert!(render_index(&config).contains(">Create worker</button>"));
        assert!(render_script(&config).contains("const MINING_PASSWORD_IGNORED = true;"));

        config.allow_registration = true;
        assert!(render_index(&config).contains("data-auth-mode=\"register\""));
        assert_eq!(
            render_index(&PortalConfig::testnet()),
            include_str!("../assets/index.html")
        );
    }

    #[test]
    fn argon2_slots_reject_excess_work_without_waiting() -> Result<(), &'static str> {
        let slots = Arc::new(Semaphore::new(1));
        let _permit = argon2_operation_slot(&slots).map_err(|_| "first operation rejected")?;
        let error = match argon2_operation_slot(&slots) {
            Err(error) => error,
            Ok(_) => return Err("second operation was admitted"),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get("retry-after"),
            Some(&HeaderValue::from_static("1"))
        );
        Ok(())
    }
}
