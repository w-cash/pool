//! End-to-end HTTP boundary tests using a non-production in-memory repository.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use axum::{
    body::{to_bytes, Body},
    http::{header::SET_COOKIE, Request, StatusCode},
};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha1::Sha1;
use tower::ServiceExt;
use uuid::Uuid;
use wcash_pool_portal::{
    mask_destination, AccountCredential, AddressValidationError, AddressValidator, Asset,
    AuthenticatedSession, BroadcastReceipt, ChainNetwork, Clock, DisabledPayoutSigner,
    IsolatedPayoutSigner, NewSession, PayoutBatchRequest, PayoutPreferenceChange,
    PayoutSettingSummary, PoolDataSource, PortalApp, PortalConfig, PortalRepository, PortalSecrets,
    ProvisionedWorker, ReceiverKind, RepositoryError, RepositoryFuture, SignerError,
    TestnetPayoutBoundary, UnavailablePoolData, ValidatedDestination, WorkerSummary,
};

const ORIGIN: &str = "https://testnet.zecwec.com";
const TEST_CREDENTIAL: &str = "test-only credential 0001";
const FIRST_WEC_DESTINATION: &str = "fixture-wec-destination-00000001";
const SECOND_WEC_DESTINATION: &str = "fixture-wec-destination-00000002";
const WRONG_NETWORK_DESTINATION: &str = "fixture-wrong-network-destination";

#[derive(Default)]
struct FixedClock(AtomicU64);

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone)]
struct SavedSession {
    account_id: Uuid,
    csrf_digest: [u8; 32],
    authenticated_at: u64,
    expires_at: u64,
    idle_expires_at: u64,
    security_version: u64,
}

#[derive(Clone)]
struct PayoutState {
    destination: ValidatedDestination,
    pending: Option<(ValidatedDestination, u64)>,
    threshold_zat: u64,
    automatic: bool,
    revision: u64,
}

#[derive(Default)]
struct MemoryState {
    accounts: HashMap<String, AccountCredential>,
    failed: HashMap<Uuid, u32>,
    sessions: HashMap<[u8; 32], SavedSession>,
    workers: HashMap<Uuid, (Uuid, String, u64, Option<u64>)>,
    payouts: HashMap<(Uuid, Asset), PayoutState>,
}

#[derive(Default)]
struct MemoryRepository(Mutex<MemoryState>);

fn future<T: Send + 'static>(value: Result<T, RepositoryError>) -> RepositoryFuture<'static, T> {
    Box::pin(async move { value })
}

impl PortalRepository for MemoryRepository {
    fn readiness(&self) -> RepositoryFuture<'_, ()> {
        future(Ok(()))
    }

    fn create_account<'a>(
        &'a self,
        id: Uuid,
        username: &'a str,
        password_hash: &'a str,
        _now: u64,
    ) -> RepositoryFuture<'a, ()> {
        let result = match self.0.lock() {
            Ok(state) if state.accounts.contains_key(username) => Err(RepositoryError::Conflict),
            Ok(mut state) => {
                state.accounts.insert(
                    username.to_owned(),
                    AccountCredential {
                        id,
                        username: username.to_owned(),
                        password_hash: password_hash.to_owned(),
                        totp_secret: None,
                        totp_pending: None,
                        totp_pending_expires_at: None,
                        locked_until: None,
                        security_version: 1,
                    },
                );
                Ok(())
            }
            Err(_) => Err(RepositoryError::Unavailable),
        };
        Box::pin(async move { result })
    }

    fn account_by_username<'a>(
        &'a self,
        username: &'a str,
    ) -> RepositoryFuture<'a, Option<AccountCredential>> {
        let result = self
            .0
            .lock()
            .map(|state| state.accounts.get(username).cloned())
            .map_err(|_| RepositoryError::Unavailable);
        Box::pin(async move { result })
    }

    fn record_failed_login(
        &self,
        account_id: Uuid,
        maximum_attempts: u32,
        locked_until: u64,
    ) -> RepositoryFuture<'_, ()> {
        let result = self
            .0
            .lock()
            .map_err(|_| RepositoryError::Unavailable)
            .map(|mut state| {
                let count = state.failed.entry(account_id).or_default();
                *count += 1;
                if *count >= maximum_attempts {
                    if let Some(account) = state
                        .accounts
                        .values_mut()
                        .find(|value| value.id == account_id)
                    {
                        account.locked_until = Some(locked_until);
                    }
                }
            });
        Box::pin(async move { result })
    }

    fn clear_failed_login(&self, account_id: Uuid) -> RepositoryFuture<'_, ()> {
        let result = self
            .0
            .lock()
            .map_err(|_| RepositoryError::Unavailable)
            .map(|mut state| {
                state.failed.remove(&account_id);
                if let Some(account) = state
                    .accounts
                    .values_mut()
                    .find(|value| value.id == account_id)
                {
                    account.locked_until = None;
                }
            });
        Box::pin(async move { result })
    }

    fn create_session(&self, session: NewSession<'_>) -> RepositoryFuture<'_, ()> {
        let saved = SavedSession {
            account_id: session.account_id,
            csrf_digest: *session.csrf_digest,
            authenticated_at: session.authenticated_at,
            expires_at: session.expires_at,
            idle_expires_at: session.idle_expires_at,
            security_version: session.security_version,
        };
        let digest = *session.token_digest;
        let result = self
            .0
            .lock()
            .map_err(|_| RepositoryError::Unavailable)
            .map(|mut state| {
                state.sessions.insert(digest, saved);
            });
        Box::pin(async move { result })
    }

    fn authenticate_session<'a>(
        &'a self,
        token_digest: &'a [u8; 32],
        now: u64,
        new_idle_expiry: u64,
    ) -> RepositoryFuture<'a, Option<AuthenticatedSession>> {
        let result = self
            .0
            .lock()
            .map_err(|_| RepositoryError::Unavailable)
            .map(|mut state| {
                let saved = state.sessions.get(token_digest)?.clone();
                let account = state
                    .accounts
                    .values()
                    .find(|value| value.id == saved.account_id)?;
                let account_security_version = account.security_version;
                let account_username = account.username.clone();
                if saved.expires_at <= now
                    || saved.idle_expires_at <= now
                    || saved.security_version != account_security_version
                {
                    return None;
                }
                if let Some(session) = state.sessions.get_mut(token_digest) {
                    session.idle_expires_at = saved.expires_at.min(new_idle_expiry);
                }
                Some(AuthenticatedSession {
                    account_id: saved.account_id,
                    username: account_username,
                    csrf_digest: saved.csrf_digest,
                    authenticated_at: saved.authenticated_at,
                })
            });
        Box::pin(async move { result })
    }

    fn delete_session<'a>(&'a self, token_digest: &'a [u8; 32]) -> RepositoryFuture<'a, ()> {
        let result = self
            .0
            .lock()
            .map_err(|_| RepositoryError::Unavailable)
            .map(|mut state| {
                state.sessions.remove(token_digest);
            });
        Box::pin(async move { result })
    }

    fn delete_account_sessions(&self, account_id: Uuid) -> RepositoryFuture<'_, ()> {
        let result = self
            .0
            .lock()
            .map_err(|_| RepositoryError::Unavailable)
            .map(|mut state| {
                state
                    .sessions
                    .retain(|_, session| session.account_id != account_id);
            });
        Box::pin(async move { result })
    }

    fn save_pending_totp<'a>(
        &'a self,
        account_id: Uuid,
        sealed_secret: &'a [u8],
        expires_at: u64,
    ) -> RepositoryFuture<'a, ()> {
        let result = self
            .0
            .lock()
            .map_err(|_| RepositoryError::Unavailable)
            .and_then(|mut state| {
                let account = state
                    .accounts
                    .values_mut()
                    .find(|value| value.id == account_id)
                    .ok_or(RepositoryError::NotFound)?;
                account.totp_pending = Some(sealed_secret.to_vec());
                account.totp_pending_expires_at = Some(expires_at);
                Ok(())
            });
        Box::pin(async move { result })
    }

    fn activate_pending_totp(&self, account_id: Uuid, now: u64) -> RepositoryFuture<'_, bool> {
        let result = self
            .0
            .lock()
            .map_err(|_| RepositoryError::Unavailable)
            .map(|mut state| {
                let Some(account) = state
                    .accounts
                    .values_mut()
                    .find(|value| value.id == account_id)
                else {
                    return false;
                };
                if account
                    .totp_pending_expires_at
                    .is_none_or(|expiry| expiry <= now)
                {
                    return false;
                }
                account.totp_secret = account.totp_pending.take();
                account.totp_pending_expires_at = None;
                account.security_version += 1;
                true
            });
        Box::pin(async move { result })
    }

    fn provision_worker<'a>(
        &'a self,
        account_id: Uuid,
        account_login: &'a str,
        worker_label: &'a str,
        now: u64,
    ) -> RepositoryFuture<'a, ProvisionedWorker> {
        let worker_id = Uuid::new_v4();
        let canonical_login = format!("{account_login}.{worker_label}");
        let token = format!("zw1.{}.{}", worker_id.simple(), "a1".repeat(32));
        let result = self
            .0
            .lock()
            .map_err(|_| RepositoryError::Unavailable)
            .and_then(|mut state| {
                if state.workers.values().any(|(owner, label, _, revoked)| {
                    *owner == account_id && label == worker_label && revoked.is_none()
                }) {
                    return Err(RepositoryError::Conflict);
                }
                state
                    .workers
                    .insert(worker_id, (account_id, worker_label.to_owned(), now, None));
                Ok(ProvisionedWorker {
                    account_id,
                    worker_id,
                    canonical_login,
                    token,
                })
            });
        Box::pin(async move { result })
    }

    fn list_workers<'a>(
        &'a self,
        account_id: Uuid,
        account_login: &'a str,
    ) -> RepositoryFuture<'a, Vec<WorkerSummary>> {
        let result = self
            .0
            .lock()
            .map_err(|_| RepositoryError::Unavailable)
            .map(|state| {
                state
                    .workers
                    .iter()
                    .filter(|(_, (owner, _, _, _))| *owner == account_id)
                    .map(|(id, (_, label, created_at, revoked_at))| WorkerSummary {
                        id: *id,
                        label: label.clone(),
                        mining_username: format!("{account_login}.{label}"),
                        created_at: *created_at,
                        revoked_at: *revoked_at,
                    })
                    .collect()
            });
        Box::pin(async move { result })
    }

    fn revoke_worker(
        &self,
        account_id: Uuid,
        worker_id: Uuid,
        now: u64,
    ) -> RepositoryFuture<'_, bool> {
        let result = self
            .0
            .lock()
            .map_err(|_| RepositoryError::Unavailable)
            .map(|mut state| {
                let Some((owner, _, _, revoked)) = state.workers.get_mut(&worker_id) else {
                    return false;
                };
                if *owner != account_id || revoked.is_some() {
                    return false;
                }
                *revoked = Some(now);
                true
            });
        Box::pin(async move { result })
    }

    fn configure_payout(
        &self,
        change: PayoutPreferenceChange<'_>,
    ) -> RepositoryFuture<'_, PayoutSettingSummary> {
        let key = (change.account_id, change.destination.asset());
        let result = self
            .0
            .lock()
            .map_err(|_| RepositoryError::Unavailable)
            .map(|mut state| {
                let entry = state.payouts.entry(key).or_insert_with(|| PayoutState {
                    destination: change.destination.clone(),
                    pending: None,
                    threshold_zat: change.threshold_zat,
                    automatic: change.automatic,
                    revision: 0,
                });
                if entry.destination.canonical_address() != change.destination.canonical_address() {
                    entry.pending = Some((
                        change.destination.clone(),
                        change
                            .changed_at
                            .saturating_add(change.replacement_hold_secs),
                    ));
                }
                entry.threshold_zat = change.threshold_zat;
                entry.automatic = change.automatic;
                entry.revision += 1;
                payout_summary(entry)
            });
        Box::pin(async move { result })
    }

    fn payout_settings(
        &self,
        account_id: Uuid,
        _network: ChainNetwork,
        now: u64,
    ) -> RepositoryFuture<'_, Vec<PayoutSettingSummary>> {
        let result = self
            .0
            .lock()
            .map_err(|_| RepositoryError::Unavailable)
            .map(|mut state| {
                state
                    .payouts
                    .iter_mut()
                    .filter(|((owner, _), _)| *owner == account_id)
                    .map(|(_, payout)| {
                        if payout
                            .pending
                            .as_ref()
                            .is_some_and(|(_, effective)| *effective <= now)
                        {
                            if let Some((destination, _)) = payout.pending.take() {
                                payout.destination = destination;
                            }
                        }
                        payout_summary(payout)
                    })
                    .collect()
            });
        Box::pin(async move { result })
    }

    fn active_payout_destination(
        &self,
        account_id: Uuid,
        asset: Asset,
        _network: ChainNetwork,
        _now: u64,
    ) -> RepositoryFuture<'_, Option<ValidatedDestination>> {
        let result = self
            .0
            .lock()
            .map(|state| {
                state
                    .payouts
                    .get(&(account_id, asset))
                    .map(|value| value.destination.clone())
            })
            .map_err(|_| RepositoryError::Unavailable);
        Box::pin(async move { result })
    }
}

fn payout_summary(state: &PayoutState) -> PayoutSettingSummary {
    PayoutSettingSummary {
        asset: state.destination.asset(),
        network: state.destination.network(),
        active_destination: Some(mask_destination(state.destination.canonical_address())),
        active_receiver: Some(state.destination.receiver_kind()),
        pending_destination: state
            .pending
            .as_ref()
            .map(|(destination, _)| mask_destination(destination.canonical_address())),
        pending_effective_at: state.pending.as_ref().map(|(_, effective)| *effective),
        threshold_zat: state.threshold_zat,
        automatic: state.automatic,
        revision: state.revision,
    }
}

struct FixtureValidator;

impl AddressValidator for FixtureValidator {
    fn readiness(
        &self,
        _asset: Asset,
        network: ChainNetwork,
    ) -> Result<(), AddressValidationError> {
        if network == ChainNetwork::Testnet {
            Ok(())
        } else {
            Err(AddressValidationError::WrongNetwork)
        }
    }

    fn validate(
        &self,
        asset: Asset,
        network: ChainNetwork,
        candidate: &str,
    ) -> Result<ValidatedDestination, AddressValidationError> {
        if candidate == WRONG_NETWORK_DESTINATION {
            return Err(AddressValidationError::WrongNetwork);
        }
        let allowed = matches!(
            (asset, candidate),
            (Asset::Wec, FIRST_WEC_DESTINATION | SECOND_WEC_DESTINATION)
                | (Asset::Zec, "fixture-zec-destination-00000001")
        );
        if !allowed {
            return Err(AddressValidationError::Malformed);
        }
        ValidatedDestination::from_authoritative_validation(
            asset,
            network,
            candidate.to_owned(),
            ReceiverKind::Ironwood,
        )
    }
}

fn fixture_totp(encoded_secret: &str, now: u64) -> String {
    let secret = data_encoding::BASE32_NOPAD
        .decode(encoded_secret.as_bytes())
        .expect("valid fixture secret");
    let mut mac = Hmac::<Sha1>::new_from_slice(&secret).expect("HMAC key");
    mac.update(&(now / 30).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let value = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    format!("{:06}", value % 1_000_000)
}

struct ReadySigner;

impl IsolatedPayoutSigner for ReadySigner {
    fn readiness(&self) -> Result<(), SignerError> {
        Ok(())
    }

    fn sign_and_broadcast(
        &self,
        _request: &PayoutBatchRequest,
    ) -> Result<BroadcastReceipt, SignerError> {
        Err(SignerError::Rejected)
    }
}

fn portal(clock: Arc<FixedClock>) -> axum::Router {
    portal_with_repository(clock, Arc::new(MemoryRepository::default()))
}

fn portal_with_repository(
    clock: Arc<FixedClock>,
    repository: Arc<MemoryRepository>,
) -> axum::Router {
    clock.0.store(1_800_000_000, Ordering::SeqCst);
    PortalApp::with_clock(
        PortalConfig::testnet(),
        PortalSecrets::new([3; 32], [7; 32]),
        repository,
        Arc::new(FixtureValidator),
        Arc::new(UnavailablePoolData),
        Arc::new(TestnetPayoutBoundary::new(Arc::new(ReadySigner))),
        clock,
    )
    .expect("valid test portal")
    .router()
}

async fn register_and_login(app: &axum::Router, username: &str) -> (String, String, String) {
    let registration = app
        .clone()
        .oneshot(mutation(
            "/api/v1/auth/register",
            "POST",
            json!({"username": username, "password": TEST_CREDENTIAL}),
        ))
        .await
        .expect("registration response");
    assert_eq!(registration.status(), StatusCode::CREATED);
    let login = app
        .clone()
        .oneshot(mutation(
            "/api/v1/auth/login",
            "POST",
            json!({"username": username, "password": TEST_CREDENTIAL}),
        ))
        .await
        .expect("login response");
    assert_eq!(login.status(), StatusCode::OK);
    let cookies: Vec<String> = login
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect();
    let session = cookies
        .iter()
        .find(|value| value.starts_with("__Host-zecwec_session="))
        .and_then(|value| value.split(';').next())
        .expect("session cookie")
        .to_owned();
    let csrf_cookie = cookies
        .iter()
        .find(|value| value.starts_with("__Host-zecwec_csrf="))
        .and_then(|value| value.split(';').next())
        .expect("csrf cookie")
        .to_owned();
    let csrf = csrf_cookie.split_once('=').expect("csrf pair").1.to_owned();
    (session, csrf_cookie, csrf)
}

fn authorized_mutation(
    path: &str,
    method: &str,
    body: Value,
    session: &str,
    csrf_cookie: &str,
    csrf: &str,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("origin", ORIGIN)
        .header("cookie", format!("{session}; {csrf_cookie}"))
        .header("x-csrf-token", csrf)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("authorized request")
}

async fn json_response(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("bounded response body");
    serde_json::from_slice(&bytes).expect("JSON response")
}

fn mutation(path: &str, method: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("origin", ORIGIN)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("valid request")
}

#[tokio::test]
async fn static_ui_and_health_are_hardened() {
    let app = portal(Arc::new(FixedClock::default()));
    let response = app
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("content-security-policy").is_some());
    let html = String::from_utf8(
        to_bytes(response.into_body(), 128 * 1024)
            .await
            .expect("body")
            .to_vec(),
    )
    .expect("utf8");
    for page in [
        "Overview", "Workers", "Rewards", "Blocks", "Payouts", "Settings",
    ] {
        assert!(html.contains(page));
    }

    let ready = app
        .oneshot(
            Request::get("/readyz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(ready.status(), StatusCode::OK);
}

#[tokio::test]
async fn account_worker_and_payout_flow_enforces_security_boundaries() {
    let app = portal(Arc::new(FixedClock::default()));
    let registration = app
        .clone()
        .oneshot(mutation(
            "/api/v1/auth/register",
            "POST",
            json!({"username":"testminer","password":"test-only credential 0001"}),
        ))
        .await
        .expect("registration response");
    assert_eq!(registration.status(), StatusCode::CREATED);

    let login = app
        .clone()
        .oneshot(mutation(
            "/api/v1/auth/login",
            "POST",
            json!({"username":"testminer","password":"test-only credential 0001"}),
        ))
        .await
        .expect("login response");
    assert_eq!(login.status(), StatusCode::OK);
    let cookies: Vec<String> = login
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect();
    assert_eq!(cookies.len(), 2);
    assert!(cookies.iter().any(|value| {
        value.starts_with("__Host-zecwec_session=")
            && value.contains("HttpOnly")
            && value.contains("SameSite=Strict")
            && value.contains("Secure")
    }));
    let session = cookies
        .iter()
        .find(|value| value.starts_with("__Host-zecwec_session="))
        .and_then(|value| value.split(';').next())
        .expect("session cookie")
        .to_owned();
    let csrf_cookie = cookies
        .iter()
        .find(|value| value.starts_with("__Host-zecwec_csrf="))
        .and_then(|value| value.split(';').next())
        .expect("csrf cookie")
        .to_owned();
    let csrf = csrf_cookie.split_once('=').expect("csrf pair").1.to_owned();
    let login_body = json_response(login).await;
    assert_eq!(login_body["csrf_token"], csrf);
    assert!(!login_body.to_string().contains("test-only credential"));

    let no_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/workers")
                .header("origin", ORIGIN)
                .header("cookie", &session)
                .header("content-type", "application/json")
                .body(Body::from(json!({"label":"z15-01"}).to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);

    let wrong_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/workers")
                .header("origin", ORIGIN)
                .header("cookie", format!("{session}; {csrf_cookie}"))
                .header("x-csrf-token", "zc_invalid-test-token")
                .header("content-type", "application/json")
                .body(Body::from(json!({"label":"z15-01"}).to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(wrong_csrf.status(), StatusCode::FORBIDDEN);

    let worker_request = Request::builder()
        .method("POST")
        .uri("/api/v1/workers")
        .header("origin", ORIGIN)
        .header("cookie", format!("{session}; {csrf_cookie}"))
        .header("x-csrf-token", &csrf)
        .header("content-type", "application/json")
        .body(Body::from(json!({"label":"z15-01"}).to_string()))
        .expect("worker request");
    let created = app
        .clone()
        .oneshot(worker_request)
        .await
        .expect("worker response");
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_body = json_response(created).await;
    let token = created_body["worker"]["token"]
        .as_str()
        .expect("one-time token");
    assert!(token.starts_with("zw1."));

    let workers = app
        .clone()
        .oneshot(
            Request::get("/api/v1/workers")
                .header("cookie", &session)
                .body(Body::empty())
                .expect("workers request"),
        )
        .await
        .expect("workers response");
    let workers_body = json_response(workers).await;
    assert!(!workers_body.to_string().contains(token));
    assert_eq!(
        workers_body["workers"][0]["mining_username"],
        "testminer.z15-01"
    );

    let payout = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings/payouts/wec")
        .header("origin", ORIGIN)
        .header("cookie", format!("{session}; {csrf_cookie}"))
        .header("x-csrf-token", &csrf)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "destination": FIRST_WEC_DESTINATION,
                "threshold_zat": 100_000,
                "automatic": true,
                "password": "test-only credential 0001"
            })
            .to_string(),
        ))
        .expect("payout request");
    let payout = app.clone().oneshot(payout).await.expect("payout response");
    assert_eq!(payout.status(), StatusCode::OK);
    let payout_body = json_response(payout).await;
    assert_eq!(
        payout_body["active_destination"],
        mask_destination(FIRST_WEC_DESTINATION)
    );
    assert!(!payout_body.to_string().contains(FIRST_WEC_DESTINATION));

    let replacement = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings/payouts/wec")
        .header("origin", ORIGIN)
        .header("cookie", format!("{session}; {csrf_cookie}"))
        .header("x-csrf-token", &csrf)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "destination": SECOND_WEC_DESTINATION,
                "threshold_zat": 200_000,
                "automatic": true,
                "password": "test-only credential 0001"
            })
            .to_string(),
        ))
        .expect("replacement request");
    let replacement = app
        .oneshot(replacement)
        .await
        .expect("replacement response");
    let replacement_body = json_response(replacement).await;
    assert_eq!(
        replacement_body["pending_destination"],
        mask_destination(SECOND_WEC_DESTINATION)
    );
    assert!(replacement_body["pending_effective_at"].as_u64().is_some());
}

#[test]
fn mainnet_router_is_disabled() {
    let mut config = PortalConfig::testnet();
    config.network = ChainNetwork::Mainnet;
    config.canonical_origin = "https://pool.zecwec.com".to_owned();
    let result = PortalApp::with_clock(
        config,
        PortalSecrets::new([3; 32], [7; 32]),
        Arc::new(MemoryRepository::default()),
        Arc::new(FixtureValidator),
        Arc::new(UnavailablePoolData),
        Arc::new(TestnetPayoutBoundary::new(Arc::new(ReadySigner))),
        Arc::new(FixedClock::default()),
    );
    assert!(result.is_err());
}

#[test]
fn unavailable_overview_is_explicit() {
    let overview = UnavailablePoolData.overview();
    assert!(!overview.available);
    assert_eq!(overview.hashrate_sol_s, None);
}

#[tokio::test]
async fn readiness_fails_closed_without_signer() {
    let clock = Arc::new(FixedClock::default());
    clock.0.store(1_800_000_000, Ordering::SeqCst);
    let app = PortalApp::with_clock(
        PortalConfig::testnet(),
        PortalSecrets::new([3; 32], [7; 32]),
        Arc::new(MemoryRepository::default()),
        Arc::new(FixtureValidator),
        Arc::new(UnavailablePoolData),
        Arc::new(TestnetPayoutBoundary::new(Arc::new(DisabledPayoutSigner))),
        clock,
    )
    .expect("valid disabled portal")
    .router();
    let response = app
        .oneshot(
            Request::get("/readyz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn mutations_reject_origin_csrf_unknown_fields_and_oversized_bodies() {
    let app = portal(Arc::new(FixedClock::default()));
    let missing_origin = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"username":"origincheck","password":TEST_CREDENTIAL}).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(missing_origin.status(), StatusCode::FORBIDDEN);

    let wrong_origin = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/register")
                .header("origin", "https://invalid.example")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"username":"origincheck","password":TEST_CREDENTIAL}).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(wrong_origin.status(), StatusCode::FORBIDDEN);

    let unknown_field = app
        .clone()
        .oneshot(mutation(
            "/api/v1/auth/register",
            "POST",
            json!({"username":"fieldcheck","password":TEST_CREDENTIAL,"unexpected":true}),
        ))
        .await
        .expect("response");
    assert_eq!(unknown_field.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let oversized = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/register")
                .header("origin", ORIGIN)
                .header("content-type", "application/json")
                .body(Body::from("x".repeat(17 * 1024)))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn sessions_fail_closed_on_absolute_idle_and_security_version_expiry() {
    let repository = Arc::new(MemoryRepository::default());
    let app = portal_with_repository(Arc::new(FixedClock::default()), repository.clone());
    let (absolute_cookie, _, _) = register_and_login(&app, "absoluteexpiry").await;
    let (idle_cookie, _, _) = register_and_login(&app, "idleexpiry").await;
    let (version_cookie, _, _) = register_and_login(&app, "versionexpiry").await;

    {
        let mut state = repository.0.lock().expect("repository lock");
        let absolute_id = state.accounts["absoluteexpiry"].id;
        let idle_id = state.accounts["idleexpiry"].id;
        let version_id = state.accounts["versionexpiry"].id;
        for session in state.sessions.values_mut() {
            if session.account_id == absolute_id {
                session.expires_at = 1_800_000_000;
            } else if session.account_id == idle_id {
                session.idle_expires_at = 1_800_000_000;
            }
        }
        state
            .accounts
            .values_mut()
            .find(|account| account.id == version_id)
            .expect("version account")
            .security_version += 1;
    }

    for cookie in [absolute_cookie, idle_cookie, version_cookie] {
        let response = app
            .clone()
            .oneshot(
                Request::get("/api/v1/me")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn login_lock_and_payout_reauthentication_fail_closed() {
    let app = portal(Arc::new(FixedClock::default()));
    let (session, csrf_cookie, csrf) = register_and_login(&app, "lockedminer").await;
    for _ in 0..5 {
        let response = app
            .clone()
            .oneshot(mutation(
                "/api/v1/auth/login",
                "POST",
                json!({"username":"lockedminer","password":"wrong test credential"}),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let locked = app
        .clone()
        .oneshot(mutation(
            "/api/v1/auth/login",
            "POST",
            json!({"username":"lockedminer","password":TEST_CREDENTIAL}),
        ))
        .await
        .expect("response");
    assert_eq!(locked.status(), StatusCode::UNAUTHORIZED);

    let payout = app
        .oneshot(authorized_mutation(
            "/api/v1/settings/payouts/wec",
            "PUT",
            json!({
                "destination":FIRST_WEC_DESTINATION,
                "threshold_zat":100,
                "automatic":true,
                "password":"wrong test credential"
            }),
            &session,
            &csrf_cookie,
            &csrf,
        ))
        .await
        .expect("response");
    assert_eq!(payout.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn worker_revocation_is_scoped_to_its_owner() {
    let app = portal(Arc::new(FixedClock::default()));
    let (owner_session, owner_csrf_cookie, owner_csrf) =
        register_and_login(&app, "workerowner").await;
    let created = app
        .clone()
        .oneshot(authorized_mutation(
            "/api/v1/workers",
            "POST",
            json!({"label":"z15-owner"}),
            &owner_session,
            &owner_csrf_cookie,
            &owner_csrf,
        ))
        .await
        .expect("response");
    let worker_id = json_response(created).await["worker"]["id"]
        .as_str()
        .expect("worker id")
        .to_owned();
    let (other_session, other_csrf_cookie, other_csrf) =
        register_and_login(&app, "otherminer").await;
    let response = app
        .oneshot(authorized_mutation(
            &format!("/api/v1/workers/{worker_id}"),
            "DELETE",
            json!({}),
            &other_session,
            &other_csrf_cookie,
            &other_csrf,
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn wrong_network_destination_is_rejected_after_reauthentication() {
    let app = portal(Arc::new(FixedClock::default()));
    let (session, csrf_cookie, csrf) = register_and_login(&app, "networkcheck").await;
    let response = app
        .oneshot(authorized_mutation(
            "/api/v1/settings/payouts/wec",
            "PUT",
            json!({
                "destination":WRONG_NETWORK_DESTINATION,
                "threshold_zat":100,
                "automatic":true,
                "password":TEST_CREDENTIAL
            }),
            &session,
            &csrf_cookie,
            &csrf,
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn totp_enrollment_rejects_invalid_expired_and_replayed_confirmation() {
    let clock = Arc::new(FixedClock::default());
    let app = portal(clock.clone());
    let (session, csrf_cookie, csrf) = register_and_login(&app, "totpinvalid").await;
    let begin = app
        .clone()
        .oneshot(authorized_mutation(
            "/api/v1/security/totp/begin",
            "POST",
            json!({"password":TEST_CREDENTIAL}),
            &session,
            &csrf_cookie,
            &csrf,
        ))
        .await
        .expect("begin response");
    let begin_body = json_response(begin).await;
    let correct = fixture_totp(
        begin_body["secret_base32"]
            .as_str()
            .expect("secret encoding"),
        clock.now(),
    );
    let invalid = if correct == "000000" {
        "000001"
    } else {
        "000000"
    };
    let invalid_response = app
        .clone()
        .oneshot(authorized_mutation(
            "/api/v1/security/totp/confirm",
            "POST",
            json!({"code":invalid}),
            &session,
            &csrf_cookie,
            &csrf,
        ))
        .await
        .expect("invalid response");
    assert_eq!(invalid_response.status(), StatusCode::UNAUTHORIZED);

    clock.0.fetch_add(601, Ordering::SeqCst);
    let expired_response = app
        .clone()
        .oneshot(authorized_mutation(
            "/api/v1/security/totp/confirm",
            "POST",
            json!({"code":correct}),
            &session,
            &csrf_cookie,
            &csrf,
        ))
        .await
        .expect("expired response");
    assert_eq!(expired_response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let (valid_session, valid_csrf_cookie, valid_csrf) =
        register_and_login(&app, "totpvalid").await;
    let valid_begin = app
        .clone()
        .oneshot(authorized_mutation(
            "/api/v1/security/totp/begin",
            "POST",
            json!({"password":TEST_CREDENTIAL}),
            &valid_session,
            &valid_csrf_cookie,
            &valid_csrf,
        ))
        .await
        .expect("begin response");
    let valid_body = json_response(valid_begin).await;
    let valid_code = fixture_totp(
        valid_body["secret_base32"]
            .as_str()
            .expect("secret encoding"),
        clock.now(),
    );
    let confirmation = app
        .clone()
        .oneshot(authorized_mutation(
            "/api/v1/security/totp/confirm",
            "POST",
            json!({"code":valid_code}),
            &valid_session,
            &valid_csrf_cookie,
            &valid_csrf,
        ))
        .await
        .expect("confirmation response");
    assert_eq!(confirmation.status(), StatusCode::OK);
    let replay = app
        .oneshot(authorized_mutation(
            "/api/v1/security/totp/confirm",
            "POST",
            json!({"code":valid_code}),
            &valid_session,
            &valid_csrf_cookie,
            &valid_csrf,
        ))
        .await
        .expect("replay response");
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}
