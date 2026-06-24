//! Admin authentication for the management API (admin-lite + the `fp` CLI).
//!
//! Multiple admin ACCOUNTS (username + argon2-hashed password) live in the
//! `admin` table — changeable + addable from the UI, persisted across restarts.
//! A fresh DB is seeded with a default `admin` account whose password is
//! `FLUXPEER_ADMIN_PASSWORD` (or a random one, logged once).
//!
//! Two ways to authorize a management request via `Authorization: Bearer <v>`:
//! - a **session token** from `POST /admin/login {username,password}` — what the
//! browser uses, so the password never lives in localStorage; the token also
//! identifies WHICH admin (for change-password);
//! - the **`FLUXPEER_ADMIN_PASSWORD` master key** directly — a break-glass /
//! automation bearer for the `fp` CLI (no per-request argon2 verify).
//!
//! Node/client routes (enroll, config, watch, relay directory) stay open — nodes
//! authenticate with invite codes / device ids.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::extract::{Path, Request};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use axum::{Extension, Json};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::sql_store::SqlStore;

const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);

struct Session {
    username: String,
    expiry: Instant,
}

pub struct Auth {
    store: Arc<SqlStore>,
    /// `FLUXPEER_ADMIN_PASSWORD` — an optional master bearer for CLI/automation.
    master: Option<String>,
    sessions: RwLock<HashMap<String, Session>>,
}

impl Auth {
    pub fn new(store: Arc<SqlStore>) -> Arc<Self> {
        Arc::new(Self {
            store,
            master: std::env::var("FLUXPEER_ADMIN_PASSWORD").ok().filter(|s| !s.is_empty()),
            sessions: RwLock::new(HashMap::new()),
        })
    }

    async fn login(&self, username: &str, password: &str) -> Option<String> {
        let hash = self.store.admin_hash(username).await.ok().flatten()?;
        if !verify_password(password, &hash) {
            return None;
        }
        let token = random_hex(24);
        self.sessions.write().insert(
            token.clone(),
            Session {
                username: username.to_string(),
                expiry: Instant::now() + SESSION_TTL,
            },
        );
        Some(token)
    }

    /// The admin a token belongs to, if live.
    fn session_user(&self, token: &str) -> Option<String> {
        let mut sessions = self.sessions.write();
        match sessions.get(token) {
            Some(s) if s.expiry > Instant::now() => Some(s.username.clone()),
            Some(_) => {
                sessions.remove(token);
                None
            }
            None => None,
        }
    }

    fn bearer(headers: &HeaderMap) -> Option<&str> {
        headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
    }

    /// A bearer authorizes if it's the master key or a live session token.
    fn valid_bearer(&self, bearer: &str) -> bool {
        if let Some(m) = &self.master
            && constant_eq(bearer.as_bytes(), m.as_bytes())
        {
            return true;
        }
        self.session_user(bearer).is_some()
    }

    /// The acting admin username for a request (None for the master key —
    /// account-scoped actions like change-password require a real session).
    fn acting_user(&self, headers: &HeaderMap) -> Option<String> {
        Self::bearer(headers).and_then(|t| self.session_user(t))
    }
}

fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_default()
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

/// `bytes` CSPRNG bytes as lowercase hex. Used for session tokens, generated admin
/// passwords, and **invite codes** (which are bearer credentials — must be
/// unguessable, never sequential).
pub(crate) fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `bearer` is the master automation key (`FLUXPEER_ADMIN_PASSWORD`).
/// Stateless (no session map), so per-device route guards can let an admin
/// automation caller (`fp`/CLI) act on any device without an `Auth` handle. False
/// if no master key is configured. (Interactive admin SESSIONS aren't checked here
/// — they go through the admin-gated routes, not the per-device node endpoints.)
pub(crate) fn is_master_bearer(bearer: &str) -> bool {
    matches!(std::env::var("FLUXPEER_ADMIN_PASSWORD"), Ok(m) if !m.is_empty() && constant_eq(bearer.as_bytes(), m.as_bytes()))
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Seed the default `admin` account on a fresh DB (password = env or generated).
pub async fn ensure_default_admin(store: &SqlStore) {
    if store.count_admins().await.unwrap_or(0) > 0 {
        return;
    }
    let password = std::env::var("FLUXPEER_ADMIN_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let generated = random_hex(9);
            tracing::warn!(
                "default admin 'admin' password (generated — set FLUXPEER_ADMIN_PASSWORD or change it in the UI): {}",
                generated
            );
            generated
        });
    if store
        .create_admin("admin", &hash_password(&password), unix_now())
        .await
        .is_ok()
    {
        tracing::info!("seeded default admin account 'admin'");
    }
}

// ── handlers ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResp {
    token: String,
    username: String,
}

/// `POST /admin/login` — exchange username+password for a session token.
pub async fn admin_login(
    Extension(auth): Extension<Arc<Auth>>,
    Json(req): Json<LoginReq>,
) -> Result<Json<LoginResp>, StatusCode> {
    match auth.login(&req.username, &req.password).await {
        Some(token) => {
            auth.store.record_audit(unix_millis(), &req.username, "login").await;
            Ok(Json(LoginResp {
                token,
                username: req.username,
            }))
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

#[derive(Serialize)]
pub struct MeResp {
    username: String,
}

/// `GET /admin/me` — the acting admin's username ("" for the master key).
pub async fn admin_me(Extension(auth): Extension<Arc<Auth>>, headers: HeaderMap) -> Json<MeResp> {
    Json(MeResp {
        username: auth.acting_user(&headers).unwrap_or_default(),
    })
}

#[derive(Deserialize)]
pub struct ChangePwReq {
    old_password: String,
    new_password: String,
}

/// `POST /admin/password` — change the acting admin's own password.
pub async fn admin_change_password(
    Extension(auth): Extension<Arc<Auth>>,
    headers: HeaderMap,
    Json(req): Json<ChangePwReq>,
) -> StatusCode {
    let Some(user) = auth.acting_user(&headers) else {
        // master-key bearer has no account to change
        return StatusCode::BAD_REQUEST;
    };
    if req.new_password.len() < 4 {
        return StatusCode::BAD_REQUEST;
    }
    let Ok(Some(hash)) = auth.store.admin_hash(&user).await else {
        return StatusCode::BAD_REQUEST;
    };
    if !verify_password(&req.old_password, &hash) {
        return StatusCode::UNAUTHORIZED;
    }
    match auth
        .store
        .update_admin_password(&user, &hash_password(&req.new_password))
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// `GET /admin/admins` — list admin usernames.
pub async fn list_admins(Extension(auth): Extension<Arc<Auth>>) -> Result<Json<Vec<String>>, StatusCode> {
    auth.store
        .list_admins()
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Deserialize)]
pub struct NewAdminReq {
    username: String,
    password: String,
}

/// `POST /admin/admins` — create a new admin account.
pub async fn create_admin(Extension(auth): Extension<Arc<Auth>>, Json(req): Json<NewAdminReq>) -> StatusCode {
    if req.username.trim().is_empty() || req.password.len() < 4 {
        return StatusCode::BAD_REQUEST;
    }
    if auth.store.admin_hash(&req.username).await.ok().flatten().is_some() {
        return StatusCode::CONFLICT;
    }
    match auth
        .store
        .create_admin(&req.username, &hash_password(&req.password), unix_now())
        .await
    {
        Ok(()) => StatusCode::CREATED,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// `DELETE /admin/admins/:username` — remove an admin (not the last, not self).
pub async fn delete_admin(
    Extension(auth): Extension<Arc<Auth>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> StatusCode {
    if auth.acting_user(&headers).as_deref() == Some(username.as_str()) {
        return StatusCode::BAD_REQUEST; // don't lock yourself out
    }
    match auth.store.count_admins().await {
        Ok(n) if n <= 1 => return StatusCode::BAD_REQUEST, // keep at least one
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
        _ => {}
    }
    match auth.store.delete_admin(&username).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// `GET /admin/audit` — recent admin actions (newest first).
pub async fn audit_log(
    Extension(auth): Extension<Arc<Auth>>,
) -> Result<Json<Vec<crate::domain::AuditEntry>>, StatusCode> {
    auth.store
        .recent_audit(200)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Middleware: require a valid bearer on the management routes. Records an audit
/// entry for each successful MUTATION (POST/PUT/DELETE).
pub async fn require_admin(
    Extension(auth): Extension<Arc<Auth>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !Auth::bearer(req.headers()).is_some_and(|t| auth.valid_bearer(t)) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let method = req.method().clone();
    let mutating = matches!(
        method,
        axum::http::Method::POST | axum::http::Method::PUT | axum::http::Method::PATCH | axum::http::Method::DELETE
    );
    let actor = auth
        .acting_user(req.headers())
        .unwrap_or_else(|| "(master)".to_string());
    let path = req.uri().path().to_string();
    let resp = next.run(req).await;
    if mutating && resp.status().is_success() {
        auth.store
            .record_audit(unix_millis(), &actor, &format!("{method} {path}"))
            .await;
    }
    Ok(resp)
}
