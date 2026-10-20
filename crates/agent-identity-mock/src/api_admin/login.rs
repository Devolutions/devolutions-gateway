//! This module serves DVLS's login under `<prefix>/api/v1`, with the operations and models of DVLS's public OpenAPI
//! document, since the management API follows DVLS's public API authentication ([DVLS intent][dvls-intent],
//! "Management API").
//!
//! An application identity's key and secret open a session whose `tokenId` authenticates management API requests until
//! it logs out or its lifetime has passed since its login, however often it is used.
//! The lifetime runs on real time rather than the mock clock, because tests advance the mock clock by days.
//!
//! [dvls-intent]: ../../../../docs/agent-identity/INTENT.DVLS.md#management-api

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State as AxumState;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse as _, Response};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio::time::Instant;
use uuid::Uuid;

use super::{ManagementError, Permissions, TOKEN_ID_HEADER, key_permissions, parse_body};
use crate::app::App;

/// The application identity that logs in to the management API, and the sessions its logins open.
pub struct ManagementLogin {
    app_key: String,
    app_secret: String,
    token_lifetime: Duration,
    /// Sessions by `tokenId`, until they log out.
    sessions: Mutex<HashMap<String, Session>>,
}

struct Session {
    permissions: Permissions,
    logged_in_at: Instant,
}

impl ManagementLogin {
    /// Returns the login of the application identity `app_key` with `app_secret`, whose sessions last `token_lifetime`.
    pub fn new(app_key: String, app_secret: String, token_lifetime: Duration) -> Self {
        Self {
            app_key,
            app_secret,
            token_lifetime,
            sessions: Mutex::default(),
        }
    }

    /// Opens a session for the application key `app_key` and returns its `tokenId`, or `None` when the key or the secret
    /// is wrong.
    async fn open_session(&self, app_key: &str, app_secret: &str) -> Option<String> {
        if app_secret != self.app_secret {
            return None;
        }
        let permissions = key_permissions(&self.app_key, app_key)?;
        let token_id = Uuid::new_v4().to_string();
        let session = Session {
            permissions,
            logged_in_at: Instant::now(),
        };
        self.sessions.lock().await.insert(token_id.clone(), session);
        Some(token_id)
    }

    /// Returns the permissions of the session `token_id` names, or `None` once it has logged out or expired.
    pub(super) async fn session_permissions(&self, token_id: &str) -> Option<Permissions> {
        self.sessions
            .lock()
            .await
            .get(token_id)
            .filter(|session| session.logged_in_at.elapsed() < self.token_lifetime)
            .map(|session| session.permissions)
    }

    async fn close_session(&self, token_id: &str) {
        self.sessions.lock().await.remove(token_id);
    }
}

/// `LoginPublicApi_Login`: opens a session and returns its `tokenId` in a `LoginResult`.
///
/// A body that is not a `LoginParameters` with a non-empty `appKey` and `appSecret` is `400` without a body, and a wrong
/// key or secret is `401`.
pub(super) async fn login(AxumState(app): AxumState<Arc<App>>, body: Bytes) -> Response {
    let Ok(body) = parse_body(&body, &["appKey", "appSecret"]) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let member = |name: &str| body.get(name).and_then(Value::as_str).filter(|text| !text.is_empty());
    let (Some(app_key), Some(app_secret)) = (member("appKey"), member("appSecret")) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match app.login.open_session(app_key, app_secret).await {
        Some(token_id) => Json(json!({ "tokenId": token_id })).into_response(),
        None => ManagementError::status(StatusCode::UNAUTHORIZED, "invalid application key or secret").into_response(),
    }
}

/// `LoginPublicApi_LogOut`: closes the session the `tokenId` header names.
pub(super) async fn logout(AxumState(app): AxumState<Arc<App>>, headers: HeaderMap) -> StatusCode {
    if let Some(token_id) = headers.get(TOKEN_ID_HEADER).and_then(|value| value.to_str().ok()) {
        app.login.close_session(token_id).await;
    }
    StatusCode::OK
}
