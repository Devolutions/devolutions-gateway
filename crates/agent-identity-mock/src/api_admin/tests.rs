//! Each test cites the operation (by `operationId`) or schema of DVLS's OpenAPI document that it pins.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rstest::rstest;
use serde_json::{Value, json};
use tower::ServiceExt as _;
use uuid::Uuid;

use super::{BASE_PATH, Permission, Permissions, TOKEN_ID_HEADER, credential_permissions, router};
use crate::app::{App, rfc3339};
use crate::state::{State, StreamPush};

const ADMIN: &str = "admin";
const DAY: i64 = 24 * 3600;

/// Returns an app whose clock is frozen at its current second, and that second.
fn frozen_app() -> anyhow::Result<(Arc<App>, i64)> {
    let app = App::for_test()?;
    let now = app.now();
    app.clock.freeze_at(now);
    Ok((app, now))
}

/// Sends a management API request and returns the status and the JSON body, `null` when empty.
async fn send(
    app: &Arc<App>,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<String>,
) -> anyhow::Result<(u16, Value)> {
    let mut request = Request::builder().method(method).uri(format!("{BASE_PATH}{path}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = request.body(body.map_or_else(Body::empty, Body::from))?;
    let response = router(Arc::clone(app)).oneshot(request).await?;
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, body))
}

/// Sends a request with the full-permission credential and an optional JSON body.
async fn call(app: &Arc<App>, method: Method, path: &str, body: Option<Value>) -> anyhow::Result<(u16, Value)> {
    send(
        app,
        method,
        path,
        &[(TOKEN_ID_HEADER, ADMIN)],
        body.map(|body| body.to_string()),
    )
    .await
}

/// Returns the `field` of each `PublicApiFieldError` in a `PublicApiValidationError`.
fn error_fields(body: &Value) -> Vec<Value> {
    body["errors"]
        .as_array()
        .expect("PublicApiValidationError has errors")
        .iter()
        .map(|error| {
            assert!(error["message"].is_string(), "PublicApiFieldError has a message");
            error["field"].clone()
        })
        .collect()
}

/// Asserts a `PublicApiError` body: exactly one string `message`.
fn assert_public_api_error(body: &Value) {
    let members = body.as_object().expect("PublicApiError is an object");
    assert_eq!(members.len(), 1, "{body}");
    assert!(members["message"].is_string(), "{body}");
}

/// Enrolls an identity with the CSR test vector and `metadata`, as the agent-facing enroll does.
/// An app holds at most one, since a key is enrolled once.
async fn enroll(app: &Arc<App>, metadata: Value) -> anyhow::Result<Uuid> {
    let vectors: Value = serde_json::from_str(include_str!("../../../../docs/agent-identity/test-vectors.json"))?;
    let csr = STANDARD.decode(vectors["csr"]["valid"]["csr"].as_str().expect("valid CSR vector"))?;
    let now = app.now();
    let mut state = app.state.lock().await;
    let (_, secret) = state.create_token("test".to_owned(), 1, now + DAY, None, None, now);
    let metadata = metadata.as_object().cloned().expect("metadata is an object");
    Ok(state
        .enroll(&secret, &csr, metadata, now, &app.base_url)
        .expect("enrollment succeeds")
        .identity_id)
}

async fn create_token(app: &Arc<App>, body: Value) -> anyhow::Result<String> {
    let (status, created) = call(app, Method::POST, "/enrollment-token", Some(body)).await?;
    assert_eq!(status, 201, "{created}");
    Ok(created["enrollmentToken"]["id"].as_str().expect("token ID").to_owned())
}

fn names(page: &Value) -> Vec<&str> {
    page["data"]
        .as_array()
        .expect("page data")
        .iter()
        .map(|item| item["name"].as_str().expect("token name"))
        .collect()
}

fn config_entries(count: usize) -> Value {
    (0..count).map(|i| (format!("key_{i}"), json!("v"))).collect()
}

// ==== Authentication and permissions ====

#[rstest]
#[case::admin_token("admin", &[Permission::View, Permission::Manage, Permission::Revoke, Permission::RotateRoot])]
#[case::unprivileged("admin-unprivileged", &[])]
#[case::scope_none("admin.none", &[])]
#[case::scope_one("admin.rotate-root", &[Permission::RotateRoot])]
#[case::scope_several("admin.view+revoke", &[Permission::View, Permission::Revoke])]
fn credential_holds_its_permissions(#[case] credential: &str, #[case] expected: &[Permission]) {
    let held = credential_permissions("admin", credential).expect("credential is valid");
    let held: Vec<Permission> = Permission::ALL.into_iter().filter(|p| held.contains(*p)).collect();
    assert_eq!(held, expected);
}

#[rstest]
#[case::empty("")]
#[case::other_secret("other")]
#[case::longer_secret("admin2")]
#[case::empty_scope("admin.")]
#[case::unknown_permission("admin.view+audit")]
#[case::trailing_separator("admin.view+")]
#[case::display_name("admin.View")]
fn invalid_credential_is_refused(#[case] credential: &str) {
    assert_eq!(credential_permissions("admin", credential), None::<Permissions>);
}

/// Each operation's `403` response in DVLS's OpenAPI document names the permission the operation requires.
#[rstest]
#[case::get_identities(Method::GET, "", "view", "manage+revoke+rotate-root", "AgentIdentityView")]
#[case::get_identity(Method::GET, "/{id}", "view", "manage+revoke+rotate-root", "AgentIdentityView")]
#[case::patch_identity(Method::PATCH, "/{id}", "manage", "view+revoke+rotate-root", "AgentIdentityManage")]
#[case::delete_identity(Method::DELETE, "/{id}", "manage", "view+revoke+rotate-root", "AgentIdentityManage")]
#[case::revoke_identity(
    Method::POST,
    "/{id}/revoke",
    "revoke",
    "view+manage+rotate-root",
    "AgentIdentityRevoke"
)]
#[case::request_renewal(
    Method::POST,
    "/{id}/request-renewal",
    "manage",
    "view+revoke+rotate-root",
    "AgentIdentityManage"
)]
#[case::create_token(
    Method::POST,
    "/enrollment-token",
    "manage",
    "view+revoke+rotate-root",
    "AgentIdentityManage"
)]
#[case::get_tokens(
    Method::GET,
    "/enrollment-token",
    "view",
    "manage+revoke+rotate-root",
    "AgentIdentityView"
)]
#[case::get_token(
    Method::GET,
    "/enrollment-token/{id}",
    "view",
    "manage+revoke+rotate-root",
    "AgentIdentityView"
)]
#[case::delete_token(
    Method::DELETE,
    "/enrollment-token/{id}",
    "manage",
    "view+revoke+rotate-root",
    "AgentIdentityManage"
)]
#[case::get_rotation(Method::GET, "/rotation", "view", "manage+revoke+rotate-root", "AgentIdentityView")]
#[case::start_rotation(
    Method::POST,
    "/rotation",
    "rotate-root",
    "view+manage+revoke",
    "AgentIdentityRotateRoot"
)]
#[case::get_settings(Method::GET, "/settings", "view", "manage+revoke+rotate-root", "AgentIdentityView")]
#[case::patch_settings(
    Method::PATCH,
    "/settings",
    "manage",
    "view+revoke+rotate-root",
    "AgentIdentityManage"
)]
#[tokio::test]
async fn operation_requires_its_permission(
    #[case] method: Method,
    #[case] route: &str,
    #[case] required: &str,
    #[case] all_others: &str,
    #[case] permission_name: &str,
) -> anyhow::Result<()> {
    let app = App::for_test()?;
    let path = route.replace("{id}", &Uuid::new_v4().to_string());

    let refused = format!("{ADMIN}.{all_others}");
    let (status, body) = send(&app, method.clone(), &path, &[(TOKEN_ID_HEADER, &refused)], None).await?;
    assert_eq!(status, 403);
    assert_public_api_error(&body);
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|message| message.contains(permission_name)),
        "{body}"
    );

    let granted = format!("{ADMIN}.{required}");
    let (status, _) = send(&app, method, &path, &[(TOKEN_ID_HEADER, &granted)], None).await?;
    assert!(!matches!(status, 401 | 403), "{status}");
    Ok(())
}

/// The `tokenId` header carries the credential; header names are case-insensitive (RFC 9110, "5.1. Field Names").
#[rstest]
#[case::token_id("tokenId")]
#[case::lowercase("tokenid")]
#[case::uppercase("TOKENID")]
#[tokio::test]
async fn token_id_header_authenticates(#[case] header: &str) -> anyhow::Result<()> {
    let app = App::for_test()?;
    let (status, _) = send(&app, Method::GET, "/settings", &[(header, ADMIN)], None).await?;
    assert_eq!(status, 200);
    Ok(())
}

/// Each operation's `401` response: "Missing or invalid token", with a `PublicApiError` body.
#[rstest]
#[case::missing(&[])]
#[case::bearer_authorization(&[("authorization", "Bearer admin")])]
#[case::unknown_credential(&[("tokenId", "other")])]
#[case::repeated_header(&[("tokenId", "admin"), ("tokenId", "admin")])]
#[tokio::test]
async fn missing_or_invalid_token_is_401(#[case] headers: &[(&str, &str)]) -> anyhow::Result<()> {
    let app = App::for_test()?;
    let (status, body) = send(&app, Method::GET, "/settings", headers, None).await?;
    assert_eq!(status, 401);
    assert_public_api_error(&body);
    Ok(())
}

// ==== Enrollment tokens ====

/// `AgentIdentityPublicApi_CreateAgentIdentityEnrollmentToken` returns `201` with an
/// `AgentIdentityEnrollmentTokenCreated`, whose token `GetAgentIdentityEnrollmentToken` never returns.
/// `expiresOn` defaults to 90 days ahead, and a token without a friendly-name format or config omits them.
#[tokio::test]
async fn create_token_returns_the_full_token_only_once() -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    let (status, created) = call(
        &app,
        Method::POST,
        "/enrollment-token",
        Some(json!({ "name": "build agents", "maxUses": 5 })),
    )
    .await?;
    assert_eq!(status, 201);
    assert_eq!(created.as_object().map(serde_json::Map::len), Some(2));
    // CONTRACT.md §2: an enrollment token is `dvaet1.<bag>.<secret>`.
    assert!(
        created["token"]
            .as_str()
            .is_some_and(|token| token.starts_with("dvaet1.")),
        "{created}"
    );
    let id = created["enrollmentToken"]["id"].as_str().expect("token ID");
    let expected = json!({
        "id": id,
        "name": "build agents",
        "maxUses": 5,
        "useCount": 0,
        "expiresOn": rfc3339(now + 90 * DAY),
        "state": "Active",
        "createdOn": rfc3339(now),
        "createdBy": "mock-admin",
    });
    assert_eq!(created["enrollmentToken"], expected);

    let (status, read) = call(&app, Method::GET, &format!("/enrollment-token/{id}"), None).await?;
    assert_eq!((status, read), (200, expected));
    Ok(())
}

/// `AgentIdentityEnrollmentToken.friendlyNameFormat` and `config` echo the created token's.
#[tokio::test]
async fn create_token_keeps_its_format_and_config() -> anyhow::Result<()> {
    let app = App::for_test()?;
    let body = json!({
        "name": "t",
        "maxUses": 1,
        "friendlyNameFormat": "{hostname}-{os_name}",
        "config": { "site": "paris" },
    });
    let (status, created) = call(&app, Method::POST, "/enrollment-token", Some(body)).await?;
    assert_eq!(status, 201);
    assert_eq!(created["enrollmentToken"]["friendlyNameFormat"], "{hostname}-{os_name}");
    assert_eq!(created["enrollmentToken"]["config"], json!({ "site": "paris" }));
    Ok(())
}

/// `AgentIdentityEnrollmentTokenCreateDTO`'s limits, at their bounds.
#[rstest]
#[case::max_uses(|_| json!({ "name": "t", "maxUses": 1_000_000 }))]
#[case::expiry_365_days_ahead(|now| json!({ "name": "t", "maxUses": 1, "expiresOn": rfc3339(now + 365 * DAY) }))]
#[case::name_255_scalar_values(|_| json!({ "name": "é".repeat(255), "maxUses": 1 }))]
#[case::format_1024_scalar_values(|_| json!({ "name": "t", "maxUses": 1, "friendlyNameFormat": "é".repeat(1024) }))]
#[case::config_32_entries(|_| json!({ "name": "t", "maxUses": 1, "config": config_entries(32) }))]
#[case::config_key_64_bytes(|_| json!({ "name": "t", "maxUses": 1, "config": { "k".repeat(64): "v" } }))]
#[case::config_value_1024_bytes(|_| json!({ "name": "t", "maxUses": 1, "config": { "site": "v".repeat(1024) } }))]
#[tokio::test]
async fn create_token_accepts_its_bounds(#[case] body: fn(i64) -> Value) -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    let (status, created) = call(&app, Method::POST, "/enrollment-token", Some(body(now))).await?;
    assert_eq!(status, 201, "{created}");
    Ok(())
}

/// `AgentIdentityPublicApi_CreateAgentIdentityEnrollmentToken`'s `400`: invalid parameters, including a friendly-name
/// format with an unpaired brace or an unknown placeholder, reported in a `PublicApiValidationError`.
#[rstest]
#[case::missing_name(|_| json!({ "maxUses": 1 }), "name")]
#[case::blank_name(|_| json!({ "name": "  ", "maxUses": 1 }), "name")]
#[case::name_256_scalar_values(|_| json!({ "name": "n".repeat(256), "maxUses": 1 }), "name")]
#[case::missing_max_uses(|_| json!({ "name": "t" }), "maxUses")]
#[case::zero_uses(|_| json!({ "name": "t", "maxUses": 0 }), "maxUses")]
#[case::too_many_uses(|_| json!({ "name": "t", "maxUses": 1_000_001 }), "maxUses")]
#[case::expiry_now(|now| json!({ "name": "t", "maxUses": 1, "expiresOn": rfc3339(now) }), "expiresOn")]
#[case::expiry_beyond_365_days(
    |now| json!({ "name": "t", "maxUses": 1, "expiresOn": rfc3339(now + 365 * DAY + 1) }),
    "expiresOn"
)]
#[case::expiry_not_a_date_time(|_| json!({ "name": "t", "maxUses": 1, "expiresOn": "soon" }), "expiresOn")]
#[case::unpaired_brace(
    |_| json!({ "name": "t", "maxUses": 1, "friendlyNameFormat": "{hostname" }),
    "friendlyNameFormat"
)]
#[case::unknown_placeholder(
    |_| json!({ "name": "t", "maxUses": 1, "friendlyNameFormat": "{nope}" }),
    "friendlyNameFormat"
)]
#[case::format_1025_scalar_values(
    |_| json!({ "name": "t", "maxUses": 1, "friendlyNameFormat": "é".repeat(1025) }),
    "friendlyNameFormat"
)]
#[case::config_not_an_object(|_| json!({ "name": "t", "maxUses": 1, "config": "site=paris" }), "config")]
#[case::config_33_entries(|_| json!({ "name": "t", "maxUses": 1, "config": config_entries(33) }), "config")]
#[case::config_reserved_key(
    |_| json!({ "name": "t", "maxUses": 1, "config": { "agent_channel_url": "https://elsewhere.example" } }),
    "config.agent_channel_url"
)]
#[case::config_uppercase_key(|_| json!({ "name": "t", "maxUses": 1, "config": { "Site": "x" } }), "config.Site")]
#[case::config_key_with_a_dash(|_| json!({ "name": "t", "maxUses": 1, "config": { "site-id": "x" } }), "config.site-id")]
#[case::config_number_value(|_| json!({ "name": "t", "maxUses": 1, "config": { "site": 1 } }), "config.site")]
#[case::config_control_character(
    |_| json!({ "name": "t", "maxUses": 1, "config": { "site": "a\u{1}b" } }),
    "config.site"
)]
#[case::config_value_1025_bytes(
    |_| json!({ "name": "t", "maxUses": 1, "config": { "site": "v".repeat(1025) } }),
    "config.site"
)]
#[case::unknown_member(|now| json!({ "name": "t", "maxUses": 1, "expiresAt": rfc3339(now + DAY) }), "expiresAt")]
#[tokio::test]
async fn create_token_refuses_an_invalid_member(
    #[case] body: fn(i64) -> Value,
    #[case] field: &str,
) -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    let (status, refused) = call(&app, Method::POST, "/enrollment-token", Some(body(now))).await?;
    assert_eq!(status, 400);
    assert_eq!(error_fields(&refused), [json!(field)]);
    Ok(())
}

/// `AgentIdentityEnrollmentTokenCreateDTO.config` keys match `^[a-z][a-z0-9_]{0,63}$`, so at most 64 bytes.
#[tokio::test]
async fn create_token_refuses_a_65_byte_config_key() -> anyhow::Result<()> {
    let app = App::for_test()?;
    let key = "k".repeat(65);
    let body = json!({ "name": "t", "maxUses": 1, "config": { key.clone(): "v" } });
    let (status, refused) = call(&app, Method::POST, "/enrollment-token", Some(body)).await?;
    assert_eq!(status, 400);
    assert_eq!(error_fields(&refused), [json!(format!("config.{key}"))]);
    Ok(())
}

/// Management API bodies follow the agent-facing body rule ([CONTRACT.md][contract], "1. Protocol conventions"), which
/// refuses a member name repeated at any depth, as the mock's README states.
///
/// [contract]: ../../../../docs/agent-identity/CONTRACT.md#1-protocol-conventions
#[rstest]
#[case::distinct_members(r#"{"flag":"first","other":"second"}"#, 201)]
#[case::repeated_member(r#"{"flag":"first","flag":"second"}"#, 400)]
#[tokio::test]
async fn create_token_refuses_a_repeated_member_name(
    #[case] config: &str,
    #[case] expected: u16,
) -> anyhow::Result<()> {
    let app = App::for_test()?;
    let body = format!(r#"{{"name":"t","maxUses":1,"config":{config}}}"#);
    let (status, _) = send(
        &app,
        Method::POST,
        "/enrollment-token",
        &[(TOKEN_ID_HEADER, ADMIN)],
        Some(body),
    )
    .await?;
    assert_eq!(status, expected);
    Ok(())
}

/// `AgentIdentityPublicApi_CreateAgentIdentityEnrollmentToken`: "The first token also creates the Agent Identity root".
#[tokio::test]
async fn first_token_creates_the_root() -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    app.state.lock().await.reset(now, false)?;
    create_token(&app, json!({ "name": "t", "maxUses": 1 })).await?;
    let state = app.state.lock().await;
    assert_eq!(state.roots.iter().filter(|root| root.published).count(), 1);
    Ok(())
}

/// `AgentIdentityPublicApi_CreateAgentIdentityEnrollmentToken`'s `409`: "The first root cannot be created because the
/// data encryption key is unavailable".
#[tokio::test]
async fn first_root_without_the_encryption_key_is_a_conflict() -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    {
        let mut state = app.state.lock().await;
        state.reset(now, false)?;
        state.faults.root_key_unavailable = true;
    }
    let (status, body) = call(
        &app,
        Method::POST,
        "/enrollment-token",
        Some(json!({ "name": "t", "maxUses": 1 })),
    )
    .await?;
    assert_eq!(status, 409);
    assert_public_api_error(&body);
    assert!(app.state.lock().await.tokens.is_empty());
    Ok(())
}

/// `AgentIdentityPublicApi_GetAgentIdentityEnrollmentTokens` returns a `PagedResultOfAgentIdentityEnrollmentToken`.
#[tokio::test]
async fn list_tokens_returns_a_page() -> anyhow::Result<()> {
    let app = App::for_test()?;
    for name in ["c", "a", "b"] {
        create_token(&app, json!({ "name": name, "maxUses": 1 })).await?;
    }
    let (status, page) = call(&app, Method::GET, "/enrollment-token?pageSize=2&pageNumber=2", None).await?;
    assert_eq!(status, 200);
    assert_eq!(names(&page), ["b"]);
    assert_eq!(
        (
            &page["currentPage"],
            &page["pageSize"],
            &page["totalCount"],
            &page["totalPage"]
        ),
        (&json!(2), &json!(2), &json!(3), &json!(2))
    );
    Ok(())
}

/// `AgentIdentityPublicApi_GetAgentIdentityEnrollmentTokens`' `sortField` (`createdOn`, `name` or `expiresOn`, by
/// default `createdOn`) and `sortOrder` (1 ascending by default, 0 descending).
#[rstest]
#[case::default("", ["c", "a", "b"])]
#[case::created_descending("?sortOrder=0", ["b", "a", "c"])]
#[case::name("?sortField=name", ["a", "b", "c"])]
#[case::name_descending("?sortField=name&sortOrder=0", ["c", "b", "a"])]
#[case::expiry("?sortField=expiresOn", ["a", "b", "c"])]
#[tokio::test]
async fn list_tokens_sorts(#[case] query: &str, #[case] expected: [&str; 3]) -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    for (name, days) in [("c", 3), ("a", 1), ("b", 2)] {
        let body = json!({ "name": name, "maxUses": 1, "expiresOn": rfc3339(now + days * DAY) });
        create_token(&app, body).await?;
    }
    let (status, page) = call(&app, Method::GET, &format!("/enrollment-token{query}"), None).await?;
    assert_eq!(status, 200);
    assert_eq!(names(&page), expected);
    Ok(())
}

/// `AgentIdentityPublicApi_DeleteAgentIdentityEnrollmentToken` returns `204`, then `404` "already deleted"; a deleted
/// token is neither returned nor listed.
#[tokio::test]
async fn deleted_token_is_gone() -> anyhow::Result<()> {
    let app = App::for_test()?;
    let id = create_token(&app, json!({ "name": "t", "maxUses": 1 })).await?;
    let path = format!("/enrollment-token/{id}");
    assert_eq!(call(&app, Method::DELETE, &path, None).await?, (204, Value::Null));

    let (status, body) = call(&app, Method::GET, &path, None).await?;
    assert_eq!(status, 404);
    assert_public_api_error(&body);
    let (status, body) = call(&app, Method::DELETE, &path, None).await?;
    assert_eq!(status, 404);
    assert_public_api_error(&body);
    let (_, page) = call(&app, Method::GET, "/enrollment-token", None).await?;
    assert_eq!(page["totalCount"], 0);
    Ok(())
}

// ==== Identities ====

/// `AgentIdentityPublicApi_GetAgentIdentity` returns an `AgentIdentity` in the Full view.
#[tokio::test]
async fn get_identity_returns_the_full_view() -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    let id = enroll(&app, json!({ "hostname": "host-a" })).await?;
    let (root, token_id, thumbprint, serial) = {
        let state = app.state.lock().await;
        let identity = &state.identities[&id];
        let cert = identity.current_cert().expect("current certificate");
        (
            state.issuing_root().thumbprint.clone(),
            identity.token_id,
            cert.thumbprint.clone(),
            cert.serial.clone(),
        )
    };
    let (status, view) = call(&app, Method::GET, &format!("/{id}"), None).await?;
    assert_eq!(status, 200);
    // The friendly name follows the default format `{hostname}`, and the certificate the default 90-day lifetime.
    let expected = json!({
        "id": id,
        "friendlyName": "host-a",
        "status": "Active",
        "isConnected": false,
        "lastSeenOn": rfc3339(now),
        "certificate": { "issuerThumbprint": root, "validUntil": rfc3339(now + 90 * DAY) },
        "metadata": { "hostname": "host-a" },
        "certificates": [{
            "issuerThumbprint": root,
            "serialNumber": serial,
            "status": "Current",
            "thumbprint": thumbprint,
            "validFrom": rfc3339(now),
            "validUntil": rfc3339(now + 90 * DAY),
        }],
        "createdOn": rfc3339(now),
        "enrollmentTokenId": token_id,
        "enrollmentTokenName": "test",
        "isRenewalRequested": false,
    });
    assert_eq!(view, expected);
    Ok(())
}

/// `AgentIdentity.metadata` in the Summary view carries "only the keys requested with metadataKey and omits the field
/// when it has none of them"; the Full-view-only members are absent.
#[rstest]
#[case::no_keys("", Value::Null)]
#[case::one_key("?metadataKey=hostname", json!({ "hostname": "host-a" }))]
#[case::both_keys(
    "?metadataKey=hostname&metadataKey=os_name",
    json!({ "hostname": "host-a", "os_name": "Linux" })
)]
#[case::absent_key("?metadataKey=machine_id", Value::Null)]
#[case::summary_view("?view=Summary&metadataKey=os_name", json!({ "os_name": "Linux" }))]
#[tokio::test]
async fn summary_view_carries_the_requested_metadata(
    #[case] query: &str,
    #[case] metadata: Value,
) -> anyhow::Result<()> {
    let app = App::for_test()?;
    enroll(&app, json!({ "hostname": "host-a", "os_name": "Linux" })).await?;
    let (status, page) = call(&app, Method::GET, query, None).await?;
    assert_eq!(status, 200);
    let item = page["data"][0].as_object().expect("identity");
    assert_eq!(item.get("metadata").cloned().unwrap_or(Value::Null), metadata);
    let mut members: Vec<&str> = item
        .keys()
        .map(String::as_str)
        .filter(|key| *key != "metadata")
        .collect();
    members.sort_unstable();
    assert_eq!(
        members,
        [
            "certificate",
            "friendlyName",
            "id",
            "isConnected",
            "lastSeenOn",
            "status"
        ]
    );
    Ok(())
}

/// `AgentIdentityPublicApi_GetAgentIdentities` with `view=Full` lists each identity as `GetAgentIdentity` returns it,
/// ignoring `metadataKey`.
#[tokio::test]
async fn full_view_lists_each_identity_whole() -> anyhow::Result<()> {
    let app = App::for_test()?;
    let id = enroll(&app, json!({ "hostname": "host-a" })).await?;
    let (_, page) = call(&app, Method::GET, "?view=Full&metadataKey=os_name", None).await?;
    let (_, read) = call(&app, Method::GET, &format!("/{id}"), None).await?;
    assert_eq!(page["data"], json!([read]));
    Ok(())
}

/// `AgentIdentityPublicApi_GetAgentIdentities`' `status` filter takes `AgentIdentityStatus` values, repeated.
#[rstest]
#[case::active("?status=Active", 1)]
#[case::revoked("?status=Revoked", 1)]
#[case::grace("?status=Grace", 0)]
#[case::either("?status=Active&status=Revoked", 2)]
#[tokio::test]
async fn status_filter_selects_identities(#[case] query: &str, #[case] expected: u64) -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    {
        let mut state = app.state.lock().await;
        state.insert_connected_identity(now, DAY);
        let (revoked, _) = state.insert_connected_identity(now, DAY);
        state.revoke(revoked, now).expect("identity exists");
    }
    let (status, page) = call(&app, Method::GET, query, None).await?;
    assert_eq!(status, 200);
    assert_eq!(page["totalCount"], expected);
    Ok(())
}

/// `AgentIdentityPublicApi_GetAgentIdentities`' `400`: invalid parameters, including enum values other than the
/// PascalCase ones of `AgentIdentityView` and `AgentIdentityStatus`.
#[rstest]
#[case::lowercase_status("?status=active", "status")]
#[case::certificate_status("?status=Pending", "status")]
#[case::lowercase_view("?view=full", "view")]
#[case::token_id("?enrollmentTokenId=build-agents", "enrollmentTokenId")]
#[case::last_seen_from("?lastSeenFrom=yesterday", "lastSeenFrom")]
#[case::last_seen_to("?lastSeenTo=1700000000", "lastSeenTo")]
#[tokio::test]
async fn list_identities_refuses_an_invalid_filter(#[case] query: &str, #[case] field: &str) -> anyhow::Result<()> {
    let app = App::for_test()?;
    let (status, body) = call(&app, Method::GET, query, None).await?;
    assert_eq!(status, 400);
    assert_eq!(error_fields(&body), [json!(field)]);
    Ok(())
}

/// `AgentIdentityPublicApi_PatchAgentIdentity` renames and returns the Full view; "Only the provided fields are
/// changed".
#[rstest]
#[case::renamed(json!({ "friendlyName": "renamed" }), "renamed")]
#[case::empty_patch(json!({}), "test-1")]
#[case::null_name(json!({ "friendlyName": null }), "test-1")]
#[tokio::test]
async fn patch_identity_changes_the_provided_name(#[case] patch: Value, #[case] expected: &str) -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    let (id, _) = app.state.lock().await.insert_connected_identity(now, DAY);
    let (status, view) = call(&app, Method::PATCH, &format!("/{id}"), Some(patch)).await?;
    assert_eq!(status, 200);
    assert_eq!(view["friendlyName"], expected);
    assert!(
        view["certificates"].is_array(),
        "the Full view carries the certificates"
    );
    let (_, read) = call(&app, Method::GET, &format!("/{id}"), None).await?;
    assert_eq!(read, view);
    Ok(())
}

/// `AgentIdentityPatchDTO.friendlyName`: "1 to 255 Unicode scalar values that do not start or end with white space".
#[rstest]
#[case::empty(json!({ "friendlyName": "" }), "friendlyName")]
#[case::leading_space(json!({ "friendlyName": " name" }), "friendlyName")]
#[case::trailing_tab(json!({ "friendlyName": "name\t" }), "friendlyName")]
#[case::too_long(json!({ "friendlyName": "n".repeat(256) }), "friendlyName")]
#[case::not_a_string(json!({ "friendlyName": 7 }), "friendlyName")]
#[case::unknown_member(json!({ "name": "renamed" }), "name")]
#[tokio::test]
async fn patch_identity_refuses_an_invalid_name(#[case] patch: Value, #[case] field: &str) -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    let (id, _) = app.state.lock().await.insert_connected_identity(now, DAY);
    let (status, body) = call(&app, Method::PATCH, &format!("/{id}"), Some(patch)).await?;
    assert_eq!(status, 400);
    assert_eq!(error_fields(&body), [json!(field)]);
    Ok(())
}

/// `AgentIdentityPublicApi_RevokeAgentIdentity` returns `204`, also for a revoked identity, which "can then neither
/// authenticate nor renew": its live streams close.
#[tokio::test]
async fn revoke_identity_is_idempotent() -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    let (id, mut stream) = app.state.lock().await.insert_connected_identity(now, DAY);
    let path = format!("/{id}/revoke");
    assert_eq!(call(&app, Method::POST, &path, None).await?, (204, Value::Null));
    assert_eq!(call(&app, Method::POST, &path, None).await?, (204, Value::Null));
    assert!(matches!(stream.try_recv(), Ok(StreamPush::CloseRevoked)));

    let (_, view) = call(&app, Method::GET, &format!("/{id}"), None).await?;
    assert_eq!(
        (&view["status"], &view["revokedOn"]),
        (&json!("Revoked"), &json!(rfc3339(now)))
    );
    Ok(())
}

/// `AgentIdentityPublicApi_DeleteAgentIdentity` deletes only a revoked identity: `409` before, `204`, then `404`.
#[tokio::test]
async fn delete_identity_requires_revocation() -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    let (id, _) = app.state.lock().await.insert_connected_identity(now, DAY);
    let path = format!("/{id}");
    let (status, body) = call(&app, Method::DELETE, &path, None).await?;
    assert_eq!(status, 409);
    assert_public_api_error(&body);

    call(&app, Method::POST, &format!("{path}/revoke"), None).await?;
    assert_eq!(call(&app, Method::DELETE, &path, None).await?, (204, Value::Null));
    assert_eq!(call(&app, Method::GET, &path, None).await?.0, 404);
    assert_eq!(call(&app, Method::DELETE, &path, None).await?.0, 404);
    Ok(())
}

/// `AgentIdentityPublicApi_RequestAgentIdentityRenewal` sets the request-renewal flag and notifies the connected agent.
#[tokio::test]
async fn request_renewal_flags_and_notifies() -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    let (id, mut stream) = app.state.lock().await.insert_connected_identity(now, DAY);
    assert_eq!(
        call(&app, Method::POST, &format!("/{id}/request-renewal"), None).await?,
        (202, Value::Null)
    );
    assert!(matches!(stream.try_recv(), Ok(StreamPush::RenewRequested("admin"))));
    let (_, view) = call(&app, Method::GET, &format!("/{id}"), None).await?;
    assert_eq!(view["isRenewalRequested"], true);
    Ok(())
}

/// `AgentIdentityPublicApi_RequestAgentIdentityRenewal`'s `409`: "The identity is revoked".
#[tokio::test]
async fn request_renewal_of_a_revoked_identity_is_a_conflict() -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    let (id, _) = app.state.lock().await.insert_connected_identity(now, DAY);
    call(&app, Method::POST, &format!("/{id}/revoke"), None).await?;
    let (status, body) = call(&app, Method::POST, &format!("/{id}/request-renewal"), None).await?;
    assert_eq!(status, 409);
    assert_public_api_error(&body);
    Ok(())
}

/// The `404` of each operation on one identity or token, for an unknown GUID and for an ID that is not one.
#[rstest]
#[case::get_identity(Method::GET, "/{id}")]
#[case::patch_identity(Method::PATCH, "/{id}")]
#[case::delete_identity(Method::DELETE, "/{id}")]
#[case::revoke_identity(Method::POST, "/{id}/revoke")]
#[case::request_renewal(Method::POST, "/{id}/request-renewal")]
#[case::get_token(Method::GET, "/enrollment-token/{id}")]
#[case::delete_token(Method::DELETE, "/enrollment-token/{id}")]
#[tokio::test]
async fn unknown_record_is_404(
    #[case] method: Method,
    #[case] route: &str,
    #[values("00000000-0000-0000-0000-000000000000", "not-a-guid")] id: &str,
) -> anyhow::Result<()> {
    let app = App::for_test()?;
    let (status, body) = call(&app, method, &route.replace("{id}", id), Some(json!({}))).await?;
    assert_eq!(status, 404);
    assert_public_api_error(&body);
    Ok(())
}

// ==== Paging ====

/// `pageSize` allows up to 100 identities ("Every item carries metadata and certificates") and 500 tokens, 25 by
/// default.
#[rstest]
#[case::identities_minimum("?pageSize=1", 1)]
#[case::identities_maximum("?pageSize=100", 100)]
#[case::tokens_maximum("/enrollment-token?pageSize=500", 500)]
#[case::default_size("/enrollment-token", 25)]
#[tokio::test]
async fn page_size_within_bounds_is_accepted(#[case] path: &str, #[case] page_size: u64) -> anyhow::Result<()> {
    let app = App::for_test()?;
    let (status, page) = call(&app, Method::GET, path, None).await?;
    assert_eq!((status, &page["pageSize"]), (200, &json!(page_size)));
    Ok(())
}

/// The paging parameters' schemas: `pageNumber` ≥ 1, `pageSize` from 1 to its maximum, `sortOrder` 0 or 1, and
/// `sortField` among the allowed values.
#[rstest]
#[case::identity_page_size_101("?pageSize=101", "pageSize")]
#[case::token_page_size_501("/enrollment-token?pageSize=501", "pageSize")]
#[case::page_size_zero("?pageSize=0", "pageSize")]
#[case::page_number_zero("?pageNumber=0", "pageNumber")]
#[case::page_number_not_an_integer("/enrollment-token?pageNumber=first", "pageNumber")]
#[case::sort_order_two("?sortOrder=2", "sortOrder")]
#[case::identity_sort_by_name("?sortField=name", "sortField")]
#[case::token_sort_by_use_count("/enrollment-token?sortField=useCount", "sortField")]
#[tokio::test]
async fn paging_out_of_bounds_is_refused(#[case] path: &str, #[case] field: &str) -> anyhow::Result<()> {
    let app = App::for_test()?;
    let (status, body) = call(&app, Method::GET, path, None).await?;
    assert_eq!(status, 400);
    assert_eq!(error_fields(&body), [json!(field)]);
    Ok(())
}

/// A page past the last is `400`; page 1 of an empty listing is the last page.
#[rstest]
#[case::empty_first_page(0, 1, 200)]
#[case::empty_second_page(0, 2, 400)]
#[case::last_page(2, 2, 200)]
#[case::past_the_last_page(2, 3, 400)]
#[tokio::test]
async fn page_past_the_last_is_refused(
    #[case] identities: usize,
    #[case] page_number: u64,
    #[case] expected: u16,
) -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    for _ in 0..identities {
        app.state.lock().await.insert_connected_identity(now, DAY);
    }
    let path = format!("?pageSize=1&pageNumber={page_number}");
    assert_eq!(call(&app, Method::GET, &path, None).await?.0, expected);
    Ok(())
}

/// `PagedResultOfAgentIdentity` of an empty listing: no page, no data.
#[tokio::test]
async fn empty_listing_has_no_page() -> anyhow::Result<()> {
    let app = App::for_test()?;
    let (_, page) = call(&app, Method::GET, "", None).await?;
    assert_eq!(
        page,
        json!({ "currentPage": 1, "data": [], "pageSize": 25, "totalCount": 0, "totalPage": 0 })
    );
    Ok(())
}

// ==== Rotation ====

/// `AgentIdentityRotation` while Idle omits every root and time and counts 0.
#[tokio::test]
async fn idle_rotation_has_no_roots() -> anyhow::Result<()> {
    let app = App::for_test()?;
    let (status, rotation) = call(&app, Method::GET, "/rotation", None).await?;
    assert_eq!(
        (status, rotation),
        (200, json!({ "phase": "Idle", "oldRootActiveIdentityCount": 0 }))
    );
    Ok(())
}

/// `AgentIdentityPublicApi_StartAgentIdentityRotation` with `{}` uses the rotation maximum: the latest expiry among the
/// old root's unexpired current or pending certificates of identities that are not revoked.
#[tokio::test]
async fn rotation_defaults_to_the_rotation_maximum() -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    let old_root = {
        let mut state = app.state.lock().await;
        state.insert_connected_identity(now, 3600);
        state.insert_connected_identity(now, 7200);
        state.issuing_root().thumbprint.clone()
    };
    let (status, started) = call(&app, Method::POST, "/rotation", Some(json!({}))).await?;
    assert_eq!(status, 202);
    let expected = {
        let state = app.state.lock().await;
        let root_view = |thumbprint: &str| {
            let root = state
                .roots
                .iter()
                .find(|root| root.thumbprint == thumbprint)
                .expect("known root");
            json!({
                "thumbprint": root.thumbprint,
                "validFrom": rfc3339(root.not_before),
                "validUntil": rfc3339(root.not_after),
            })
        };
        let new_root = state.issuing_root().thumbprint.clone();
        assert_ne!(new_root, old_root);
        json!({
            "phase": "Rotating",
            "startedOn": rfc3339(now),
            "deadlineOn": rfc3339(now + 7200),
            "oldRoot": root_view(&old_root),
            "newRoot": root_view(&new_root),
            "oldRootActiveIdentityCount": 2,
        })
    };
    assert_eq!(started, expected);
    assert_eq!(call(&app, Method::GET, "/rotation", None).await?, (200, expected));
    Ok(())
}

fn tokyo_time(unix_secs: i64) -> String {
    let offset = time::UtcOffset::from_hms(9, 0, 0).expect("valid offset");
    time::OffsetDateTime::from_unix_timestamp(unix_secs)
        .expect("valid time")
        .to_offset(offset)
        .format(&time::format_description::well_known::Rfc3339)
        .expect("formattable time")
}

/// `AgentIdentityRotationCreateDTO.deadlineOn` is "UTC unless an offset is given".
#[rstest]
#[case::utc(|now| rfc3339(now + 1800))]
#[case::without_offset(|now| rfc3339(now + 1800).trim_end_matches('Z').to_owned())]
#[case::with_offset(|now| tokyo_time(now + 1800))]
#[tokio::test]
async fn rotation_deadline_is_utc_unless_an_offset_is_given(#[case] deadline: fn(i64) -> String) -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    app.state.lock().await.insert_connected_identity(now, 3600);
    let body = json!({ "deadlineOn": deadline(now) });
    let (status, started) = call(&app, Method::POST, "/rotation", Some(body)).await?;
    assert_eq!((status, &started["deadlineOn"]), (202, &json!(rfc3339(now + 1800))));
    Ok(())
}

/// `AgentIdentityRotationCreateDTO.deadlineOn`: "A time at or before now requests an emergency rotation", which
/// completes at once and unpublishes the old root (CONTRACT.md §8.3).
#[rstest]
#[case::now(0)]
#[case::past(-60)]
#[tokio::test]
async fn deadline_at_or_before_now_is_an_emergency(#[case] offset: i64) -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    app.state.lock().await.insert_connected_identity(now, 3600);
    let body = json!({ "deadlineOn": rfc3339(now + offset) });
    assert_eq!(call(&app, Method::POST, "/rotation", Some(body)).await?.0, 202);
    let (_, rotation) = call(&app, Method::GET, "/rotation", None).await?;
    assert_eq!(rotation["phase"], "Idle");
    let state = app.state.lock().await;
    let published: Vec<&str> = state
        .roots
        .iter()
        .filter(|root| root.published)
        .map(|root| root.thumbprint.as_str())
        .collect();
    assert_eq!(published, [state.issuing_root().thumbprint.as_str()]);
    Ok(())
}

/// `AgentIdentityPublicApi_StartAgentIdentityRotation`'s `422`: "deadlineOn is after the rotation maximum".
#[tokio::test]
async fn deadline_after_the_rotation_maximum_is_unprocessable() -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    app.state.lock().await.insert_connected_identity(now, 3600);
    let body = json!({ "deadlineOn": rfc3339(now + 3601) });
    let (status, refused) = call(&app, Method::POST, "/rotation", Some(body)).await?;
    assert_eq!(status, 422);
    assert_public_api_error(&refused);
    assert!(app.state.lock().await.rotation.is_none());
    Ok(())
}

fn rotation_in_progress(state: &mut State, now: i64) {
    state.insert_connected_identity(now, 3600);
    state.start_rotation(None, now).expect("first rotation starts");
}

fn no_root_yet(state: &mut State, now: i64) {
    state.reset(now, false).expect("reset succeeds");
}

fn root_key_unavailable(state: &mut State, _: i64) {
    state.faults.root_key_unavailable = true;
}

/// `AgentIdentityPublicApi_StartAgentIdentityRotation`'s `409`: "A rotation is in progress, no root exists yet, or the
/// root key is unavailable".
#[rstest]
#[case::rotation_in_progress(rotation_in_progress)]
#[case::no_root_yet(no_root_yet)]
#[case::root_key_unavailable(root_key_unavailable)]
#[tokio::test]
async fn rotation_conflict_is_409(#[case] arrange: fn(&mut State, i64)) -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    arrange(&mut *app.state.lock().await, now);
    let (status, body) = call(&app, Method::POST, "/rotation", Some(json!({}))).await?;
    assert_eq!(status, 409);
    assert_public_api_error(&body);
    Ok(())
}

/// `AgentIdentityPublicApi_StartAgentIdentityRotation` requires an `AgentIdentityRotationCreateDTO` body, whose
/// `deadlineOn` is a date-time with no `"now"` literal.
#[rstest]
#[case::empty_body(None, Value::Null)]
#[case::now_literal(Some(json!({ "deadlineOn": "now" })), json!("deadlineOn"))]
#[case::unknown_member(Some(json!({ "deadline": "2030-01-01T00:00:00Z" })), json!("deadline"))]
#[tokio::test]
async fn rotation_refuses_an_invalid_body(#[case] body: Option<Value>, #[case] field: Value) -> anyhow::Result<()> {
    let app = App::for_test()?;
    let (status, refused) = call(&app, Method::POST, "/rotation", body).await?;
    assert_eq!(status, 400);
    assert_eq!(error_fields(&refused), [field]);
    Ok(())
}

// ==== Settings ====

/// `AgentIdentitySettings` by default: the channel enabled and offered, 90-day certificates (CONTRACT.md §4), and 10
/// rotation notifications per second (INTENT.DVLS.md, "Load").
#[tokio::test]
async fn settings_have_their_defaults() -> anyhow::Result<()> {
    let app = App::for_test()?;
    let (status, settings) = call(&app, Method::GET, "/settings", None).await?;
    assert_eq!(status, 200);
    assert_eq!(
        settings,
        json!({
            "authorityId": app.authority_id,
            "isAgentChannelEnabled": true,
            "isAgentChannelAvailable": true,
            "certificateLifetimeDays": 90,
            "rotationNotificationsPerSecond": 10,
        })
    );
    Ok(())
}

/// `AgentIdentitySettingsPatchDTO.isAgentChannelEnabled` switches the channel off and on: `config.agent_channel_url`
/// leaves and returns (CONTRACT.md §5.2), each change bumping the config revision.
#[tokio::test]
async fn channel_setting_withdraws_and_restores_the_channel_url() -> anyhow::Result<()> {
    let app = App::for_test()?;
    let id = enroll(&app, json!({})).await?;

    let disable = json!({ "isAgentChannelEnabled": false });
    let (status, settings) = call(&app, Method::PATCH, "/settings", Some(disable)).await?;
    assert_eq!(status, 200);
    assert_eq!(
        (&settings["isAgentChannelEnabled"], &settings["isAgentChannelAvailable"]),
        (&json!(false), &json!(false))
    );
    let disabled = app.state.lock().await.identities[&id].config.clone();
    assert_eq!(
        (disabled.get("agent_channel_url"), &disabled["revision"]),
        (None, &json!(2))
    );

    let enable = json!({ "isAgentChannelEnabled": true });
    assert_eq!(call(&app, Method::PATCH, "/settings", Some(enable)).await?.0, 200);
    let enabled = app.state.lock().await.identities[&id].config.clone();
    assert_eq!(
        (&enabled["agent_channel_url"], &enabled["revision"]),
        (&json!(app.base_url), &json!(3))
    );
    Ok(())
}

/// `AgentIdentitySettings.isAgentChannelAvailable`: "it is enabled and the hosting supports it"; the mock's
/// `channel_available` fault stands for the hosting.
#[tokio::test]
async fn channel_is_unavailable_without_hosting_support() -> anyhow::Result<()> {
    let app = App::for_test()?;
    app.state.lock().await.update_channel_available(false, &app.base_url);
    let (_, settings) = call(&app, Method::GET, "/settings", None).await?;
    assert_eq!(
        (&settings["isAgentChannelEnabled"], &settings["isAgentChannelAvailable"]),
        (&json!(true), &json!(false))
    );
    Ok(())
}

/// `AgentIdentitySettings.certificateLifetimeDays`: "The lifetime of the identity certificates issued from now on".
#[tokio::test]
async fn certificate_lifetime_applies_to_new_certificates() -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    let patch = json!({ "certificateLifetimeDays": 7 });
    let (status, settings) = call(&app, Method::PATCH, "/settings", Some(patch)).await?;
    assert_eq!((status, &settings["certificateLifetimeDays"]), (200, &json!(7)));
    let id = enroll(&app, json!({})).await?;
    let (_, view) = call(&app, Method::GET, &format!("/{id}"), None).await?;
    assert_eq!(view["certificate"]["validUntil"], rfc3339(now + 7 * DAY));
    Ok(())
}

/// The `leaf_lifetime_secs` mock fault overrides `certificateLifetimeDays` with seconds, for expiry tests.
#[tokio::test]
async fn leaf_lifetime_fault_overrides_the_setting() -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    app.state.lock().await.faults.leaf_lifetime_secs = Some(60);
    let id = enroll(&app, json!({})).await?;
    let (_, view) = call(&app, Method::GET, &format!("/{id}"), None).await?;
    assert_eq!(view["certificate"]["validUntil"], rfc3339(now + 60));
    Ok(())
}

/// `AgentIdentitySettings.rotationNotificationsPerSecond`: "How many connected identities are notified per second during
/// a root rotation".
#[tokio::test]
async fn rotation_notifies_at_the_settings_rate() -> anyhow::Result<()> {
    let (app, now) = frozen_app()?;
    let patch = json!({ "rotationNotificationsPerSecond": 2 });
    assert_eq!(call(&app, Method::PATCH, "/settings", Some(patch)).await?.0, 200);
    let mut streams: Vec<_> = {
        let mut state = app.state.lock().await;
        (0..3).map(|_| state.insert_connected_identity(now, DAY).1).collect()
    };
    assert_eq!(call(&app, Method::POST, "/rotation", Some(json!({}))).await?.0, 202);
    let notified = streams
        .iter_mut()
        .map(|stream| stream.try_recv())
        .filter(|push| matches!(push, Ok(StreamPush::RenewRequested("rotation"))))
        .count();
    assert_eq!(notified, 2);
    Ok(())
}

/// `AgentIdentitySettingsPatchDTO`'s limits, at their bounds.
#[rstest]
#[case::shortest_lifetime("certificateLifetimeDays", 1)]
#[case::longest_lifetime("certificateLifetimeDays", 365)]
#[case::slowest_rate("rotationNotificationsPerSecond", 1)]
#[case::fastest_rate("rotationNotificationsPerSecond", 1000)]
#[tokio::test]
async fn settings_accept_their_bounds(#[case] member: &str, #[case] value: i64) -> anyhow::Result<()> {
    let app = App::for_test()?;
    let (status, settings) = call(&app, Method::PATCH, "/settings", Some(json!({ member: value }))).await?;
    assert_eq!((status, &settings[member]), (200, &json!(value)));
    Ok(())
}

/// `AgentIdentityPublicApi_PatchAgentIdentitySettings`' `400`: values outside `AgentIdentitySettingsPatchDTO`'s ranges
/// or types, and members it does not define, such as the read-only `authorityId`.
#[rstest]
#[case::zero_lifetime(json!({ "certificateLifetimeDays": 0 }), "certificateLifetimeDays")]
#[case::lifetime_366_days(json!({ "certificateLifetimeDays": 366 }), "certificateLifetimeDays")]
#[case::fractional_lifetime(json!({ "certificateLifetimeDays": 1.5 }), "certificateLifetimeDays")]
#[case::zero_rate(json!({ "rotationNotificationsPerSecond": 0 }), "rotationNotificationsPerSecond")]
#[case::rate_1001(json!({ "rotationNotificationsPerSecond": 1001 }), "rotationNotificationsPerSecond")]
#[case::channel_not_a_boolean(json!({ "isAgentChannelEnabled": "no" }), "isAgentChannelEnabled")]
#[case::authority_id(json!({ "authorityId": Uuid::nil() }), "authorityId")]
#[case::channel_availability(json!({ "isAgentChannelAvailable": true }), "isAgentChannelAvailable")]
#[tokio::test]
async fn settings_refuse_an_invalid_member(#[case] patch: Value, #[case] field: &str) -> anyhow::Result<()> {
    let app = App::for_test()?;
    let (status, body) = call(&app, Method::PATCH, "/settings", Some(patch)).await?;
    assert_eq!(status, 400);
    assert_eq!(error_fields(&body), [json!(field)]);
    Ok(())
}
