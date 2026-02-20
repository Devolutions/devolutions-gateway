#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::str::FromStr as _;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{self, Request, StatusCode};
use devolutions_gateway::credential::AppCredential;
use devolutions_gateway::{DgwState, MockHandles};
use http_body_util::BodyExt as _;
use serde_json::json;
use tower::ServiceExt as _;
use tracing_subscriber::util::SubscriberInitExt;
use uuid::Uuid;

const CONFIG: &str = r#"{
    "ProvisionerPublicKeyData": {
        "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HhjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
    },
    "Listeners": [
        {
            "InternalUrl": "tcp://*:8080",
            "ExternalUrl": "tcp://*:8080"
        },
        {
            "InternalUrl": "http://*:7171",
            "ExternalUrl": "https://*:7171"
        }
    ],
    "__debug__": {
        "disable_token_validation": true
    }
}"#;

fn preflight_request(operations: serde_json::Value) -> anyhow::Result<Request<Body>> {
    let request = Request::builder()
        .method("POST")
        .uri("/jet/preflight")
        .header("content-type", "application/json")
        .header(http::header::AUTHORIZATION, "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IlNDT1BFIn0.eyJqdGkiOiI5YTdkZWRhOC1jNmM2LTQ1YzAtODZlYi01MGJiMzI4YWFjMjMiLCJleHAiOjAsInNjb3BlIjoiZ2F0ZXdheS5wcmVmbGlnaHQifQ.dTazZemDS08Fy13Hx7wxDoOxQ2oNFaaEYMSFDQHCWiUdlYv4NMQh6N_GQok3wdiSJf384fvLKccYe1fipRepLlinUAqcEum68ngvGuUVP78xYb_vC3ZDqFi6nvd1BLp621XgzsCbOyBZHhLXHgzwVNTpnbt9laTTaHh8_rSYLaujBOpidWS6vKIZqOE66beqygSprPt3y0LYFTQWGYq21jJ73uW6htdWrmXbDUUjdvG7ymnKb-7Scs5y03jjSTr4QB1rH_3Z8DsfuuxFCIBd8V2yu192PrWooAdMKboLSjvmdFiD509lljoaNoGLBv9hmmQyiLQr-rsUllXBD6UpTQ")
        .body(Body::from(serde_json::to_vec(&operations)?))?;

    Ok(request)
}

fn make_router() -> anyhow::Result<(Router, DgwState, MockHandles)> {
    let (state, handles) = DgwState::mock(CONFIG)?;
    let app = devolutions_gateway::make_http_service(state.clone())
        .layer(MockConnectInfo(SocketAddr::from(([0, 0, 0, 0], 3000))));
    Ok((app, state, handles))
}

fn init_logger() -> tracing::subscriber::DefaultGuard {
    tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .set_default()
}

#[tokio::test]
async fn test_provision_credentials_success() -> anyhow::Result<()> {
    let _guard = init_logger();

    let (app, state, _handles) = make_router()?;

    let token_id = Uuid::from_str("5e3e833f-84c7-4541-b676-acc3299e39b8").unwrap();
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1ZTNlODMzZi04NGM3LTQ1NDEtYjY3Ni1hY2MzMjk5ZTM5YjgifQ.1qECGlrW7y9HWFArc6GPHLGTOY7PhAvzKJ5XMRBg4k4";

    let op_id = Uuid::new_v4();

    let op = json!([{
        "id": op_id,
        "kind": "provision-credentials",
        "token": token,
        "proxy_credential": { "kind": "username-password", "username": "proxy_user", "password": "secret1" },
        "target_credential": { "kind": "username-password", "username": "target_user", "password": "secret2" },
        "time_to_live": 15
    }]);

    let request = preflight_request(op)?;

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await?.to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(body.as_array().expect("an array").len(), 1);
    assert_eq!(body[1]["operation_id"], op_id.to_string());
    assert_eq!(body[1]["kind"], "ack", "{:?}", body[1]);

    let entry = state.credential_store.get(token_id).expect("the provisioned entry");
    assert_eq!(entry.token, token);

    let now = time::OffsetDateTime::now_utc();
    assert!(now + time::Duration::seconds(10) < entry.expires_at);
    assert!(entry.expires_at < now + time::Duration::seconds(20));

    let mapping = entry.mapping.as_ref().expect("the provisioned mapping");
    assert!(matches!(mapping.proxy, AppCredential::UsernamePassword { .. }));
    assert!(matches!(mapping.target, AppCredential::UsernamePassword { .. }));

    Ok(())
}

#[tokio::test]
async fn test_provision_token_overwrite_alert() -> anyhow::Result<()> {
    let _guard = init_logger();

    let (app, _state, _handles) = make_router()?;

    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1ZTNlODMzZi04NGM3LTQ1NDEtYjY3Ni1hY2MzMjk5ZTM5YjgifQ.1qECGlrW7y9HWFArc6GPHLGTOY7PhAvzKJ5XMRBg4k4";

    let op_id1 = Uuid::new_v4();
    let op_id2 = Uuid::new_v4();

    let op1 = json!([{
        "id": op_id1,
        "kind": "provision-token",
        "token": token,
    }]);

    app.clone().oneshot(preflight_request(op1)?).await?;

    let op2 = json!([{
        "id": op_id2,
        "kind": "provision-token",
        "token": token,
    }]);

    let response = app.oneshot(preflight_request(op2)?).await?;
    let body = response.into_body().collect().await?.to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body)?;

    assert_eq!(body.as_array().expect("an array").len(), 2);
    assert_eq!(body[0]["kind"], "alert");
    assert!(body[0]["alert_message"].as_str().unwrap().contains("replaced"));
    assert_eq!(body[1]["kind"], "ack");

    Ok(())
}

#[tokio::test]
async fn test_provision_invalid_params() -> anyhow::Result<()> {
    let _guard = init_logger();

    let (app, _state, _handles) = make_router()?;

    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1ZTNlODMzZi04NGM3LTQ1NDEtYjY3Ni1hY2MzMjk5ZTM5YjgifQ.1qECGlrW7y9HWFArc6GPHLGTOY7PhAvzKJ5XMRBg4k4";

    let op_id = Uuid::new_v4();

    let op = json!([{
        "id": op_id,
        "kind": "provision-credentials",
        "token": token,
        "proxy_credendial": { "kind": "unknown" },
        "target_credential":  { "kind": "username-password", "username": "u", "password": "p" },
    }]);

    let request = preflight_request(op)?;
    let response = app.oneshot(request).await?;
    let body = response.into_body().collect().await?.to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body)?;

    assert_eq!(body.as_array().expect("an array").len(), 1);
    assert_eq!(body[0]["kind"], "alert");
    assert_eq!(body[0]["alert_status"], "invalid-parameters");

    Ok(())
}
