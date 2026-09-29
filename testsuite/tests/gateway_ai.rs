use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::routing::post;
use devolutions_gateway_ai::{AiClient, BuildError, Provider};
use parking_lot::Mutex;
use tokio::net::TcpListener;
use url::Url;

const API_KEY: &str = "sk-test-secret";
const MODEL: &str = "model-under-test";
const ANSWER: &str = "{\"offsetSeconds\":1.5,\"description\":\"Listed files\",\"object\":\"/var/log\",\"parameters\":{\"Command\":\"ls\"}}\nnot an action\n{\"offsetSeconds\":4,\"description\":\"Opened a shell\"}";

#[derive(Debug)]
struct CapturedRequest {
    path: String,
    headers: HeaderMap,
    body: serde_json::Value,
}

async fn spawn_provider(status: StatusCode, response: serde_json::Value) -> (Url, Arc<Mutex<Option<CapturedRequest>>>) {
    let captured = Arc::new(Mutex::new(None));

    let app = Router::new().fallback(post({
        let captured = Arc::clone(&captured);
        move |uri: Uri, headers: HeaderMap, body: String| {
            let captured = Arc::clone(&captured);
            async move {
                *captured.lock() = Some(CapturedRequest {
                    path: uri.path().to_owned(),
                    headers,
                    body: serde_json::from_str(&body).unwrap(),
                });
                (status, axum::Json(response))
            }
        }
    }));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (Url::parse(&format!("http://{addr}/v1/")).unwrap(), captured)
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

fn client(provider: Provider, base_url: Url) -> AiClient {
    AiClient::builder()
        .provider(provider)
        .model(MODEL)
        .api_key(API_KEY)
        .base_url(base_url)
        .http_client(http_client())
        .build()
        .unwrap()
}

fn openai_response(content: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": MODEL,
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": content },
            "finish_reason": "stop"
        }],
        "usage": { "prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30 }
    })
}

fn anthropic_response(text: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": MODEL,
        "content": [{ "type": "text", "text": text }],
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": { "input_tokens": 10, "output_tokens": 20 }
    })
}

fn assert_parsed_actions(actions: &[devolutions_gateway_ai::Action]) {
    assert_eq!(actions.len(), 2);
    assert_eq!(actions[0].offset, Duration::from_millis(1500));
    assert_eq!(actions[0].description, "Listed files");
    assert_eq!(actions[0].object.as_deref(), Some("/var/log"));
    assert_eq!(actions[0].parameters.get("Command").map(String::as_str), Some("ls"));
    assert_eq!(actions[1].offset, Duration::from_secs(4));
    assert_eq!(actions[1].object, None);
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).map(|value| value.to_str().unwrap())
}

fn body_contains(body: &serde_json::Value, needle: &str) -> bool {
    body.to_string().contains(needle)
}

#[tokio::test]
async fn openai_chat_request_and_response() {
    let (base_url, captured) = spawn_provider(StatusCode::OK, openai_response(ANSWER)).await;

    let actions = client(Provider::OpenAi, base_url)
        .describe_session_actions("[1.5] ls")
        .max_output_tokens(1234)
        .send()
        .await
        .unwrap();

    assert_parsed_actions(&actions);

    let request = captured.lock().take().unwrap();
    assert_eq!(request.path, "/v1/chat/completions");
    assert_eq!(
        header(&request.headers, "authorization"),
        Some(format!("Bearer {API_KEY}").as_str())
    );
    assert_eq!(header(&request.headers, "x-api-key"), None);
    assert_eq!(request.body["model"], MODEL);
    assert!(body_contains(&request.body, "[1.5] ls"));
    assert_eq!(request.body["max_completion_tokens"], 1234);
}

#[tokio::test]
async fn anthropic_messages_request_and_response() {
    let (base_url, captured) = spawn_provider(StatusCode::OK, anthropic_response(ANSWER)).await;

    let actions = client(Provider::Anthropic, base_url)
        .describe_session_actions("[1.5] ls")
        .max_output_tokens(1234)
        .send()
        .await
        .unwrap();

    assert_parsed_actions(&actions);

    let request = captured.lock().take().unwrap();
    assert_eq!(request.path, "/v1/messages");
    assert_eq!(header(&request.headers, "x-api-key"), Some(API_KEY));
    assert_eq!(header(&request.headers, "anthropic-version"), Some("2023-06-01"));
    assert_eq!(header(&request.headers, "authorization"), None);
    assert_eq!(request.body["model"], MODEL);
    assert_eq!(request.body["max_tokens"], 1234);
    assert!(body_contains(&request.body, "[1.5] ls"));
}

#[tokio::test]
async fn provider_error_is_redacted() {
    let body = serde_json::json!({ "error": { "message": format!("Incorrect API key provided: {API_KEY}") } });
    let (base_url, _captured) = spawn_provider(StatusCode::UNAUTHORIZED, body).await;

    let error = client(Provider::OpenAi, base_url)
        .describe_session_actions("[0] whoami")
        .send()
        .await
        .unwrap_err();

    assert!(
        matches!(error, devolutions_gateway_ai::Error::Request { status: Some(401), .. }),
        "{error:?}"
    );
    assert!(!error.to_string().contains(API_KEY), "{error}");
    assert!(!format!("{error:?}").contains(API_KEY), "{error:?}");
}

#[tokio::test]
async fn openai_compatible_uses_the_given_base_url() {
    let (base_url, captured) = spawn_provider(StatusCode::OK, openai_response(ANSWER)).await;

    let actions = client(Provider::OpenAiCompatible, base_url)
        .describe_session_actions("[1.5] ls")
        .send()
        .await
        .unwrap();

    assert_parsed_actions(&actions);

    let request = captured.lock().take().unwrap();
    assert_eq!(request.path, "/v1/chat/completions");
    assert_eq!(
        header(&request.headers, "authorization"),
        Some(format!("Bearer {API_KEY}").as_str())
    );
    assert_eq!(request.body["max_tokens"], 4096);
    assert!(request.body.get("max_completion_tokens").is_none());
}

fn complete_builder(provider: Provider) -> devolutions_gateway_ai::AiClientBuilder {
    AiClient::builder()
        .provider(provider)
        .model(MODEL)
        .api_key(API_KEY)
        .base_url(Url::parse("http://127.0.0.1:1/v1/").unwrap())
        .http_client(http_client())
}

#[test]
fn build_requires_provider() {
    let result = AiClient::builder()
        .model(MODEL)
        .api_key(API_KEY)
        .http_client(http_client())
        .build();

    assert!(matches!(result, Err(BuildError::MissingProvider)), "{result:?}");
}

#[test]
fn build_requires_model() {
    let result = AiClient::builder()
        .provider(Provider::OpenAi)
        .api_key(API_KEY)
        .http_client(http_client())
        .build();
    assert!(matches!(result, Err(BuildError::MissingModel)), "{result:?}");

    let result = complete_builder(Provider::OpenAi).model("  ").build();
    assert!(matches!(result, Err(BuildError::MissingModel)), "{result:?}");
}

#[test]
fn build_requires_key_for_hosted_providers() {
    for provider in [
        Provider::OpenAi,
        Provider::Anthropic,
        Provider::Mistral,
        Provider::OpenAiCompatible,
    ] {
        let result = AiClient::builder()
            .provider(provider)
            .model(MODEL)
            .base_url(Url::parse("http://127.0.0.1:1/v1/").unwrap())
            .http_client(http_client())
            .build();
        assert!(
            matches!(result, Err(BuildError::MissingApiKey(missing)) if missing == provider),
            "{provider:?}: {result:?}"
        );

        let result = complete_builder(provider).api_key("").build();
        assert!(
            matches!(result, Err(BuildError::MissingApiKey(missing)) if missing == provider),
            "{provider:?}: {result:?}"
        );
    }
}

#[test]
fn build_requires_base_url_without_default() {
    let result = AiClient::builder()
        .provider(Provider::OpenAiCompatible)
        .model(MODEL)
        .api_key(API_KEY)
        .http_client(http_client())
        .build();

    assert!(
        matches!(result, Err(BuildError::MissingBaseUrl(Provider::OpenAiCompatible))),
        "{result:?}"
    );
}

#[test]
fn build_uses_default_base_url() {
    for provider in [Provider::OpenAi, Provider::Anthropic, Provider::Mistral] {
        let result = AiClient::builder()
            .provider(provider)
            .model(MODEL)
            .api_key(API_KEY)
            .http_client(http_client())
            .build();

        assert!(result.is_ok(), "{provider:?}: {result:?}");
    }
}

#[test]
fn build_requires_http_client() {
    let result = AiClient::builder()
        .provider(Provider::OpenAi)
        .model(MODEL)
        .api_key(API_KEY)
        .build();

    assert!(matches!(result, Err(BuildError::MissingHttpClient)), "{result:?}");
}

#[test]
fn client_debug_does_not_show_key() {
    let ai = complete_builder(Provider::Anthropic).build().unwrap();

    assert!(!format!("{ai:?}").contains(API_KEY));
}
