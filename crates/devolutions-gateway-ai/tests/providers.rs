#![allow(clippy::unwrap_used, reason = "test code can panic on errors")]

//! Round trips against mock providers: what each API receives, and how its answers and errors come back.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::routing::post;
use devolutions_gateway_ai::session_actions::Action;
use devolutions_gateway_ai::{AiClient, Error, Provider, Usage};
use tokio::net::TcpListener;
use url::Url;

const API_KEY: &str = "sk-test-secret";
const MODEL: &str = "model-under-test";
const REPORTED_MODEL: &str = "model-under-test-2026-09-30";
const USAGE: Usage = Usage {
    input_tokens: 10,
    output_tokens: 20,
};
const ANSWER: &str = "{\"offsetSeconds\":1.5,\"description\":\"Listed files\",\"object\":\"/var/log\",\"parameters\":{\"Command\":\"ls\"}}\nnot an action\n{\"offsetSeconds\":4,\"description\":\"Opened a shell\"}";

#[derive(Debug)]
struct CapturedRequest {
    path: String,
    headers: HeaderMap,
    body: serde_json::Value,
}

type Captured = Arc<Mutex<Option<CapturedRequest>>>;

/// A provider answering every request with `status` and `response`, keeping the last request.
async fn spawn_provider(status: StatusCode, response: serde_json::Value) -> (Url, Captured) {
    spawn_provider_with_headers(status, HeaderMap::new(), response).await
}

/// A provider answering every request with `status`, `response_headers` and `response`, keeping the last request.
async fn spawn_provider_with_headers(
    status: StatusCode,
    response_headers: HeaderMap,
    response: serde_json::Value,
) -> (Url, Captured) {
    let captured = Captured::default();

    let app = Router::new().fallback(post({
        let captured = Arc::clone(&captured);
        move |uri: Uri, headers: HeaderMap, body: String| {
            let captured = Arc::clone(&captured);
            async move {
                *captured.lock().unwrap() = Some(CapturedRequest {
                    path: uri.path().to_owned(),
                    headers,
                    body: serde_json::from_str(&body).unwrap(),
                });
                (status, response_headers, axum::Json(response))
            }
        }
    }));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (Url::parse(&format!("http://{addr}/v1/")).unwrap(), captured)
}

fn client(provider: Provider, base_url: Url) -> AiClient {
    AiClient::builder()
        .provider(provider)
        .model(MODEL)
        .api_key(API_KEY)
        .base_url(base_url)
        .http_client(reqwest::Client::builder().no_proxy().build().unwrap())
        .build()
        .unwrap()
}

fn openai_response(content: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": REPORTED_MODEL,
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
        "model": REPORTED_MODEL,
        "content": [{ "type": "text", "text": text }],
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": { "input_tokens": 10, "output_tokens": 20 }
    })
}

fn assert_parsed_actions(actions: &[Action]) {
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

fn take(captured: &Captured) -> CapturedRequest {
    captured.lock().unwrap().take().unwrap()
}

#[tokio::test]
async fn openai_chat_request_and_response() {
    let (base_url, captured) = spawn_provider(StatusCode::OK, openai_response(ANSWER)).await;

    let response = client(Provider::OpenAi, base_url)
        .describe_session_actions("[1.5] ls")
        .max_output_tokens(1234)
        .send()
        .await
        .unwrap();

    assert_parsed_actions(&response.output);
    assert_eq!(response.model.as_deref(), Some(REPORTED_MODEL));
    assert_eq!(response.usage, Some(USAGE));

    let request = take(&captured);
    assert_eq!(request.path, "/v1/chat/completions");
    assert_eq!(
        header(&request.headers, "authorization"),
        Some(format!("Bearer {API_KEY}").as_str())
    );
    assert_eq!(header(&request.headers, "x-api-key"), None);
    assert_eq!(request.body["model"], MODEL);
    assert!(request.body.to_string().contains("[1.5] ls"));
    assert_eq!(request.body["max_completion_tokens"], 1234);
    assert_eq!(request.body["store"], false);
}

#[tokio::test]
async fn anthropic_messages_request_and_response() {
    let (base_url, captured) = spawn_provider(StatusCode::OK, anthropic_response(ANSWER)).await;

    let response = client(Provider::Anthropic, base_url)
        .describe_session_actions("[1.5] ls")
        .max_output_tokens(1234)
        .send()
        .await
        .unwrap();

    assert_parsed_actions(&response.output);
    assert_eq!(response.model.as_deref(), Some(REPORTED_MODEL));
    assert_eq!(response.usage, Some(USAGE));

    let request = take(&captured);
    assert_eq!(request.path, "/v1/messages");
    assert_eq!(header(&request.headers, "x-api-key"), Some(API_KEY));
    assert_eq!(header(&request.headers, "anthropic-version"), Some("2023-06-01"));
    assert_eq!(header(&request.headers, "authorization"), None);
    assert_eq!(request.body["model"], MODEL);
    assert_eq!(request.body["max_tokens"], 1234);
    assert!(request.body.to_string().contains("[1.5] ls"));
}

#[tokio::test]
async fn openai_compatible_uses_the_given_base_url_and_max_tokens() {
    let (base_url, captured) = spawn_provider(StatusCode::OK, openai_response(ANSWER)).await;

    let response = client(Provider::OpenAiCompatible, base_url)
        .describe_session_actions("[1.5] ls")
        .send()
        .await
        .unwrap();

    assert_parsed_actions(&response.output);

    let request = take(&captured);
    assert_eq!(request.path, "/v1/chat/completions");
    assert_eq!(
        header(&request.headers, "authorization"),
        Some(format!("Bearer {API_KEY}").as_str())
    );
    assert_eq!(request.body["max_tokens"], 16_000);
    assert!(request.body.get("max_completion_tokens").is_none());
    assert!(request.body.get("store").is_none());
}

#[tokio::test]
async fn gemini_speaks_openai_chat_with_max_tokens() {
    let (base_url, captured) = spawn_provider(StatusCode::OK, openai_response(ANSWER)).await;

    let response = client(Provider::Gemini, base_url)
        .describe_session_actions("[1.5] ls")
        .max_output_tokens(1234)
        .send()
        .await
        .unwrap();

    assert_parsed_actions(&response.output);

    let request = take(&captured);
    assert_eq!(request.path, "/v1/chat/completions");
    assert_eq!(
        header(&request.headers, "authorization"),
        Some(format!("Bearer {API_KEY}").as_str())
    );
    assert_eq!(request.body["max_tokens"], 1234);
    assert!(request.body.get("max_completion_tokens").is_none());
    assert!(request.body.get("store").is_none());
}

#[tokio::test]
async fn mistral_chunked_content_is_read_as_text() {
    let (first_line, other_lines) = ANSWER.split_once('\n').unwrap();
    let mut answer = openai_response("");
    answer["choices"][0]["message"]["content"] = serde_json::json!([
        {
            "type": "thinking",
            "thinking": [{ "type": "text", "text": "{\"offsetSeconds\":9,\"description\":\"Drafted an action\"}" }]
        },
        { "type": "text", "text": first_line },
        { "type": "reference", "reference_ids": [1] },
        { "type": "text", "text": other_lines }
    ]);
    let (base_url, captured) = spawn_provider(StatusCode::OK, answer).await;

    let response = client(Provider::Mistral, base_url)
        .describe_session_actions("[1.5] ls")
        .max_output_tokens(1234)
        .send()
        .await
        .unwrap();

    assert_parsed_actions(&response.output);

    let request = take(&captured);
    assert_eq!(request.path, "/v1/chat/completions");
    assert_eq!(
        header(&request.headers, "authorization"),
        Some(format!("Bearer {API_KEY}").as_str())
    );
    assert_eq!(request.body["max_tokens"], 1234);
    assert!(request.body.get("max_completion_tokens").is_none());
    assert!(request.body.get("store").is_none());
}

#[tokio::test]
async fn answer_without_model_or_usage_is_accepted() {
    let mut answer = openai_response(ANSWER);
    let fields = answer.as_object_mut().unwrap();
    fields.remove("model");
    fields.remove("usage");
    let (base_url, _captured) = spawn_provider(StatusCode::OK, answer).await;

    let response = client(Provider::OpenAiCompatible, base_url)
        .describe_session_actions("[1.5] ls")
        .send()
        .await
        .unwrap();

    assert_parsed_actions(&response.output);
    assert_eq!(response.model, None);
    assert_eq!(response.usage, None);
}

#[tokio::test]
async fn think_blocks_are_not_read_as_actions() {
    let answer = format!("<think>\n{{\"offsetSeconds\":9,\"description\":\"Drafted an action\"}}\n</think>\n{ANSWER}");
    let (base_url, _captured) = spawn_provider(StatusCode::OK, openai_response(&answer)).await;

    let response = client(Provider::OpenAiCompatible, base_url)
        .describe_session_actions("[1.5] ls")
        .send()
        .await
        .unwrap();

    assert_parsed_actions(&response.output);
}

#[tokio::test]
async fn answers_cut_at_the_token_limit_are_truncated() {
    let openai = |finish_reason: &str| {
        let mut response = openai_response(ANSWER);
        response["choices"][0]["finish_reason"] = finish_reason.into();
        response
    };
    let anthropic = |stop_reason: &str| {
        let mut response = anthropic_response(ANSWER);
        response["stop_reason"] = stop_reason.into();
        response
    };

    for (provider, response) in [
        (Provider::OpenAi, openai("length")),
        (Provider::Mistral, openai("model_length")),
        (Provider::Anthropic, anthropic("max_tokens")),
        (Provider::Anthropic, anthropic("model_context_window_exceeded")),
    ] {
        let (base_url, _captured) = spawn_provider(StatusCode::OK, response).await;

        let error = client(provider, base_url)
            .describe_session_actions("[1.5] ls")
            .send()
            .await
            .unwrap_err();

        assert!(
            matches!(error, Error::Truncated { usage: Some(USAGE) }),
            "{provider:?}: {error:?}"
        );
        assert!(!error.is_transient());
    }
}

#[tokio::test]
async fn refusals_are_permanent_errors() {
    const REFUSAL: &str = "I cannot describe this session.";

    let mut content_filter = openai_response("");
    content_filter["choices"][0]["finish_reason"] = "content_filter".into();
    let mut refusal = openai_response("");
    refusal["choices"][0]["message"]["content"] = serde_json::Value::Null;
    refusal["choices"][0]["message"]["refusal"] = REFUSAL.into();
    let mut anthropic = anthropic_response(REFUSAL);
    anthropic["stop_reason"] = "refusal".into();

    for (provider, response) in [
        (Provider::OpenAi, content_filter),
        (Provider::OpenAi, refusal),
        (Provider::Anthropic, anthropic),
    ] {
        let (base_url, _captured) = spawn_provider(StatusCode::OK, response).await;

        let error = client(provider, base_url)
            .describe_session_actions("[1.5] ls")
            .send()
            .await
            .unwrap_err();

        assert!(matches!(error, Error::Refused { .. }), "{provider:?}: {error:?}");
        assert!(!error.is_transient());
        assert!(!error.to_string().contains(REFUSAL), "{error}");
    }
}

#[tokio::test]
async fn provider_failure_while_answering_is_invalid_response() {
    let mut answer = openai_response(ANSWER);
    answer["choices"][0]["finish_reason"] = "error".into();
    let (base_url, _captured) = spawn_provider(StatusCode::OK, answer).await;

    let error = client(Provider::Mistral, base_url)
        .describe_session_actions("[1.5] ls")
        .send()
        .await
        .unwrap_err();

    assert!(matches!(error, Error::InvalidResponse { .. }), "{error:?}");
    assert!(!error.is_transient());
    assert!(!error.to_string().contains("Listed files"), "{error}");
}

#[tokio::test]
async fn answer_without_any_action_line_is_invalid_output() {
    let (base_url, _captured) = spawn_provider(StatusCode::OK, openai_response("Sorry, I cannot help.")).await;

    let error = client(Provider::OpenAi, base_url)
        .describe_session_actions("[1.5] ls")
        .send()
        .await
        .unwrap_err();

    assert!(matches!(error, Error::InvalidOutput { .. }), "{error:?}");
    assert!(!error.is_transient());
}

#[tokio::test]
async fn provider_error_is_redacted_and_permanent() {
    let body = serde_json::json!({ "error": { "message": format!("Incorrect API key provided: {API_KEY}") } });
    let (base_url, _captured) = spawn_provider(StatusCode::UNAUTHORIZED, body).await;

    let error = client(Provider::OpenAi, base_url)
        .describe_session_actions("[0] whoami")
        .send()
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Status { status: 401, .. }), "{error:?}");
    assert!(!error.is_transient());
    assert!(!error.to_string().contains(API_KEY), "{error}");
    assert!(!format!("{error:?}").contains(API_KEY), "{error:?}");
}

#[tokio::test]
async fn rate_limit_is_transient_and_keeps_retry_after() {
    let body = serde_json::json!({
        "type": "error",
        "error": { "type": "rate_limit_error", "message": "Rate limit reached" }
    });
    let headers = HeaderMap::from_iter([(RETRY_AFTER, HeaderValue::from_static("7"))]);
    let (base_url, _captured) = spawn_provider_with_headers(StatusCode::TOO_MANY_REQUESTS, headers, body).await;

    let error = client(Provider::Anthropic, base_url)
        .describe_session_actions("[0] whoami")
        .send()
        .await
        .unwrap_err();

    assert!(
        matches!(
            &error,
            Error::Status { status: 429, retry_after: Some(retry_after), .. }
                if *retry_after == Duration::from_secs(7)
        ),
        "{error:?}"
    );
    assert!(error.is_transient());
}

#[tokio::test]
async fn spent_quota_is_permanent() {
    let openai = serde_json::json!({
        "error": {
            "message": "You exceeded your current quota, please check your plan and billing details.",
            "type": "insufficient_quota",
            "param": null,
            "code": "insufficient_quota"
        }
    });
    let anthropic = serde_json::json!({
        "type": "error",
        "error": {
            "type": "rate_limit_error",
            "message": "You have reached your API usage limits.",
            "details": { "error_code": "enforced_spend_limit_reached" }
        },
        "request_id": "req_1"
    });

    for (provider, body, expected_code) in [
        (Provider::OpenAi, openai, "insufficient_quota"),
        (Provider::Anthropic, anthropic, "enforced_spend_limit_reached"),
    ] {
        let (base_url, _captured) = spawn_provider(StatusCode::TOO_MANY_REQUESTS, body).await;

        let error = client(provider, base_url)
            .describe_session_actions("[0] whoami")
            .send()
            .await
            .unwrap_err();

        assert!(
            matches!(&error, Error::Status { status: 429, code: Some(code), .. } if code == expected_code),
            "{provider:?}: {error:?}"
        );
        assert!(!error.is_transient(), "{provider:?}");
    }
}

#[tokio::test]
async fn error_messages_are_read_from_gemini_and_mistral_bodies() {
    let gemini = serde_json::json!([{
        "error": {
            "code": 400,
            "message": "API key not valid. Please pass a valid API key.",
            "status": "INVALID_ARGUMENT"
        }
    }]);
    let mistral = serde_json::json!({
        "object": "error",
        "message": "Invalid model: model-under-test",
        "type": "invalid_model",
        "param": null,
        "code": "1500"
    });

    for (provider, body, expected_message, expected_code) in [
        (
            Provider::Gemini,
            gemini,
            "API key not valid. Please pass a valid API key.",
            None,
        ),
        (
            Provider::Mistral,
            mistral,
            "Invalid model: model-under-test",
            Some("1500"),
        ),
    ] {
        let (base_url, _captured) = spawn_provider(StatusCode::BAD_REQUEST, body).await;

        let error = client(provider, base_url)
            .describe_session_actions("[0] whoami")
            .send()
            .await
            .unwrap_err();

        assert!(
            matches!(
                &error,
                Error::Status { status: 400, message, code, .. }
                    if message == expected_message && code.as_deref() == expected_code
            ),
            "{provider:?}: {error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!("AI provider answered HTTP 400: {expected_message}")
        );
        assert!(!error.is_transient());
    }
}

#[tokio::test]
async fn unreachable_provider_is_transient() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let error = client(Provider::OpenAi, Url::parse(&format!("http://{addr}/v1/")).unwrap())
        .describe_session_actions("[0] whoami")
        .send()
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Transport { .. }), "{error:?}");
    assert!(error.is_transient());
}

#[tokio::test]
async fn silent_provider_times_out_as_transient() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Accepts connections and never answers.
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _open = stream;
                std::future::pending::<()>().await;
            });
        }
    });

    let started = Instant::now();
    let error = AiClient::builder()
        .provider(Provider::OpenAiCompatible)
        .model(MODEL)
        .api_key(API_KEY)
        .base_url(Url::parse(&format!("http://{addr}/v1/")).unwrap())
        .http_client(reqwest::Client::builder().no_proxy().build().unwrap())
        .request_timeout(Duration::from_millis(200))
        .build()
        .unwrap()
        .describe_session_actions("[0] whoami")
        .send()
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Transport { .. }), "{error:?}");
    assert!(error.is_transient());
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
}
