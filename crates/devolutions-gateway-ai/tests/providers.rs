#![allow(clippy::unwrap_used, reason = "test code can panic on errors")]

//! Round trips against mock providers: what each API receives, and how its answers and errors come back.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use devolutions_gateway_ai::session_actions::Action;
use devolutions_gateway_ai::{AiClient, Error, Provider, Usage};
use reqwest::StatusCode;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

const API_KEY: &str = "sk-test-secret";
const MODEL: &str = "model-under-test";
const REPORTED_MODEL: &str = "model-under-test-2026-09-30";
const USAGE: Usage = Usage {
    input_tokens: 10,
    output_tokens: 20,
};
const ANSWER: &str = "{\"offsetSeconds\":1.5,\"description\":\"Listed files\",\"object\":\"/var/log\",\"parameters\":{\"Command\":\"ls\"}}\nnot an action\n{\"offsetSeconds\":4,\"description\":\"Opened a shell\"}";
const NO_ACTIONS: &str = "{\"noActions\":true}";
/// Largest answer body the client reads, the same as in the crate.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
struct CapturedRequest {
    /// Path of the request, with its query if any.
    path: String,
    /// Headers of the request, by lowercase name.
    headers: HashMap<String, String>,
    body: serde_json::Value,
}

type Captured = Arc<Mutex<Option<CapturedRequest>>>;

/// Answer of a mock provider to every request.
struct MockAnswer {
    status: StatusCode,
    /// Headers besides `content-type`, `content-length` and `connection`, such as `retry-after`.
    headers: &'static [(&'static str, &'static str)],
    body: Vec<u8>,
    /// Whether the answer has a `content-length`; without one, closing the connection ends the body.
    content_length: bool,
}

impl MockAnswer {
    fn new(status: StatusCode, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: &[],
            body: body.into(),
            content_length: true,
        }
    }
}

/// A provider answering every request with `status` and `response`, keeping the last request.
async fn spawn_provider(status: StatusCode, response: serde_json::Value) -> (Url, Captured) {
    spawn_mock(MockAnswer::new(status, response.to_string())).await
}

/// A provider answering every request with `answer`, keeping the last request.
///
/// It speaks just enough HTTP/1.1 for the client: one request per connection, closed after the answer.
async fn spawn_mock(answer: MockAnswer) -> (Url, Captured) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let captured = Captured::default();

    tokio::spawn({
        let captured = Arc::clone(&captured);
        async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                *captured.lock().unwrap() = Some(request);
                write_answer(&mut stream, &answer).await;
            }
        }
    });

    (Url::parse(&format!("http://{addr}/v1/")).unwrap(), captured)
}

/// Reads the head of a request up to its empty line, then `content-length` bytes of body.
async fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut reader = BufReader::new(stream);

    // Such as `POST /v1/chat/completions HTTP/1.1`.
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await.unwrap();
    let path = request_line.split(' ').nth(1).unwrap().to_owned();

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let line = line.trim_end();

        if line.is_empty() {
            break;
        }

        let (name, value) = line.split_once(':').unwrap();
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }

    let content_length: usize = headers
        .get("content-length")
        .map_or(0, |length| length.parse().unwrap());
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).await.unwrap();

    CapturedRequest {
        path,
        headers,
        body: serde_json::from_slice(&body).unwrap(),
    }
}

async fn write_answer(stream: &mut TcpStream, answer: &MockAnswer) {
    let content_length = if answer.content_length {
        format!("content-length: {}\r\n", answer.body.len())
    } else {
        String::new()
    };
    let headers: String = answer
        .headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    let head = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\n{content_length}connection: close\r\n{headers}\r\n",
        answer.status.as_u16(),
        answer.status.canonical_reason().unwrap_or_default(),
    );

    // The client may close the connection without reading the whole body, such as when it is over the size limit.
    let _ = stream
        .write_all(&[head.as_bytes(), answer.body.as_slice()].concat())
        .await;
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

fn header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(name).map(String::as_str)
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
async fn think_tags_inside_an_action_are_kept() {
    const COMMAND: &str = "grep '<think>x</think>' notes.txt";

    let action = serde_json::json!({
        "offsetSeconds": 2,
        "description": "Searched notes",
        "parameters": { "Command": COMMAND }
    });
    let answer = format!("<think>plan</think>\n{action}");
    let (base_url, _captured) = spawn_provider(StatusCode::OK, openai_response(&answer)).await;

    let response = client(Provider::OpenAiCompatible, base_url)
        .describe_session_actions("[2] grep '<think>x</think>' notes.txt")
        .send()
        .await
        .unwrap();

    assert_eq!(response.output.len(), 1);
    assert_eq!(
        response.output[0].parameters.get("Command").map(String::as_str),
        Some(COMMAND)
    );
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
async fn unexpected_answers_are_invalid_responses() {
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
    let mut no_choice = openai_response(ANSWER);
    no_choice["choices"] = serde_json::json!([]);
    let mut no_content = openai_response(ANSWER);
    no_content["choices"][0]["message"]["content"] = serde_json::Value::Null;

    for (provider, response) in [
        (Provider::OpenAi, openai("tool_calls")),
        (Provider::Gemini, openai("something_new")),
        (Provider::OpenAi, no_choice),
        (Provider::OpenAiCompatible, no_content),
        (Provider::Anthropic, anthropic("tool_use")),
        (Provider::Anthropic, anthropic("pause_turn")),
    ] {
        let (base_url, _captured) = spawn_provider(StatusCode::OK, response).await;

        let error = client(provider, base_url)
            .describe_session_actions("[1.5] ls")
            .send()
            .await
            .unwrap_err();

        assert!(
            matches!(error, Error::InvalidResponse { .. }),
            "{provider:?}: {error:?}"
        );
        assert!(!error.is_transient());
        assert!(!error.to_string().contains("Listed files"), "{error}");
    }
}

#[tokio::test]
async fn no_actions_line_means_no_action() {
    for (provider, answer) in [
        (Provider::OpenAi, openai_response(NO_ACTIONS)),
        (Provider::Anthropic, anthropic_response(NO_ACTIONS)),
    ] {
        let (base_url, _captured) = spawn_provider(StatusCode::OK, answer).await;

        let response = client(provider, base_url)
            .describe_session_actions("[0.5] ")
            .send()
            .await
            .unwrap();

        assert!(response.output.is_empty(), "{provider:?}: {:?}", response.output);
    }
}

#[tokio::test]
async fn empty_answers_are_invalid_output() {
    let mut anthropic = anthropic_response("");
    anthropic["content"] = serde_json::json!([]);

    for (provider, answer) in [
        (Provider::OpenAi, openai_response("")),
        (Provider::Anthropic, anthropic),
    ] {
        let (base_url, _captured) = spawn_provider(StatusCode::OK, answer).await;

        let error = client(provider, base_url)
            .describe_session_actions("[0.5] ")
            .send()
            .await
            .unwrap_err();

        assert!(matches!(error, Error::InvalidOutput { .. }), "{provider:?}: {error:?}");
        assert!(!error.is_transient());
    }
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
    let answer = MockAnswer {
        headers: &[("retry-after", "7")],
        ..MockAnswer::new(StatusCode::TOO_MANY_REQUESTS, body.to_string())
    };
    let (base_url, _captured) = spawn_mock(answer).await;

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
async fn instructions_are_a_system_message() {
    for provider in [
        Provider::OpenAi,
        Provider::Mistral,
        Provider::Gemini,
        Provider::OpenAiCompatible,
    ] {
        let (base_url, captured) = spawn_provider(StatusCode::OK, openai_response(ANSWER)).await;

        client(provider, base_url)
            .describe_session_actions("[1.5] ls")
            .send()
            .await
            .unwrap();

        let request = take(&captured);
        let messages = &request.body["messages"];
        assert_eq!(messages.as_array().map(Vec::len), Some(2), "{provider:?}");
        assert_eq!(messages[0]["role"], "system", "{provider:?}");
        assert!(
            messages[0]["content"]
                .as_str()
                .is_some_and(|instructions| !instructions.is_empty()),
            "{provider:?}"
        );
        assert_eq!(messages[1]["role"], "user", "{provider:?}");
        assert_eq!(messages[1]["content"], "[1.5] ls", "{provider:?}");
    }
}

#[test]
fn base_url_with_query_or_fragment_is_refused() {
    for base_url in ["https://llm.example/v1/?api-version=1", "https://llm.example/v1/#part"] {
        let result = AiClient::builder()
            .provider(Provider::OpenAiCompatible)
            .model(MODEL)
            .api_key(API_KEY)
            .base_url(Url::parse(base_url).unwrap())
            .http_client(reqwest::Client::builder().no_proxy().build().unwrap())
            .build();

        assert!(
            matches!(result, Err(devolutions_gateway_ai::BuildError::UnsupportedBaseUrl)),
            "{base_url}: {result:?}"
        );
    }
}

#[tokio::test]
async fn answer_up_to_the_size_limit_is_read() {
    // JSON allows whitespace after the value, so the padded answer stays valid.
    let mut body = openai_response(ANSWER).to_string().into_bytes();
    body.resize(MAX_RESPONSE_BYTES, b' ');

    for content_length in [true, false] {
        let answer = MockAnswer {
            content_length,
            ..MockAnswer::new(StatusCode::OK, body.clone())
        };
        let (base_url, _captured) = spawn_mock(answer).await;

        let response = client(Provider::OpenAi, base_url)
            .describe_session_actions("[1.5] ls")
            .send()
            .await
            .unwrap();

        assert_parsed_actions(&response.output);
    }
}

#[tokio::test]
async fn answer_over_the_size_limit_is_invalid_response() {
    let mut body = openai_response(ANSWER).to_string().into_bytes();
    body.resize(MAX_RESPONSE_BYTES + 1, b' ');

    for content_length in [true, false] {
        let answer = MockAnswer {
            content_length,
            ..MockAnswer::new(StatusCode::OK, body.clone())
        };
        let (base_url, _captured) = spawn_mock(answer).await;

        let error = client(Provider::OpenAi, base_url)
            .describe_session_actions("[1.5] ls")
            .send()
            .await
            .unwrap_err();

        assert!(
            matches!(&error, Error::InvalidResponse { reason } if reason.contains("larger than")),
            "content_length {content_length}: {error:?}"
        );
        assert!(!error.is_transient());
        assert!(!error.to_string().contains("Listed files"), "{error}");
    }
}

#[tokio::test]
async fn error_answer_over_the_size_limit_keeps_the_status() {
    // Read whole, the body would give its message.
    let mut body = serde_json::json!({ "error": { "message": "Overloaded" } })
        .to_string()
        .into_bytes();
    body.resize(MAX_RESPONSE_BYTES + 1, b' ');

    for content_length in [true, false] {
        let answer = MockAnswer {
            content_length,
            ..MockAnswer::new(StatusCode::SERVICE_UNAVAILABLE, body.clone())
        };
        let (base_url, _captured) = spawn_mock(answer).await;

        let error = client(Provider::OpenAi, base_url)
            .describe_session_actions("[0] whoami")
            .send()
            .await
            .unwrap_err();

        assert!(
            matches!(
                &error,
                Error::Status { status: 503, message, code: None, .. } if message == "Service Unavailable"
            ),
            "content_length {content_length}: {error:?}"
        );
        assert!(error.is_transient());
    }
}

#[tokio::test]
async fn answer_cut_by_a_closed_connection_is_transient() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Promises a longer body than it sends, then closes the connection.
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100\r\nconnection: close\r\n\r\n{\"choices\":")
            .await
            .unwrap();
    });

    let error = client(Provider::OpenAi, Url::parse(&format!("http://{addr}/v1/")).unwrap())
        .describe_session_actions("[0] whoami")
        .send()
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Transport { .. }), "{error:?}");
    assert!(error.is_transient());
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
