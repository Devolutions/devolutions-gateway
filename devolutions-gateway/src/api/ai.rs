//! AI Router module (experimental)
//!
//! This module provides a proxy for AI provider APIs, currently supporting Mistral AI,
//! Ollama, LM Studio, Anthropic, OpenAI, OpenRouter, and Azure OpenAI.
//! It handles authentication via a gateway API key and forwards requests to the
//! configured AI provider endpoints.

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request};
use axum::response::Response;
use axum::routing::{get, post};
use http_body_util::BodyExt as _; // into_data_stream

use crate::DgwState;
use crate::ai::{AuthMethod, ProviderConfig, ProviderConfigBuilder};
use crate::http::HttpError;

/// Anthropic API version header value
const ANTHROPIC_API_VERSION: &str = "2023-06-01";

/// Creates the AI router with all provider endpoints.
pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        // Mistral AI routes
        .route("/mistral/v1/models", get(mistral_list_models))
        .route("/mistral/v1/models/{model_id}", get(mistral_get_model))
        .route("/mistral/v1/chat/completions", post(mistral_chat_completions))
        // OpenAI routes
        .route("/openai/v1/models", get(openai_list_models))
        .route("/openai/v1/chat/completions", post(openai_chat_completions))
        // Ollama routes
        .route("/ollama/v1/models", get(ollama_list_models))
        .route("/ollama/v1/chat/completions", post(ollama_chat_completions))
        // LM Studio routes
        .route("/lmstudio/v1/models", get(lmstudio_list_models))
        .route("/lmstudio/v1/chat/completions", post(lmstudio_chat_completions))
        // Anthropic routes
        .route("/anthropic/v1/messages", post(anthropic_messages))
        // OpenRouter routes
        .route("/openrouter/v1/models", get(openrouter_list_models))
        .route("/openrouter/v1/chat/completions", post(openrouter_chat_completions))
        // Azure OpenAI routes
        .route("/azure-openai/chat/completions", post(azure_openai_chat_completions))
        .route("/azure-openai/completions", post(azure_openai_completions))
        .route("/azure-openai/embeddings", post(azure_openai_embeddings))
        .with_state(state)
}

/// Default HTTP client with a longer timeout suitable for AI requests.
fn create_client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .expect("parameters known to be valid only")
}

/// Validates the Authorization header against the gateway API key.
fn validate_gateway_api_key(headers: &HeaderMap, expected_key: Option<&str>) -> Result<(), HttpError> {
    let Some(expected_key) = expected_key else {
        // If no gateway API key is configured, allow all requests.
        return Ok(());
    };

    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| HttpError::unauthorized().msg("missing authorization header"))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| HttpError::unauthorized().msg("invalid authorization header format"))?;

    if token != expected_key {
        return Err(HttpError::unauthorized().msg("invalid gateway API key"));
    }

    Ok(())
}

/// Builds the provider API URL for a given path.
fn build_provider_url(endpoint: &str, path: &str) -> String {
    format!("{}{}", endpoint.trim_end_matches('/'), path)
}

/// Generic proxy function that forwards a request to an AI provider.
async fn proxy_to_provider(
    state: &DgwState,
    provider_config: &ProviderConfig,
    method: reqwest::Method,
    path: &str,
    headers: HeaderMap,
    body: Option<Body>,
) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let ai_conf = &conf.ai_gateway;

    // Validate gateway API key.
    validate_gateway_api_key(&headers, ai_conf.gateway_api_key.as_deref())?;

    // Check if API key is required.
    if provider_config.api_key_required && provider_config.api_key.is_none() {
        error!(provider = %provider_config.name, "API key not configured");
        return Err(HttpError::internal().msg("provider API key not configured"));
    }

    // Build the target URL.
    let url = build_provider_url(&provider_config.endpoint, path);

    debug!(%url, provider = %provider_config.name, "Proxying request to AI provider");

    // Create a client with the configured timeout.
    let client = create_client(ai_conf.request_timeout);

    // Build the request.
    let mut request_builder = client.request(method, &url);

    // Set the authentication header based on the provider's auth method.
    if let Some(api_key) = &provider_config.api_key {
        match &provider_config.auth_method {
            AuthMethod::Bearer => {
                request_builder = request_builder.header("Authorization", format!("Bearer {}", api_key));
            }
            AuthMethod::Header(header_name) => {
                request_builder = request_builder.header(header_name, api_key);
            }
        }
    }

    // Add extra headers configured for this provider.
    for (name, value) in &provider_config.extra_headers {
        request_builder = request_builder.header(name, value);
    }

    // Forward relevant headers (excluding Authorization which we set above).
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        // Skip headers that should not be forwarded.
        if name_str == "authorization" || name_str == "host" || name_str == "content-length" {
            continue;
        }
        request_builder = request_builder.header(name.clone(), value.clone());
    }

    // Add body if present.
    if let Some(body) = body {
        let body_stream = body.into_data_stream();
        request_builder = request_builder.body(reqwest::Body::wrap_stream(body_stream));
    }

    // Execute the request.
    let response = request_builder.send().await.map_err(HttpError::bad_gateway().err())?;

    if let Err(error) = response.error_for_status_ref() {
        info!(%error, provider = %provider_config.name, "AI provider responded with a failure HTTP status code");
    }

    // Convert the response to axum format, streaming the body for SSE support.
    let response = axum::http::Response::from(response);
    let (parts, body) = response.into_parts();
    let body = Body::from_stream(body.into_data_stream());

    Ok(Response::from_parts(parts, body))
}

/// GET /mistral/v1/models - List available models.
async fn mistral_list_models(State(state): State<DgwState>, headers: HeaderMap) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let mistral_conf = &conf.ai_gateway.mistral;

    let provider_config = ProviderConfigBuilder::new()
        .name("mistral")
        .endpoint(mistral_conf.get_endpoint())
        .api_key(mistral_conf.get_api_key())
        .bearer_auth()
        .build()
        .expect("valid provider config");

    proxy_to_provider(
        &state,
        &provider_config,
        reqwest::Method::GET,
        "/v1/models",
        headers,
        None,
    )
    .await
}

/// GET /mistral/v1/models/{model_id} - Get a specific model.
async fn mistral_get_model(
    State(state): State<DgwState>,
    Path(model_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let mistral_conf = &conf.ai_gateway.mistral;

    let provider_config = ProviderConfigBuilder::new()
        .name("mistral")
        .endpoint(mistral_conf.get_endpoint())
        .api_key(mistral_conf.get_api_key())
        .bearer_auth()
        .build()
        .expect("valid provider config");

    let path = format!("/v1/models/{}", model_id);
    proxy_to_provider(&state, &provider_config, reqwest::Method::GET, &path, headers, None).await
}

/// POST /mistral/v1/chat/completions - Create a chat completion (supports SSE streaming).
async fn mistral_chat_completions(
    State(state): State<DgwState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let mistral_conf = &conf.ai_gateway.mistral;

    let provider_config = ProviderConfigBuilder::new()
        .name("mistral")
        .endpoint(mistral_conf.get_endpoint())
        .api_key(mistral_conf.get_api_key())
        .bearer_auth()
        .build()
        .expect("valid provider config");

    let (_, body) = request.into_parts();
    proxy_to_provider(
        &state,
        &provider_config,
        reqwest::Method::POST,
        "/v1/chat/completions",
        headers,
        Some(body),
    )
    .await
}

/// GET /openai/v1/models - List available models.
async fn openai_list_models(State(state): State<DgwState>, headers: HeaderMap) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let openai_conf = &conf.ai_gateway.openai;

    let provider_config = ProviderConfigBuilder::new()
        .name("openai")
        .endpoint(openai_conf.get_endpoint())
        .api_key(openai_conf.get_api_key())
        .bearer_auth()
        .build()
        .expect("valid provider config");

    proxy_to_provider(
        &state,
        &provider_config,
        reqwest::Method::GET,
        "/v1/models",
        headers,
        None,
    )
    .await
}

/// POST /openai/v1/chat/completions - Create a chat completion (supports SSE streaming).
async fn openai_chat_completions(
    State(state): State<DgwState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let openai_conf = &conf.ai_gateway.openai;

    let provider_config = ProviderConfigBuilder::new()
        .name("openai")
        .endpoint(openai_conf.get_endpoint())
        .api_key(openai_conf.get_api_key())
        .bearer_auth()
        .build()
        .expect("valid provider config");

    let (_, body) = request.into_parts();
    proxy_to_provider(
        &state,
        &provider_config,
        reqwest::Method::POST,
        "/v1/chat/completions",
        headers,
        Some(body),
    )
    .await
}

/// GET /ollama/v1/models - List available models.
async fn ollama_list_models(State(state): State<DgwState>, headers: HeaderMap) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let ollama_conf = &conf.ai_gateway.ollama;

    let provider_config = ProviderConfigBuilder::new()
        .name("ollama")
        .endpoint(ollama_conf.get_endpoint())
        .api_key(ollama_conf.get_api_key())
        .api_key_required(false)
        .bearer_auth()
        .build()
        .expect("valid provider config");

    proxy_to_provider(
        &state,
        &provider_config,
        reqwest::Method::GET,
        "/v1/models",
        headers,
        None,
    )
    .await
}

/// POST /ollama/v1/chat/completions - Create a chat completion (supports SSE streaming).
async fn ollama_chat_completions(
    State(state): State<DgwState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let ollama_conf = &conf.ai_gateway.ollama;

    let provider_config = ProviderConfigBuilder::new()
        .name("ollama")
        .endpoint(ollama_conf.get_endpoint())
        .api_key(ollama_conf.get_api_key())
        .api_key_required(false)
        .bearer_auth()
        .build()
        .expect("valid provider config");

    let (_, body) = request.into_parts();
    proxy_to_provider(
        &state,
        &provider_config,
        reqwest::Method::POST,
        "/v1/chat/completions",
        headers,
        Some(body),
    )
    .await
}

/// GET /lmstudio/v1/models - List available models.
async fn lmstudio_list_models(State(state): State<DgwState>, headers: HeaderMap) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let lmstudio_conf = &conf.ai_gateway.lmstudio;

    let provider_config = ProviderConfigBuilder::new()
        .name("lmstudio")
        .endpoint(lmstudio_conf.get_endpoint())
        .api_key(lmstudio_conf.get_api_key())
        .api_key_required(false)
        .bearer_auth()
        .build()
        .expect("valid provider config");

    proxy_to_provider(
        &state,
        &provider_config,
        reqwest::Method::GET,
        "/v1/models",
        headers,
        None,
    )
    .await
}

/// POST /lmstudio/v1/chat/completions - Create a chat completion (supports SSE streaming).
async fn lmstudio_chat_completions(
    State(state): State<DgwState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let lmstudio_conf = &conf.ai_gateway.lmstudio;

    let provider_config = ProviderConfigBuilder::new()
        .name("lmstudio")
        .endpoint(lmstudio_conf.get_endpoint())
        .api_key(lmstudio_conf.get_api_key())
        .api_key_required(false)
        .bearer_auth()
        .build()
        .expect("valid provider config");

    let (_, body) = request.into_parts();
    proxy_to_provider(
        &state,
        &provider_config,
        reqwest::Method::POST,
        "/v1/chat/completions",
        headers,
        Some(body),
    )
    .await
}

/// POST /anthropic/v1/messages - Create a message using the Anthropic Messages API.
async fn anthropic_messages(
    State(state): State<DgwState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let anthropic_conf = &conf.ai_gateway.anthropic;

    let provider_config = ProviderConfigBuilder::new()
        .name("anthropic")
        .endpoint(anthropic_conf.get_endpoint())
        .api_key(anthropic_conf.get_api_key())
        .header_auth("x-api-key")
        .extra_header("anthropic-version", ANTHROPIC_API_VERSION)
        .build()
        .expect("valid provider config");

    let (_, body) = request.into_parts();
    proxy_to_provider(
        &state,
        &provider_config,
        reqwest::Method::POST,
        "/v1/messages",
        headers,
        Some(body),
    )
    .await
}

/// GET /openrouter/v1/models - List available models.
async fn openrouter_list_models(State(state): State<DgwState>, headers: HeaderMap) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let openrouter_conf = &conf.ai_gateway.openrouter;

    let provider_config = ProviderConfigBuilder::new()
        .name("openrouter")
        .endpoint(openrouter_conf.get_endpoint())
        .api_key(openrouter_conf.get_api_key())
        .bearer_auth()
        .build()
        .expect("valid provider config");

    proxy_to_provider(
        &state,
        &provider_config,
        reqwest::Method::GET,
        "/v1/models",
        headers,
        None,
    )
    .await
}

/// POST /openrouter/v1/chat/completions - Create a chat completion (supports SSE streaming).
async fn openrouter_chat_completions(
    State(state): State<DgwState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let openrouter_conf = &conf.ai_gateway.openrouter;

    let provider_config = ProviderConfigBuilder::new()
        .name("openrouter")
        .endpoint(openrouter_conf.get_endpoint())
        .api_key(openrouter_conf.get_api_key())
        .bearer_auth()
        .build()
        .expect("valid provider config");

    let (_, body) = request.into_parts();
    proxy_to_provider(
        &state,
        &provider_config,
        reqwest::Method::POST,
        "/v1/chat/completions",
        headers,
        Some(body),
    )
    .await
}

/// POST /azure-openai/chat/completions - Create a chat completion (supports SSE streaming).
async fn azure_openai_chat_completions(
    State(state): State<DgwState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let azure_conf = &conf.ai_gateway.azure_openai;

    let endpoint = azure_conf.build_endpoint("chat/completions");

    let provider_config = ProviderConfigBuilder::new()
        .name("azure-openai")
        .endpoint(endpoint)
        .api_key(azure_conf.get_api_key())
        .header_auth("api-key")
        .build()
        .expect("valid provider config");

    let (_, body) = request.into_parts();
    proxy_to_provider(&state, &provider_config, reqwest::Method::POST, "", headers, Some(body)).await
}

/// POST /azure-openai/completions - Create a text completion.
async fn azure_openai_completions(
    State(state): State<DgwState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let azure_conf = &conf.ai_gateway.azure_openai;

    let endpoint = azure_conf.build_endpoint("completions");

    let provider_config = ProviderConfigBuilder::new()
        .name("azure-openai")
        .endpoint(endpoint)
        .api_key(azure_conf.get_api_key())
        .header_auth("api-key")
        .build()
        .expect("valid provider config");

    let (_, body) = request.into_parts();
    proxy_to_provider(&state, &provider_config, reqwest::Method::POST, "", headers, Some(body)).await
}

/// POST /azure-openai/embeddings - Create embeddings.
async fn azure_openai_embeddings(
    State(state): State<DgwState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, HttpError> {
    let conf = state.conf_handle.get_conf();
    let azure_conf = &conf.ai_gateway.azure_openai;

    let endpoint = azure_conf.build_endpoint("embeddings");

    let provider_config = ProviderConfigBuilder::new()
        .name("azure-openai")
        .endpoint(endpoint)
        .api_key(azure_conf.get_api_key())
        .header_auth("api-key")
        .build()
        .expect("valid provider config");

    let (_, body) = request.into_parts();
    proxy_to_provider(&state, &provider_config, reqwest::Method::POST, "", headers, Some(body)).await
}
