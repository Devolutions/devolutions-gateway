use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use futures::{SinkExt as _, StreamExt as _};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::task::{JoinError, JoinSet};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION as WS_AUTHORIZATION;
use tokio_tungstenite::tungstenite::http::{
    HeaderMap as WsHeaderMap, HeaderName as WsHeaderName, HeaderValue as WsHeaderValue,
};
use url::Url;

use crate::config::dto::PsuEventHubConnectionConf;
use crate::psu_event_hub::executor::EventHubExecutor;

const RECORD_SEPARATOR: char = '\u{1e}';

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NegotiateResponse {
    connection_id: Option<String>,
    connection_token: Option<String>,
}

pub(super) async fn run_connection(
    connection: PsuEventHubConnectionConf,
    executor: EventHubExecutor,
    mut shutdown_signal: devolutions_gateway_task::ShutdownSignal,
) -> anyhow::Result<()> {
    use backoff::backoff::Backoff as _;

    const RETRY_INITIAL_INTERVAL: Duration = Duration::from_secs(1);
    const RETRY_MAX_INTERVAL: Duration = Duration::from_secs(60);
    const RETRY_MULTIPLIER: f64 = 2.0;
    const CONNECTED_THRESHOLD: Duration = Duration::from_secs(30);

    let mut backoff = backoff::ExponentialBackoffBuilder::default()
        .with_initial_interval(RETRY_INITIAL_INTERVAL)
        .with_max_interval(RETRY_MAX_INTERVAL)
        .with_multiplier(RETRY_MULTIPLIER)
        .with_max_elapsed_time(None)
        .build();
    let mut execution_tasks = JoinSet::new();

    loop {
        let start = Instant::now();

        match run_single_connection(&connection, &executor, &mut shutdown_signal, &mut execution_tasks).await {
            Ok(()) => {
                info!(hub = %connection.hub, "Stopping PSU Event Hub connection");
                execution_tasks.shutdown().await;
                return Ok(());
            }
            Err(error) => {
                warn!(
                    hub = %connection.hub,
                    url = %connection.url,
                    error = format!("{error:#}"),
                    "PSU Event Hub connection failed"
                );
            }
        }

        if start.elapsed() > CONNECTED_THRESHOLD {
            backoff.reset();
        }

        let wait = match backoff.next_backoff() {
            Some(wait) => wait,
            None => {
                warn!("PSU Event Hub reconnect backoff exhausted, resetting");
                backoff.reset();
                RETRY_INITIAL_INTERVAL
            }
        };

        info!(hub = %connection.hub, ?wait, "Reconnecting PSU Event Hub after backoff");

        if !wait_before_reconnect(&mut shutdown_signal, wait, &mut execution_tasks).await {
            execution_tasks.shutdown().await;
            return Ok(());
        }
    }
}

async fn run_single_connection(
    connection: &PsuEventHubConnectionConf,
    executor: &EventHubExecutor,
    shutdown_signal: &mut devolutions_gateway_task::ShutdownSignal,
    execution_tasks: &mut JoinSet<()>,
) -> anyhow::Result<()> {
    let endpoint = endpoint_url(connection)?;
    let negotiate = negotiate_url(&endpoint)?;
    let headers = psu_headers(connection)?;
    let client = reqwest::Client::new();

    let mut request = client.post(negotiate.clone()).headers(headers.clone());
    if let Some(token) = &connection.app_token {
        request = request.bearer_auth(token);
    }

    let negotiate_response: NegotiateResponse = request
        .send()
        .await
        .with_context(|| format!("failed to negotiate SignalR connection at {negotiate}"))?
        .error_for_status()
        .with_context(|| format!("SignalR negotiate failed at {negotiate}"))?
        .json()
        .await
        .context("failed to parse SignalR negotiate response")?;

    let connection_token = negotiate_response
        .connection_token
        .or(negotiate_response.connection_id)
        .context("SignalR negotiate response did not include a connection token")?;

    let ws_url = websocket_url(&endpoint, &connection_token, connection.app_token.as_deref())?;
    let mut ws_request = ws_url.as_str().into_client_request()?;
    apply_ws_headers(ws_request.headers_mut(), &headers)?;
    if let Some(token) = &connection.app_token {
        let value = format!("Bearer {token}");
        ws_request
            .headers_mut()
            .insert(WS_AUTHORIZATION, WsHeaderValue::from_str(&value)?);
    }

    info!(hub = %connection.hub, url = %connection.url, "Connecting to PSU Event Hub");
    let (mut socket, _) = connect_async(ws_request)
        .await
        .with_context(|| format!("failed to connect PSU Event Hub WebSocket at {}", redact_url(&ws_url)))?;

    socket
        .send(Message::Text(
            format!(r#"{{"protocol":"json","version":1}}{RECORD_SEPARATOR}"#).into(),
        ))
        .await
        .context("failed to send SignalR handshake")?;

    info!(hub = %connection.hub, "Connected to PSU Event Hub");

    loop {
        tokio::select! {
            _ = shutdown_signal.wait() => {
                let _ = socket.close(None).await;
                break Ok(());
            }
            message = socket.next() => {
                let Some(message) = message else {
                    break Err(anyhow::anyhow!("SignalR WebSocket closed"));
                };

                let message = match message.context("failed to read SignalR WebSocket message") {
                    Ok(message) => message,
                    Err(error) => break Err(error),
                };

                let message_result = match message {
                    Message::Text(text) => handle_text_message(&mut socket, executor, &text, execution_tasks).await,
                    Message::Binary(bytes) => {
                        let text = match std::str::from_utf8(&bytes).context("SignalR binary message was not UTF-8") {
                            Ok(text) => text,
                            Err(error) => break Err(error),
                        };
                        handle_text_message(&mut socket, executor, text, execution_tasks).await
                    }
                    Message::Close(frame) => break Err(anyhow::anyhow!("SignalR WebSocket closed: {frame:?}")),
                    Message::Ping(payload) => socket
                        .send(Message::Pong(payload))
                        .await
                        .context("failed to send SignalR pong"),
                    Message::Pong(_) | Message::Frame(_) => Ok(()),
                };

                if let Err(error) = message_result {
                    break Err(error);
                }
            }
            Some(result) = execution_tasks.join_next(), if !execution_tasks.is_empty() => {
                log_execution_task_result(result);
            }
        }
    }
}

async fn wait_before_reconnect(
    shutdown_signal: &mut devolutions_gateway_task::ShutdownSignal,
    wait: Duration,
    execution_tasks: &mut JoinSet<()>,
) -> bool {
    let sleep = tokio::time::sleep(wait);
    tokio::pin!(sleep);

    loop {
        tokio::select! {
            _ = shutdown_signal.wait() => return false,
            _ = &mut sleep => return true,
            Some(result) = execution_tasks.join_next(), if !execution_tasks.is_empty() => {
                log_execution_task_result(result);
            }
        }
    }
}

async fn handle_text_message<S>(
    socket: &mut S,
    executor: &EventHubExecutor,
    text: &str,
    execution_tasks: &mut JoinSet<()>,
) -> anyhow::Result<()>
where
    S: futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    for frame in text.split(RECORD_SEPARATOR).filter(|frame| !frame.is_empty()) {
        let value: Value =
            serde_json::from_str(frame).with_context(|| format!("invalid SignalR JSON frame: {frame}"))?;
        let message_type = value.get("type").and_then(Value::as_u64);

        match message_type {
            None => {}
            Some(1) => handle_invocation(socket, executor, value, execution_tasks).await?,
            Some(6) => {}
            Some(7) => bail!("SignalR server sent close message"),
            Some(message_type) => trace!(message_type, "Ignoring unsupported SignalR message"),
        }
    }

    Ok(())
}

async fn handle_invocation<S>(
    socket: &mut S,
    executor: &EventHubExecutor,
    value: Value,
    execution_tasks: &mut JoinSet<()>,
) -> anyhow::Result<()>
where
    S: futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let target = value
        .get("target")
        .and_then(Value::as_str)
        .context("SignalR invocation missing target")?;
    let arguments = value
        .get("arguments")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let invocation_id = value.get("invocationId").and_then(Value::as_str);

    let result = executor.handle_invocation(target, arguments, execution_tasks)?;
    if let Some(invocation_id) = invocation_id {
        let completion = if let Some(result) = result {
            json!({
                "type": 3,
                "invocationId": invocation_id,
                "result": result,
            })
        } else {
            json!({
                "type": 3,
                "invocationId": invocation_id,
            })
        };

        socket
            .send(Message::Text(format!("{completion}{RECORD_SEPARATOR}").into()))
            .await
            .context("failed to send SignalR completion")?;
    }

    Ok(())
}

fn log_execution_task_result(result: Result<(), JoinError>) {
    if let Err(error) = result {
        error!(%error, "PSU Event Hub execution task panicked");
    }
}

fn endpoint_url(connection: &PsuEventHubConnectionConf) -> anyhow::Result<Url> {
    let endpoint = if connection.app_token.is_some() || connection.use_default_credentials {
        "autheventhub"
    } else {
        "eventhub"
    };

    let mut url = Url::parse(&format!("{}/{endpoint}", connection.url.as_str().trim_end_matches('/')))
        .context("failed to build PSU Event Hub URL")?;
    url.query_pairs_mut().append_pair("group", &connection.hub);
    Ok(url)
}

fn negotiate_url(endpoint: &Url) -> anyhow::Result<Url> {
    let mut url = endpoint.clone();
    let path = format!("{}/negotiate", endpoint.path().trim_end_matches('/'));
    url.set_path(&path);
    url.query_pairs_mut().append_pair("negotiateVersion", "1");
    Ok(url)
}

fn websocket_url(endpoint: &Url, connection_token: &str, access_token: Option<&str>) -> anyhow::Result<Url> {
    let mut url = endpoint.clone();
    let scheme = match endpoint.scheme() {
        "http" => "ws",
        "https" => "wss",
        scheme => bail!("unsupported SignalR endpoint scheme: {scheme}"),
    };
    url.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("failed to set SignalR WebSocket URL scheme"))?;
    url.query_pairs_mut().append_pair("id", connection_token);
    if let Some(access_token) = access_token {
        url.query_pairs_mut().append_pair("access_token", access_token);
    }
    Ok(url)
}

/// Returns a printable form of `url` with the SignalR `access_token` query parameter removed,
/// so we don't leak bearer tokens into logs/errors.
fn redact_url(url: &Url) -> String {
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != "access_token")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();

    let mut redacted = url.clone();
    if pairs.is_empty() {
        redacted.set_query(None);
    } else {
        redacted.query_pairs_mut().clear().extend_pairs(&pairs);
    }
    redacted.to_string()
}

fn psu_headers(connection: &PsuEventHubConnectionConf) -> anyhow::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    let identity = psu_identity();
    headers.insert(
        "PSUComputerName",
        psu_header_value("PSUComputerName", &computer_name())?,
    );
    headers.insert("PSUUserName", psu_header_value("PSUUserName", &identity.user_name)?);
    headers.insert(
        "PSUDomainName",
        psu_header_value("PSUDomainName", &identity.domain_name)?,
    );
    headers.insert("PSUVersion", HeaderValue::from_static(env!("CARGO_PKG_VERSION")));
    let description = sanitize_header_value(connection.description.as_deref().unwrap_or_default());
    headers.insert("PSUDescription", psu_header_value("PSUDescription", &description)?);
    if let Some(token) = &connection.app_token {
        let authorization = format!("Bearer {token}");
        headers.insert(AUTHORIZATION, psu_header_value("Authorization", &authorization)?);
    }
    Ok(headers)
}

fn psu_header_value(name: &str, value: &str) -> anyhow::Result<HeaderValue> {
    HeaderValue::from_str(value).with_context(|| format!("invalid PSU header value for {name}"))
}

fn apply_ws_headers(target: &mut WsHeaderMap, source: &HeaderMap) -> anyhow::Result<()> {
    for (name, value) in source {
        let name = WsHeaderName::from_bytes(name.as_str().as_bytes())?;
        let value = WsHeaderValue::from_bytes(value.as_bytes())?;
        target.insert(name, value);
    }
    Ok(())
}

fn computer_name() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| hostname::get().ok().and_then(|name| name.into_string().ok()))
        .unwrap_or_else(|| "localhost".to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PsuIdentity {
    user_name: String,
    domain_name: String,
}

fn psu_identity() -> PsuIdentity {
    platform_psu_identity().unwrap_or_else(env_psu_identity)
}

#[cfg(target_os = "windows")]
fn platform_psu_identity() -> Option<PsuIdentity> {
    use win_api_wrappers::identity::account::get_username;
    use win_api_wrappers::raw::Win32::Security::Authentication::Identity::NameSamCompatible;

    let name = get_username(NameSamCompatible).ok()?.to_string_lossy();
    let identity = split_sam_compatible_name(&name);
    if identity.user_name.is_empty() {
        None
    } else {
        Some(identity)
    }
}

#[cfg(not(target_os = "windows"))]
fn platform_psu_identity() -> Option<PsuIdentity> {
    None
}

fn split_sam_compatible_name(name: &str) -> PsuIdentity {
    if let Some((domain_name, user_name)) = name.split_once('\\') {
        PsuIdentity {
            user_name: user_name.to_owned(),
            domain_name: domain_name.to_owned(),
        }
    } else {
        PsuIdentity {
            user_name: name.to_owned(),
            domain_name: env_domain_name(),
        }
    }
}

fn env_psu_identity() -> PsuIdentity {
    PsuIdentity {
        user_name: std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_default(),
        domain_name: env_domain_name(),
    }
}

fn env_domain_name() -> String {
    std::env::var("USERDOMAIN").unwrap_or_default()
}

fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_control() && ch != '\t' { ' ' } else { ch })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connection(description: Option<String>) -> PsuEventHubConnectionConf {
        PsuEventHubConnectionConf {
            hub: "Hub".to_owned(),
            url: Url::parse("http://localhost:5000").expect("parse URL"),
            app_token: None,
            use_default_credentials: false,
            script_path: None,
            description,
        }
    }

    #[test]
    fn psu_headers_sanitize_description_control_characters() {
        let headers = psu_headers(&test_connection(Some("line 1\r\nline 2".to_owned()))).expect("build headers");

        assert_eq!(
            headers["PSUDescription"].to_str().expect("description header"),
            "line 1  line 2"
        );
    }

    #[test]
    fn sam_compatible_identity_splits_domain_and_user() {
        assert_eq!(
            split_sam_compatible_name("DOMAIN\\user"),
            PsuIdentity {
                user_name: "user".to_owned(),
                domain_name: "DOMAIN".to_owned(),
            }
        );
    }
}
