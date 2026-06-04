use anyhow::{Context as _, bail};
use futures::{SinkExt as _, StreamExt as _};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json};
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
    loop {
        match run_single_connection(&connection, &executor, &mut shutdown_signal).await {
            Ok(()) => {
                info!(hub = %connection.hub, "Stopping PSU Event Hub connection");
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

        tokio::select! {
            _ = shutdown_signal.wait() => return Ok(()),
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
        }
    }
}

async fn run_single_connection(
    connection: &PsuEventHubConnectionConf,
    executor: &EventHubExecutor,
    shutdown_signal: &mut devolutions_gateway_task::ShutdownSignal,
) -> anyhow::Result<()> {
    if connection.use_default_credentials && connection.app_token.is_none() {
        warn!(
            hub = %connection.hub,
            "PSU Event Hub UseDefaultCredentials is configured, but Windows default credentials are not implemented yet"
        );
    }

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
                return Ok(());
            }
            message = socket.next() => {
                let Some(message) = message else {
                    bail!("SignalR WebSocket closed");
                };

                match message.context("failed to read SignalR WebSocket message")? {
                    Message::Text(text) => handle_text_message(&mut socket, executor, &text).await?,
                    Message::Binary(bytes) => {
                        let text = String::from_utf8(bytes.to_vec()).context("SignalR binary message was not UTF-8")?;
                        handle_text_message(&mut socket, executor, &text).await?;
                    }
                    Message::Close(frame) => bail!("SignalR WebSocket closed: {frame:?}"),
                    Message::Ping(payload) => socket.send(Message::Pong(payload)).await?,
                    Message::Pong(_) => {}
                    Message::Frame(_) => {}
                }
            }
        }
    }
}

async fn handle_text_message<S>(socket: &mut S, executor: &EventHubExecutor, text: &str) -> anyhow::Result<()>
where
    S: futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    for frame in text.split(RECORD_SEPARATOR).filter(|frame| !frame.is_empty()) {
        let value: Value =
            serde_json::from_str(frame).with_context(|| format!("invalid SignalR JSON frame: {frame}"))?;
        let message_type = value.get("type").and_then(Value::as_u64);

        match message_type {
            None => {}
            Some(1) => handle_invocation(socket, executor, value).await?,
            Some(6) => {}
            Some(7) => bail!("SignalR server sent close message"),
            Some(message_type) => trace!(message_type, "Ignoring unsupported SignalR message"),
        }
    }

    Ok(())
}

async fn handle_invocation<S>(socket: &mut S, executor: &EventHubExecutor, value: Value) -> anyhow::Result<()>
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

    let result = executor.handle_invocation(target, arguments)?;
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
    headers.insert("PSUComputerName", HeaderValue::from_str(&computer_name())?);
    headers.insert("PSUUserName", HeaderValue::from_str(&user_name())?);
    headers.insert("PSUDomainName", HeaderValue::from_str(&domain_name())?);
    headers.insert("PSUVersion", HeaderValue::from_static(env!("CARGO_PKG_VERSION")));
    headers.insert(
        "PSUDescription",
        HeaderValue::from_str(connection.description.as_deref().unwrap_or_default())?,
    );
    if let Some(token) = &connection.app_token {
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}"))?);
    }
    Ok(headers)
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

fn user_name() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default()
}

fn domain_name() -> String {
    std::env::var("USERDOMAIN").unwrap_or_default()
}
