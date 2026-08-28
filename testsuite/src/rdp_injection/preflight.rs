//! Provisions credentials over `/jet/preflight` the way DVLS does.

use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;

use super::tokens::{next_id, preflight_scope_token};
use super::{PROXY_PASSWORD, PROXY_USER, TARGET_PASSWORD};

pub async fn post_preflight(
    http_port: u16,
    provisioning_operations: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let preflight_token = preflight_scope_token()?;
    let body = serde_json::to_string(&provisioning_operations).context("serialize preflight body")?;
    let request = format!(
        "POST /jet/preflight HTTP/1.1\r\n\
         Host: 127.0.0.1:{http_port}\r\n\
         Content-Type: application/json\r\n\
         Authorization: Bearer {preflight_token}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );

    let mut stream = TcpStream::connect(("127.0.0.1", http_port))
        .await
        .context("connect to gateway HTTP")?;
    stream.write_all(request.as_bytes()).await.context("write preflight")?;
    stream.flush().await.context("flush preflight")?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .await
        .context("read preflight status")?;
    anyhow::ensure!(status_line.contains("200"), "preflight HTTP status was {status_line:?}");

    let mut content_length = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.context("read preflight header")?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some(value) = line
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim().to_owned())
        {
            content_length = Some(value.parse::<usize>().context("parse Content-Length")?);
        }
    }

    let response_body = if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await.context("read preflight body")?;
        String::from_utf8(buf).context("preflight body utf-8")?
    } else {
        let mut buf = String::new();
        reader
            .read_to_string(&mut buf)
            .await
            .context("read preflight eof body")?;
        buf
    };

    let json: serde_json::Value =
        serde_json::from_str(&response_body).with_context(|| format!("parse preflight JSON: {response_body}"))?;
    let outputs = json.as_array().context("preflight response is not an array")?;
    // Re-provisioning the same JTI emits an info alert, then still acks.
    let mut acked = 0usize;
    for output in outputs {
        match output["kind"].as_str() {
            Some("ack") => acked += 1,
            Some("alert") if output["alert_status"] == "info" => {}
            _ => anyhow::bail!("preflight operation was not ack: {output}"),
        }
    }
    anyhow::ensure!(acked > 0, "preflight returned no ack: {json}");
    Ok(json)
}

pub async fn provision_credentials(
    http_port: u16,
    association_token: &str,
    target_username: &str,
    time_to_live: u32,
    krb_kdc: Option<&str>,
) -> anyhow::Result<()> {
    provision_mapping(
        http_port,
        association_token,
        PROXY_USER,
        target_username,
        TARGET_PASSWORD,
        time_to_live,
        krb_kdc,
    )
    .await
}

pub async fn provision_mapping(
    http_port: u16,
    association_token: &str,
    proxy_username: &str,
    target_username: &str,
    target_password: &str,
    time_to_live: u32,
    krb_kdc: Option<&str>,
) -> anyhow::Result<()> {
    let mut provisioning_operations = vec![serde_json::json!({
        "id": next_id(),
        "kind": "provision-credentials",
        "token": association_token,
        "proxy_credential": {
            "kind": "username-password",
            "username": proxy_username,
            "password": PROXY_PASSWORD
        },
        "target_credential": {
            "kind": "username-password",
            "username": target_username,
            "password": target_password
        },
        "time_to_live": time_to_live
    })];

    if let Some(krb_kdc) = krb_kdc {
        provisioning_operations.push(serde_json::json!({
            "id": next_id(),
            "kind": "provision-connection-options",
            "token": association_token,
            "connection_options": { "krb_kdc": krb_kdc },
            "time_to_live": time_to_live
        }));
    }

    post_preflight(http_port, serde_json::Value::Array(provisioning_operations)).await?;
    Ok(())
}
