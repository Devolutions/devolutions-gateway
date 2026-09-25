use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, ensure};
use base64::Engine as _;
use http::Method;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;

use crate::signer::{KeyPair, SignedHeaders};

#[derive(Clone)]
pub(crate) struct Target {
    pub(crate) base_url: String,
    pub(crate) admin_token: String,
    pub(crate) ca_path: Option<PathBuf>,
    pub(crate) authority_id: Option<uuid::Uuid>,
    pub(crate) http: reqwest::Client,
}

#[derive(Clone)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) body: Value,
}

impl Target {
    pub(crate) fn new(
        base_url: String,
        admin_token: String,
        ca_path: Option<&Path>,
        authority_id: Option<&str>,
    ) -> anyhow::Result<Self> {
        let url = reqwest::Url::parse(&base_url).context("parse base URL")?;
        ensure!(url.scheme() == "https", "base URL must use https");
        ensure!(
            url.query().is_none() && url.fragment().is_none(),
            "base URL cannot have a query or fragment"
        );
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(8));
        if let Some(path) = ca_path {
            let pem = std::fs::read(path).context("read trusted root PEM")?;
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
        }
        let authority_id = authority_id
            .map(|id| {
                let parsed = uuid::Uuid::parse_str(id).context("invalid known authority ID")?;
                ensure!(
                    parsed.to_string() == id,
                    "authority ID must be a lowercase hyphenated UUID"
                );
                Ok(parsed)
            })
            .transpose()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            admin_token,
            ca_path: ca_path.map(Path::to_path_buf),
            authority_id,
            http: builder.build()?,
        })
    }

    pub(crate) async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        bearer: Option<&str>,
        signed: Option<&SignedHeaders>,
    ) -> anyhow::Result<Reply> {
        let mut request = self.http.request(method, format!("{}{path}", self.base_url));
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        if let Some(body) = body {
            request = request.header("content-type", "application/json").body(body.to_vec());
        }
        if let Some(signed) = signed {
            request = request
                .header("signature-input", &signed.input)
                .header("signature", &signed.signature);
            if let Some(digest) = &signed.digest {
                request = request.header("content-digest", digest);
            }
        }
        let response = request.send().await.context("send HTTP request")?;
        let status = response.status().as_u16();
        let bytes = response.bytes().await.context("read HTTP response")?;
        let body = decode_reply_body(path, status, &bytes)?;
        Ok(Reply { status, body })
    }

    pub(crate) async fn admin(&self, method: Method, path: &str, body: Option<&Value>) -> anyhow::Result<Reply> {
        let bytes = body.map(serde_json::to_vec).transpose()?;
        self.send(
            method,
            &format!("/api/v3/agent-identity{path}"),
            bytes.as_deref(),
            Some(&self.admin_token),
            None,
        )
        .await
    }

    pub(crate) async fn agent(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        token: Option<&str>,
    ) -> anyhow::Result<Reply> {
        let bytes = body.map(serde_json::to_vec).transpose()?;
        self.send(
            method,
            &format!("/api/agent-identity/v1{path}"),
            bytes.as_deref(),
            token,
            None,
        )
        .await
    }

    pub(crate) async fn control(&self, path: &str, body: &Value) -> anyhow::Result<Reply> {
        let bytes = serde_json::to_vec(body)?;
        self.send(Method::POST, &format!("/__mock__/{path}"), Some(&bytes), None, None)
            .await
    }

    pub(crate) async fn reset(&self) -> anyhow::Result<()> {
        let reply = self.control("reset", &json!({})).await?;
        expect_status(&reply, 200)?;
        if let Some(known) = self.authority_id {
            ensure!(
                reply.body["authority_id"] == known.to_string(),
                "mock authority ID changed"
            );
        }
        Ok(())
    }

    pub(crate) async fn channel_available(&self) -> anyhow::Result<bool> {
        let token = self.create_token(1, Duration::from_secs(3600), None).await?;
        let key = KeyPair::generate()?;
        let reply = self.enroll(&token.text, &key, &json!({})).await?;
        let identity = Identity::from_enrollment(key, &reply)?;
        self.revoke(&identity.device_id).await?;
        expect_status(
            &self
                .admin(Method::DELETE, &format!("/devices/{}", identity.device_id), None)
                .await?,
            204,
        )?;
        expect_status(
            &self
                .admin(Method::DELETE, &format!("/enrollment-tokens/{}", token.id), None)
                .await?,
            204,
        )?;
        Ok(identity.agent_channel_url.is_some())
    }

    pub(crate) async fn requests(&self, token: Option<&Token>) -> anyhow::Result<Value> {
        let path = token.map_or_else(
            || "/__mock__/requests".to_owned(),
            |token| format!("/__mock__/requests?token_id={}", token.id),
        );
        let reply = self.send(Method::GET, &path, None, None, None).await?;
        expect_status(&reply, 200)?;
        Ok(reply.body)
    }

    pub(crate) async fn events(&self, device_id: &str) -> anyhow::Result<Vec<Value>> {
        let reply = self
            .send(
                Method::GET,
                &format!("/__mock__/events?device_id={device_id}"),
                None,
                None,
                None,
            )
            .await?;
        expect_status(&reply, 200)?;
        let events = reply.body["events"].as_array().context("mock events are missing")?;
        let mut previous = 0;
        for event in events {
            ensure!(
                event["device_id"] == device_id,
                "mock event belongs to the wrong device"
            );
            let seq = count(event, "seq")?;
            ensure!(seq > previous, "mock event sequences are not strictly increasing");
            previous = seq;
        }
        Ok(events.clone())
    }

    pub(crate) async fn paused_stream_ids(&self) -> anyhow::Result<Vec<String>> {
        let reply = self.send(Method::GET, "/__mock__/handshake", None, None, None).await?;
        expect_status(&reply, 200)?;
        reply.body["paused_stream_ids"]
            .as_array()
            .context("mock paused-stream ids are missing")?
            .iter()
            .map(|id| id.as_str().context("invalid paused-stream id").map(str::to_owned))
            .collect()
    }

    pub(crate) async fn faults(&self, faults: &Value) -> anyhow::Result<()> {
        expect_status(&self.control("faults", faults).await?, 200)
    }

    pub(crate) async fn advance(&self, secs: i64) -> anyhow::Result<()> {
        expect_status(&self.control("time/advance", &json!({ "secs": secs })).await?, 200)
    }

    pub(crate) async fn create_token(
        &self,
        max_uses: u32,
        lifetime: Duration,
        friendly_name_format: Option<&str>,
    ) -> anyhow::Result<Token> {
        let expires = (time::OffsetDateTime::now_utc() + time::Duration::seconds(i64::try_from(lifetime.as_secs())?))
            .format(&Rfc3339)?;
        let mut body = json!({
            "name": format!("conformance-{}", uuid::Uuid::new_v4()),
            "maxUses": max_uses,
            "expiresAt": expires,
        });
        if let Some(format) = friendly_name_format {
            body["friendlyNameFormat"] = Value::String(format.to_owned());
        }
        let reply = self.admin(Method::POST, "/enrollment-tokens", Some(&body)).await?;
        expect_status(&reply, 201)?;
        Ok(Token {
            text: field(&reply.body, "token")?.to_owned(),
            id: field(&reply.body["record"], "id")?.to_owned(),
        })
    }

    pub(crate) async fn enroll(&self, token: &str, key: &KeyPair, metadata: &Value) -> anyhow::Result<Reply> {
        self.agent(
            Method::POST,
            "/enroll",
            Some(&json!({ "csr": key.csr, "metadata": metadata })),
            Some(token),
        )
        .await
    }

    pub(crate) async fn renew(&self, current: &Identity, new_key: &KeyPair, metadata: &Value) -> anyhow::Result<Reply> {
        let body = serde_json::to_vec(&json!({ "csr": new_key.csr, "metadata": metadata }))?;
        let headers = current.key.sign_now(&current.thumbprint, "renew", Some(&body));
        self.signed_renew(&body, &headers, None).await
    }

    pub(crate) async fn signed_renew(
        &self,
        body: &[u8],
        headers: &SignedHeaders,
        token: Option<&str>,
    ) -> anyhow::Result<Reply> {
        self.send(
            Method::POST,
            "/api/agent-identity/v1/renew",
            Some(body),
            token,
            Some(headers),
        )
        .await
    }

    pub(crate) async fn confirm(&self, identity: &Identity) -> anyhow::Result<Reply> {
        let headers = identity.key.sign_now(&identity.thumbprint, "confirm", None);
        self.signed_confirm(&headers, None).await
    }

    pub(crate) async fn signed_confirm(&self, headers: &SignedHeaders, body: Option<&[u8]>) -> anyhow::Result<Reply> {
        self.send(
            Method::POST,
            "/api/agent-identity/v1/confirm",
            body,
            None,
            Some(headers),
        )
        .await
    }

    pub(crate) async fn check_in(&self, identity: &Identity, metadata: &Value) -> anyhow::Result<Reply> {
        let body = serde_json::to_vec(&json!({ "metadata": metadata }))?;
        let headers = identity.key.sign_now(&identity.thumbprint, "check-in", Some(&body));
        self.signed_check_in(&body, &headers).await
    }

    pub(crate) async fn signed_check_in(&self, body: &[u8], headers: &SignedHeaders) -> anyhow::Result<Reply> {
        self.send(
            Method::POST,
            "/api/agent-identity/v1/check-in",
            Some(body),
            None,
            Some(headers),
        )
        .await
    }

    pub(crate) async fn device(&self, id: &str) -> anyhow::Result<Reply> {
        self.admin(Method::GET, &format!("/devices/{id}"), None).await
    }

    pub(crate) async fn devices_for(&self, token: &Token, extra_query: &str) -> anyhow::Result<Reply> {
        let page_size = if extra_query.contains("pageSize=") {
            ""
        } else {
            "&pageSize=100"
        };
        self.admin(
            Method::GET,
            &format!("/devices?enrollmentTokenId={}{page_size}{extra_query}", token.id),
            None,
        )
        .await
    }

    pub(crate) async fn token_record(&self, id: &str) -> anyhow::Result<Reply> {
        self.admin(Method::GET, &format!("/enrollment-tokens/{id}"), None).await
    }

    pub(crate) async fn revoke(&self, id: &str) -> anyhow::Result<()> {
        expect_status(
            &self.admin(Method::POST, &format!("/devices/{id}/revoke"), None).await?,
            204,
        )
    }

    pub(crate) async fn rotate(&self, deadline: Option<&str>) -> anyhow::Result<Reply> {
        let body = deadline.map_or_else(|| json!({}), |value| json!({ "deadline": value }));
        self.admin(Method::POST, "/ca/rotation", Some(&body)).await
    }

    pub(crate) async fn trust_anchor(&self) -> anyhow::Result<Value> {
        let reply = self.agent(Method::GET, "/trust-anchor", None, None).await?;
        expect_status(&reply, 200)?;
        Ok(reply.body)
    }
}

fn decode_reply_body(path: &str, status: u16, bytes: &[u8]) -> anyhow::Result<Value> {
    if bytes.is_empty() || (path.starts_with("/api/v3/agent-identity") && !(200..300).contains(&status)) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(bytes).context("decode JSON response")
}

pub(crate) struct Token {
    pub(crate) text: String,
    pub(crate) id: String,
}

pub(crate) struct Identity {
    pub(crate) device_id: String,
    pub(crate) authority_id: String,
    pub(crate) thumbprint: String,
    pub(crate) certificate_chain: Vec<String>,
    pub(crate) agent_channel_url: Option<String>,
    pub(crate) config: Value,
    pub(crate) key: KeyPair,
}

impl Identity {
    pub(crate) fn from_enrollment(key: KeyPair, reply: &Reply) -> anyhow::Result<Self> {
        expect_status(reply, 200)?;
        let chain = reply.body["certificate_chain"]
            .as_array()
            .context("missing certificate chain")?
            .iter()
            .map(|entry| entry.as_str().context("invalid chain entry").map(str::to_owned))
            .collect::<anyhow::Result<Vec<_>>>()?;
        ensure!(!chain.is_empty(), "empty certificate chain");
        ensure!(
            reply.body.get("channel_url").is_none(),
            "enrollment used obsolete top-level channel_url"
        );
        let config = reply.body["config"].as_object().context("missing enrollment config")?;
        ensure!(
            config.get("version") == Some(&json!(1)),
            "enrollment config.version is not 1"
        );
        ensure!(
            config.get("revision").and_then(Value::as_u64).is_some(),
            "enrollment config.revision is not an unsigned integer"
        );
        let agent_channel_url = match config.get("agent_channel_url") {
            None => None,
            Some(Value::String(url)) => Some(url.clone()),
            Some(_) => anyhow::bail!("enrollment config.agent_channel_url must be a string when present"),
        };
        Ok(Self {
            device_id: field(&reply.body, "device_id")?.to_owned(),
            authority_id: field(&reply.body, "authority_id")?.to_owned(),
            thumbprint: crate::signer::thumbprint(&chain[0])?,
            certificate_chain: chain,
            agent_channel_url,
            config: reply.body["config"].clone(),
            key,
        })
    }

    pub(crate) fn adopt_certificate(&mut self, chain: &Value, key: KeyPair) -> anyhow::Result<()> {
        let chain = chain
            .as_array()
            .context("missing renewal certificate chain")?
            .iter()
            .map(|entry| entry.as_str().context("invalid chain entry").map(str::to_owned))
            .collect::<anyhow::Result<Vec<_>>>()?;
        ensure!(!chain.is_empty(), "empty renewal certificate chain");
        self.thumbprint = crate::signer::thumbprint(&chain[0])?;
        self.certificate_chain = chain;
        self.key = key;
        Ok(())
    }
}

pub(crate) fn expect_status(reply: &Reply, status: u16) -> anyhow::Result<()> {
    ensure!(
        reply.status == status,
        "expected HTTP {status}, got HTTP {} ({})",
        reply.status,
        reply.body["error"].as_str().unwrap_or("no error code")
    );
    Ok(())
}

pub(crate) fn expect_error(reply: &Reply, status: u16, code: &str) -> anyhow::Result<()> {
    expect_status(reply, status)?;
    ensure!(
        reply.body["error"] == code,
        "expected {code}, got {}",
        reply.body["error"]
    );
    ensure!(
        reply.body["message"].as_str().is_some_and(|value| !value.is_empty()),
        "missing error message"
    );
    let server_time = field(&reply.body, "server_time")?;
    time::OffsetDateTime::parse(server_time, &Rfc3339).context("invalid server_time")?;
    Ok(())
}

pub(crate) fn field<'a>(value: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    value[key]
        .as_str()
        .with_context(|| format!("missing string field {key}"))
}

pub(crate) fn count(value: &Value, key: &str) -> anyhow::Result<u64> {
    value[key]
        .as_u64()
        .with_context(|| format!("missing number field {key}"))
}

pub(crate) fn decoded_certificate(certificate: &str) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(certificate)
        .context("decode certificate")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_denials_are_status_only_but_agent_errors_need_json() -> anyhow::Result<()> {
        let opaque = b"<html>access denied</html>";
        ensure!(
            decode_reply_body("/api/v3/agent-identity/devices", 403, opaque)?.is_null(),
            "admin denial required a JSON body"
        );
        ensure!(
            decode_reply_body("/api/agent-identity/v1/renew", 401, opaque).is_err(),
            "agent-facing error accepted a non-JSON body"
        );
        Ok(())
    }

    #[test]
    fn enrollment_omission_differs_from_explicit_null() -> anyhow::Result<()> {
        let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let certificate = field(&vectors["keys"][0], "certificate")?;
        let mut reply = Reply {
            status: 200,
            body: json!({
                "authority_id": uuid::Uuid::new_v4(),
                "device_id": uuid::Uuid::new_v4(),
                "certificate_chain": [certificate],
                "config": { "version": 1, "revision": 1 },
            }),
        };
        ensure!(
            Identity::from_enrollment(KeyPair::generate()?, &reply)?
                .agent_channel_url
                .is_none(),
            "omitted config.agent_channel_url was not accepted"
        );
        reply.body["config"]["agent_channel_url"] = Value::Null;
        ensure!(
            Identity::from_enrollment(KeyPair::generate()?, &reply).is_err(),
            "explicit null config.agent_channel_url was accepted"
        );
        reply.body["config"]["agent_channel_url"] = json!("https://host/mock");
        reply.body["channel_url"] = Value::Null;
        ensure!(
            Identity::from_enrollment(KeyPair::generate()?, &reply).is_err(),
            "obsolete top-level channel_url was accepted"
        );
        Ok(())
    }
}
