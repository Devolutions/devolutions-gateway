use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, ensure};
use base64::Engine as _;
use http::Method;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;

use crate::dvls::{AppCredential, Credential, Management, Session};
use crate::signer::{KeyPair, SignedHeaders};

#[derive(Clone)]
pub(crate) struct Target {
    pub(crate) base_url: String,
    /// The privileged session of the management API.
    pub(crate) session: Arc<Session>,
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
        credential: AppCredential,
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
            session: Arc::new(Session::new(credential)),
            ca_path: ca_path.map(Path::to_path_buf),
            authority_id,
            http: builder.build()?,
        })
    }

    pub(crate) fn management(&self) -> Management<'_> {
        Management::new(self, Credential::Session(&self.session))
    }

    /// The management API called with `credential`.
    pub(crate) fn management_as<'a>(&'a self, credential: Credential<'a>) -> Management<'a> {
        Management::new(self, credential)
    }

    /// Sends a request whose response must have a JSON body unless it is empty.
    pub(crate) async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        bearer: Option<&str>,
        signed: Option<&SignedHeaders>,
    ) -> anyhow::Result<Reply> {
        let (status, bytes) = self.exchange(method, path, body, bearer, signed).await?;
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).context("decode JSON response")?
        };
        Ok(Reply { status, body })
    }

    /// Sends a request and returns the response status and body bytes.
    pub(crate) async fn exchange(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        bearer: Option<&str>,
        signed: Option<&SignedHeaders>,
    ) -> anyhow::Result<(u16, Vec<u8>)> {
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
        Ok((status, bytes.to_vec()))
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
        let management = self.management();
        let token = management.create_token(1, Duration::from_secs(3600), None).await?;
        let key = KeyPair::generate()?;
        let reply = self.enroll(&token.text, &key, &json!({})).await?;
        let identity = Identity::from_enrollment(&token.text, key, &reply)?;
        management.revoke(&identity.identity_id).await?;
        management.delete_identity(&identity.identity_id).await?;
        management.revoke_token(&token.id).await?;
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

    pub(crate) async fn events(&self, identity_id: &str) -> anyhow::Result<Vec<Value>> {
        let reply = self
            .send(
                Method::GET,
                &format!("/__mock__/events?identity_id={identity_id}"),
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
                event["identity_id"] == identity_id,
                "mock event belongs to the wrong identity"
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

    /// Enrolls `key` with `token`, by a CSR naming the token's `u`.
    pub(crate) async fn enroll(&self, token: &str, key: &KeyPair, metadata: &Value) -> anyhow::Result<Reply> {
        let csr = key.csr(&token_base_url(token)?)?;
        self.agent(
            Method::POST,
            "/enroll",
            Some(&json!({ "csr": csr, "metadata": metadata })),
            Some(token),
        )
        .await
    }

    /// Renews `current` with `new_key`, by a CSR naming the identity's base URL.
    pub(crate) async fn renew(&self, current: &Identity, new_key: &KeyPair, metadata: &Value) -> anyhow::Result<Reply> {
        let body = serde_json::to_vec(&json!({ "csr": new_key.csr(&current.base_url)?, "metadata": metadata }))?;
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

    pub(crate) async fn trust_anchor(&self) -> anyhow::Result<Value> {
        let reply = self.agent(Method::GET, "/trust-anchor", None, None).await?;
        expect_status(&reply, 200)?;
        Ok(reply.body)
    }
}

pub(crate) struct Token {
    pub(crate) text: String,
    pub(crate) id: String,
}

pub(crate) struct Identity {
    pub(crate) identity_id: String,
    pub(crate) authority_id: String,
    pub(crate) thumbprint: String,
    pub(crate) certificate_chain: Vec<String>,
    pub(crate) agent_channel_url: Option<String>,
    pub(crate) config: Value,
    pub(crate) key: KeyPair,
    /// The `u` of the token that enrolled the identity, without its trailing slashes, which its renewal CSRs name.
    pub(crate) base_url: String,
}

impl Identity {
    /// The identity that `reply` enrolled with `token` for `key`.
    pub(crate) fn from_enrollment(token: &str, key: KeyPair, reply: &Reply) -> anyhow::Result<Self> {
        expect_status(reply, 200)?;
        let chain = reply.body["certificate_chain"]
            .as_array()
            .context("missing certificate chain")?
            .iter()
            .map(|entry| entry.as_str().context("invalid chain entry").map(str::to_owned))
            .collect::<anyhow::Result<Vec<_>>>()?;
        ensure!(!chain.is_empty(), "empty certificate chain");
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
            identity_id: field(&reply.body, "identity_id")?.to_owned(),
            authority_id: field(&reply.body, "authority_id")?.to_owned(),
            thumbprint: crate::signer::thumbprint(&chain[0])?,
            certificate_chain: chain,
            agent_channel_url,
            config: reply.body["config"].clone(),
            key,
            base_url: token_base_url(token)?,
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
    ensure!(
        server_time.ends_with('Z'),
        "error body server_time {server_time:?} does not end in Z"
    );
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

/// Returns the JSON object that the bag of `token` encodes ([CONTRACT.agent-identity.md] §2 "Enrollment token").
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
pub(crate) fn token_bag(token: &str) -> anyhow::Result<Value> {
    let bag = token.split('.').nth(1).context("token has no bag")?;
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(bag)
            .context("decode token bag")?,
    )
    .context("parse token bag")
}

/// Returns `token` with its bag replaced by `bag`, keeping its prefix and secret.
fn with_bag(token: &str, bag: &Value) -> anyhow::Result<String> {
    let (head, secret) = token.rsplit_once('.').context("token has no secret")?;
    let (prefix, _) = head.rsplit_once('.').context("token has no bag")?;
    Ok(format!(
        "{prefix}.{}.{secret}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(bag)?)
    ))
}

/// Returns `token` with the `u` of its bag replaced by `url`, keeping its other bag fields and its secret.
pub(crate) fn with_bag_url(token: &str, url: &str) -> anyhow::Result<String> {
    let mut bag = token_bag(token)?;
    bag["u"] = json!(url);
    with_bag(token, &bag)
}

/// Returns the `u` that the bag of `token` carries, without its trailing slashes, which is the URL the token's certificates name ([CONTRACT.agent-identity.md] §2 "Enrollment token" and §4 "Certificates").
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
pub(crate) fn token_base_url(token: &str) -> anyhow::Result<String> {
    Ok(field(&token_bag(token)?, "u")?.trim_end_matches('/').to_owned())
}

/// Splits the `https` URL `url` into its authority and its path, which is empty or starts with `/`.
pub(crate) fn https_authority_and_path(url: &str) -> anyhow::Result<(&str, &str)> {
    let rest = url.strip_prefix("https://").context("URL is not https")?;
    Ok(rest.find('/').map_or((rest, ""), |slash| rest.split_at(slash)))
}

/// Returns the `https` URL `url` with its scheme in upper case, which differs from `url` only as text.
pub(crate) fn with_upper_case_scheme(url: &str) -> anyhow::Result<String> {
    let (authority, path) = https_authority_and_path(url)?;
    Ok(format!("HTTPS://{authority}{path}"))
}

pub(crate) fn decoded_certificate(certificate: &str) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(certificate)
        .context("decode certificate")
}

/// The invisible format characters that no metadata value holds, as [CONTRACT.agent-identity.md] §3 "Metadata" lists them.
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
const INVISIBLE_FORMAT_CHARACTERS: [RangeInclusive<char>; 17] = [
    '\u{00AD}'..='\u{00AD}',
    '\u{034F}'..='\u{034F}',
    '\u{061C}'..='\u{061C}',
    '\u{115F}'..='\u{1160}',
    '\u{17B4}'..='\u{17B5}',
    '\u{180B}'..='\u{180F}',
    '\u{200B}'..='\u{200F}',
    '\u{202A}'..='\u{202E}',
    '\u{2060}'..='\u{206F}',
    '\u{3164}'..='\u{3164}',
    '\u{FE00}'..='\u{FE0F}',
    '\u{FEFF}'..='\u{FEFF}',
    '\u{FFA0}'..='\u{FFA0}',
    '\u{FFF0}'..='\u{FFFB}',
    '\u{1BCA0}'..='\u{1BCA3}',
    '\u{1D173}'..='\u{1D17A}',
    '\u{E0000}'..='\u{E0FFF}',
];

/// A code point strictly inside a listed range, so that no range end stands for it.
///
/// A list kept in pieces, with gaps where a range runs on, passes every range end, so these are sent as well:
/// U+2065 inside U+2060–U+206F, U+180D inside U+180B–U+180F, U+FFF8 inside U+FFF0–U+FFFB, and U+E0002, U+E001F and U+E0080 inside U+E0000–U+E0FFF.
pub(crate) const INTERIOR_INVISIBLE_FORMAT_CHARACTERS: [char; 6] = [
    '\u{2065}',
    '\u{180D}',
    '\u{FFF8}',
    '\u{E0002}',
    '\u{E001F}',
    '\u{E0080}',
];

pub(crate) fn is_invisible_format_character(character: char) -> bool {
    INVISIBLE_FORMAT_CHARACTERS
        .iter()
        .any(|range| range.contains(&character))
}

/// The first and last code point of each range of [`INVISIBLE_FORMAT_CHARACTERS`], in order.
///
/// An implementation that holds the list as ranges goes wrong at their ends, so these are the code points worth sending.
///
/// A single code point is both ends of its range, and appears once.
pub(crate) fn invisible_format_character_range_ends() -> Vec<char> {
    let mut ends = INVISIBLE_FORMAT_CHARACTERS
        .iter()
        .flat_map(|range| [*range.start(), *range.end()])
        .collect::<Vec<_>>();
    ends.dedup();
    ends
}

/// Code points that a metadata value may hold although an implementation could take them for invisible format characters.
///
/// They are each code point just outside a range of [`INVISIBLE_FORMAT_CHARACTERS`], which a range off by one refuses, and format characters (`Cf`) that the closed list leaves out, which a filter by general category refuses.
pub(crate) fn unlisted_format_character_neighbors() -> Vec<char> {
    let mut neighbors = INVISIBLE_FORMAT_CHARACTERS
        .iter()
        .flat_map(|range| [u32::from(*range.start()) - 1, u32::from(*range.end()) + 1])
        .filter_map(char::from_u32)
        .filter(|character| !is_invisible_format_character(*character))
        .collect::<Vec<_>>();
    // U+DFFFF, just below U+E0000, is a noncharacter (`Noncharacter_Code_Point` in PropList.txt).
    // That is deliberate: noncharacters are valid Unicode scalar values (Unicode Corrigendum #9), so a value holding one is accepted, and a failure at U+DFFFF means the implementation refuses a valid scalar value.
    // oracle: spec Unicode 15.0.0 PropList.txt §Noncharacter_Code_Point
    // oracle: spec Unicode 15.0.0 UnicodeData.txt §General_Category
    // U+0600 ARABIC NUMBER SIGN, U+110BD KAITHI NUMBER SIGN and U+13430 EGYPTIAN HIEROGLYPH VERTICAL JOINER are each `Cf`.
    neighbors.extend(['\u{0600}', '\u{110BD}', '\u{13430}']);
    neighbors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invisible_format_character_lists_match_the_contract() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
        assert_eq!(
            invisible_format_character_range_ends(),
            [
                '\u{00AD}',
                '\u{034F}',
                '\u{061C}',
                '\u{115F}',
                '\u{1160}',
                '\u{17B4}',
                '\u{17B5}',
                '\u{180B}',
                '\u{180F}',
                '\u{200B}',
                '\u{200F}',
                '\u{202A}',
                '\u{202E}',
                '\u{2060}',
                '\u{206F}',
                '\u{3164}',
                '\u{FE00}',
                '\u{FE0F}',
                '\u{FEFF}',
                '\u{FFA0}',
                '\u{FFF0}',
                '\u{FFFB}',
                '\u{1BCA0}',
                '\u{1BCA3}',
                '\u{1D173}',
                '\u{1D17A}',
                '\u{E0000}',
                '\u{E0FFF}',
            ]
        );
        let neighbors = unlisted_format_character_neighbors();
        assert_eq!(
            neighbors,
            [
                '\u{00AC}',
                '\u{00AE}',
                '\u{034E}',
                '\u{0350}',
                '\u{061B}',
                '\u{061D}',
                '\u{115E}',
                '\u{1161}',
                '\u{17B3}',
                '\u{17B6}',
                '\u{180A}',
                '\u{1810}',
                '\u{200A}',
                '\u{2010}',
                '\u{2029}',
                '\u{202F}',
                '\u{205F}',
                '\u{2070}',
                '\u{3163}',
                '\u{3165}',
                '\u{FDFF}',
                '\u{FE10}',
                '\u{FEFE}',
                '\u{FF00}',
                '\u{FF9F}',
                '\u{FFA1}',
                '\u{FFEF}',
                '\u{FFFC}',
                '\u{1BC9F}',
                '\u{1BCA4}',
                '\u{1D172}',
                '\u{1D17B}',
                '\u{DFFFF}',
                '\u{E1000}',
                '\u{0600}',
                '\u{110BD}',
                '\u{13430}',
            ]
        );
        assert!(!neighbors.into_iter().any(is_invisible_format_character));
    }

    #[test]
    fn interior_samples_are_listed_and_are_not_range_ends() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
        let ends = invisible_format_character_range_ends();
        for character in INTERIOR_INVISIBLE_FORMAT_CHARACTERS {
            assert!(
                is_invisible_format_character(character),
                "U+{:04X} is not in a listed range",
                u32::from(character)
            );
            assert!(
                !ends.contains(&character),
                "U+{:04X} is the end of a range, which the range ends already send",
                u32::from(character)
            );
        }
    }

    #[test]
    fn error_body_server_time_must_end_in_z() -> anyhow::Result<()> {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        let reply = |server_time: &str| Reply {
            status: 401,
            body: json!({ "error": "clock_skew", "message": "skewed", "server_time": server_time }),
        };
        expect_error(&reply("2026-09-24T12:00:00Z"), 401, "clock_skew")?;
        ensure!(
            expect_error(&reply("2026-09-24T12:00:00+00:00"), 401, "clock_skew").is_err(),
            "server_time with a numeric offset was accepted"
        );
        Ok(())
    }

    #[test]
    fn enrollment_accepts_unknown_fields_but_not_null_known_fields() -> anyhow::Result<()> {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let certificate = field(&vectors["keys"][0], "certificate")?;
        let token = format!(
            "dvaet1.{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"u":"https://host/mock"}"#),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5a; 32])
        );
        let mut reply = Reply {
            status: 200,
            body: json!({
                "authority_id": uuid::Uuid::new_v4(),
                "identity_id": uuid::Uuid::new_v4(),
                "certificate_chain": [certificate],
                "config": { "version": 1, "revision": 1 },
            }),
        };
        reply.body["channel_url"] = Value::Null;
        reply.body["extra_response_field"] = json!({ "nested": true });
        reply.body["config"]["product_field"] = json!("product-specific");
        let identity = Identity::from_enrollment(&token, KeyPair::generate()?, &reply)?;
        ensure!(
            identity.agent_channel_url.is_none() && identity.config["product_field"] == "product-specific",
            "unknown response fields or omitted config.agent_channel_url were not accepted"
        );
        reply.body["config"]["agent_channel_url"] = Value::Null;
        ensure!(
            Identity::from_enrollment(&token, KeyPair::generate()?, &reply).is_err(),
            "explicit null config.agent_channel_url was accepted"
        );
        reply.body["config"]["agent_channel_url"] = json!("https://host/mock");
        ensure!(
            Identity::from_enrollment(&token, KeyPair::generate()?, &reply)?
                .agent_channel_url
                .as_deref()
                == Some("https://host/mock"),
            "unknown top-level channel_url overrode config.agent_channel_url"
        );
        for name in ["authority_id", "identity_id", "certificate_chain", "config"] {
            let mut invalid = reply.clone();
            invalid.body[name] = Value::Null;
            ensure!(
                Identity::from_enrollment(&token, KeyPair::generate()?, &invalid).is_err(),
                "explicit null {name} was accepted"
            );
        }
        for name in ["version", "revision", "agent_channel_url"] {
            let mut invalid = reply.clone();
            invalid.body["config"][name] = Value::Null;
            ensure!(
                Identity::from_enrollment(&token, KeyPair::generate()?, &invalid).is_err(),
                "explicit null config.{name} was accepted"
            );
        }
        Ok(())
    }
}
