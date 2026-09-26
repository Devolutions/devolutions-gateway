use std::fmt;
use std::str::FromStr;

use anyhow::{Context as _, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use url::Url;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Token {
    value: Zeroizing<String>,
    base_url: Url,
}

impl Token {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        ensure!(value.len() <= 4096, "enrollment token exceeds length limit");
        let mut parts = value.split('.');
        ensure!(parts.next() == Some("dvaet1"), "unsupported enrollment token prefix");
        let bag = parts.next().context("missing enrollment token bag")?;
        let secret = parts.next().context("missing enrollment token secret")?;
        ensure!(parts.next().is_none(), "invalid enrollment token format");
        ensure!(
            !bag.is_empty() && bag.bytes().all(is_base64url),
            "invalid enrollment token bag"
        );
        ensure!(
            secret.len() == 43 && secret.bytes().all(is_base64url),
            "invalid enrollment token secret"
        );
        let decoded_secret = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(secret)
                .map_err(|_| anyhow::anyhow!("invalid enrollment token secret"))?,
        );
        ensure!(decoded_secret.len() == 32, "invalid enrollment token secret");
        let decoded_bag = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(bag)
                .map_err(|_| anyhow::anyhow!("invalid enrollment token bag"))?,
        );
        let fields: serde_json::Value =
            serde_json::from_slice(&decoded_bag).map_err(|_| anyhow::anyhow!("invalid enrollment token bag"))?;
        let base_url = fields
            .as_object()
            .and_then(|fields| fields.get("u"))
            .and_then(serde_json::Value::as_str)
            .and_then(|url| Url::parse(url).ok())
            .filter(|url| {
                url.scheme() == "https" && url.has_host() && url.query().is_none() && url.fragment().is_none()
            })
            .context("invalid enrollment authority URL")?;
        Ok(Self {
            value: Zeroizing::new(value.to_owned()),
            base_url,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub fn sha256_base64url(&self) -> String {
        sha256_base64url(&self.value)
    }

    pub fn sha256_hex(&self) -> String {
        sha256_hex(&self.value)
    }
}

/// Hashes the full UTF-8 token text, including when parsing rejects its format.
pub fn sha256_base64url(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

/// Hashes the full UTF-8 token text, including when parsing rejects its format.
pub fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

impl FromStr for Token {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> anyhow::Result<Self> {
        Self::parse(value)
    }
}

impl fmt::Display for Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted enrollment token]")
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Token([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_with_bag(bag: &str) -> String {
        format!("dvaet1.{}.{}", URL_SAFE_NO_PAD.encode(bag), "A".repeat(43))
    }

    #[test]
    fn accepts_valid_token_and_hashes_the_entire_string() -> anyhow::Result<()> {
        let raw = token_with_bag(r#"{"u":"https://example.test/dvls","extra":true}"#);
        let token = Token::parse(&raw)?;
        assert_eq!(token.base_url().as_str(), "https://example.test/dvls");
        assert_eq!(
            token.sha256_base64url(),
            URL_SAFE_NO_PAD.encode(Sha256::digest(raw.as_bytes()))
        );
        assert_eq!(token.sha256_hex(), hex::encode(Sha256::digest(raw.as_bytes())));
        assert_eq!(sha256_hex(&raw), token.sha256_hex());
        assert_eq!(token.sha256_hex().len(), 64);
        assert!(!format!("{token:?} {token}").contains(&raw));
        assert!(!format!("{token:?} {token}").contains(&raw[..12]));
        Ok(())
    }

    #[test]
    fn rejects_every_malformed_token_locally_without_exposing_it() {
        let valid = token_with_bag(r#"{"u":"https://example.test/dvls"}"#);
        let invalid = [
            valid.replacen("dvaet1", "dvaet2", 1),
            valid.replace("dvaet1.", "dvaet1.."),
            token_with_bag("not-json"),
            token_with_bag(r#"["not-an-object"]"#),
            token_with_bag(r#"{"other":"https://example.test"}"#),
            token_with_bag(r#"{"u":"http://example.test"}"#),
            token_with_bag(r#"{"u":"https://example.test?query=true"}"#),
            token_with_bag(r##"{"u":"https://example.test/#fragment"}"##),
            token_with_bag(r#"{"u":"relative/path"}"#),
            token_with_bag(r#"{"u":123}"#),
            format!("{valid}A"),
            valid[..valid.len() - 1].to_owned(),
            format!("{valid}.extra"),
            format!("dvaet1.{}.{}", "A".repeat(4096), "A".repeat(43)),
            valid.replace(".AAAA", ".!!!!"),
        ];
        for raw in invalid {
            let error = Token::parse(&raw).expect_err("malformed token was accepted");
            assert!(!error.to_string().contains(&raw), "{error}");
        }
    }
}
