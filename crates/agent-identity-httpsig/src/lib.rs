use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use agent_identity_keys::IdentityKey;
use anyhow::{Context as _, anyhow, ensure};
use base64::Engine as _;
use base64::engine::general_purpose;
use http::uri::PathAndQuery;
use http::{HeaderValue, Method, Request, Uri};
use httpsig::prelude::message_component::{HttpMessageComponent, HttpMessageComponentId};
use httpsig::prelude::{
    AlgorithmName, HttpSigError, HttpSigResult, HttpSignatureBase, HttpSignatureParams, SigningKey,
};
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};
use tokio::sync::oneshot;
use tower::{Layer, Service};

const SIGNATURE_DURATION_SECS: u64 = 60;
const MAX_STRUCTURED_FIELD_INTEGER: u64 = 999_999_999_999_999;
const CONNECT_RPC_PATH: &str = "/devolutions.agent.channel.v1.AgentChannel/Connect";
type BoxError = Box<dyn Error + Send + Sync>;

/// The Agent Identity operation covered by a request signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tag {
    Renew,
    Connect,
    Confirm,
    CheckIn,
}

impl Tag {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Renew => "renew",
            Self::Connect => "connect",
            Self::Confirm => "confirm",
            Self::CheckIn => "check-in",
        }
    }

    const fn covers_body(self) -> bool {
        matches!(self, Self::Renew | Self::CheckIn)
    }
}

/// Signs Agent Identity requests with a device key and its leaf certificate's thumbprint.
#[derive(Clone)]
pub struct RequestSigner {
    key: Arc<dyn IdentityKey>,
    keyid: String,
}

impl RequestSigner {
    pub fn new(key: Arc<dyn IdentityKey>, leaf_certificate_der: &[u8]) -> Self {
        let keyid = general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(leaf_certificate_der));
        Self { key, keyid }
    }

    /// Signs one request with a fresh 16-byte nonce and the supplied Unix timestamp.
    ///
    /// Renew and check-in require the exact body bytes; connect and confirm do not cover a body.
    pub fn sign(&self, tag: Tag, method: &Method, body: Option<&[u8]>, created: u64) -> anyhow::Result<SignedHeaders> {
        let nonce = rand::rng().random::<[u8; 16]>();
        self.sign_with_nonce(tag, method, body, created, &nonce)
    }

    fn sign_with_nonce(
        &self,
        tag: Tag,
        method: &Method,
        body: Option<&[u8]>,
        created: u64,
        nonce: &[u8; 16],
    ) -> anyhow::Result<SignedHeaders> {
        let content_digest = if tag.covers_body() {
            let body = body.ok_or_else(|| anyhow!("missing signed request body"))?;
            Some(content_digest(body)?)
        } else {
            None
        };
        let nonce = general_purpose::URL_SAFE_NO_PAD.encode(nonce);
        let base = self.signature_base(tag, method, content_digest.as_ref(), created, &nonce)?;
        let signing_key = DeviceSigningKey(self.key.as_ref(), &self.keyid);
        let headers = base
            .build_signature_headers(&signing_key, Some("sig"))
            .context("sign identity request")?;

        Ok(SignedHeaders {
            signature_input: HeaderValue::from_str(&headers.signature_input_header_value())
                .context("build signature input header")?,
            signature: HeaderValue::from_str(&headers.signature_header_value()).context("build signature header")?,
            content_digest,
            nonce,
        })
    }

    fn signature_base(
        &self,
        tag: Tag,
        method: &Method,
        content_digest: Option<&HeaderValue>,
        created: u64,
        nonce: &str,
    ) -> anyhow::Result<HttpSignatureBase> {
        let expires = created
            .checked_add(SIGNATURE_DURATION_SECS)
            .ok_or_else(|| anyhow!("signature expiration overflow"))?;
        ensure!(
            expires <= MAX_STRUCTURED_FIELD_INTEGER,
            "signature timestamp exceeds structured-field range"
        );

        let method_id = HttpMessageComponentId::try_from("@method")?;
        let method_values = [method.as_str().to_owned()];
        let method_component = HttpMessageComponent::try_from((&method_id, method_values.as_slice()))?;
        let mut components = vec![method_component];

        if let Some(digest) = content_digest {
            let digest_id = HttpMessageComponentId::try_from("content-digest")?;
            let digest_values = [digest.to_str()?.to_owned()];
            components.push(HttpMessageComponent::try_from((&digest_id, digest_values.as_slice()))?);
        }

        let covered_components = components
            .iter()
            .map(|component| component.id.clone())
            .collect::<Vec<_>>();
        let mut params = HttpSignatureParams::try_new(&covered_components)?;
        let signing_key = DeviceSigningKey(self.key.as_ref(), &self.keyid);
        params
            .set_created(created)
            .set_expires(expires)
            .set_nonce(nonce)
            .set_key_info(&signing_key)
            .set_tag(tag.as_str());
        Ok(HttpSignatureBase::try_new(&components, &params)?)
    }
}

struct DeviceSigningKey<'a>(&'a dyn IdentityKey, &'a str);

impl SigningKey for DeviceSigningKey<'_> {
    fn sign(&self, data: &[u8]) -> HttpSigResult<Vec<u8>> {
        let signature: p256::ecdsa::Signature = signature::Signer::try_sign(self.0, data)
            .map_err(|_| HttpSigError::InvalidSignature("device key signing failed".to_owned()))?;
        Ok(signature.to_bytes().to_vec())
    }

    fn key_id(&self) -> String {
        self.1.to_owned()
    }

    fn alg(&self) -> AlgorithmName {
        AlgorithmName::EcdsaP256Sha256
    }
}

fn content_digest(body: &[u8]) -> anyhow::Result<HeaderValue> {
    let digest = Sha256::digest(body);
    let digest_bytes: &[u8] = digest.as_ref();
    let mut serializer = sfv::DictSerializer::new();
    let _ = serializer.bare_item(
        sfv::KeyRef::constant("sha-256"),
        sfv::RefBareItem::ByteSequence(digest_bytes),
    );
    let value = serializer.finish().ok_or_else(|| anyhow!("empty content digest"))?;
    Ok(HeaderValue::from_str(&value)?)
}

/// HTTP headers returned by [`RequestSigner::sign`].
pub struct SignedHeaders {
    pub signature_input: HeaderValue,
    pub signature: HeaderValue,
    pub content_digest: Option<HeaderValue>,
    /// The exact serialized nonce signed in `signature_input`, for channel proofs.
    pub nonce: String,
}

/// Carries one signed opening nonce from the channel layer back to its caller.
#[derive(Clone)]
pub struct OpeningNonce(Arc<Mutex<Option<oneshot::Sender<String>>>>);

impl OpeningNonce {
    /// Attach the sender to a tonic `Connect` request's extensions and await the receiver for `Hello.proof`.
    pub fn new() -> (Self, oneshot::Receiver<String>) {
        let (sender, receiver) = oneshot::channel();
        (Self(Arc::new(Mutex::new(Some(sender)))), receiver)
    }

    fn send(self, nonce: String) -> anyhow::Result<()> {
        let sender = self
            .0
            .lock()
            .map_err(|_| anyhow!("channel nonce handoff poisoned"))?
            .take()
            .ok_or_else(|| anyhow!("channel nonce handoff already used"))?;
        sender
            .send(nonce)
            .map_err(|_| anyhow!("channel nonce receiver dropped"))
    }
}

/// Signs each gRPC stream opening and prepends the channel URL's path.
#[derive(Clone)]
pub struct ChannelLayer {
    signer: RequestSigner,
    path_prefix: String,
    clock_offset: i64,
}

impl ChannelLayer {
    pub fn new(signer: RequestSigner, base_url: &url::Url) -> Self {
        Self {
            signer,
            path_prefix: base_url.path().trim_end_matches('/').to_owned(),
            clock_offset: 0,
        }
    }

    /// Adjusts signing time by `server_time - local_time` for one clock-skew retry.
    #[must_use]
    pub fn with_clock_offset(mut self, seconds: i64) -> Self {
        self.clock_offset = seconds;
        self
    }
}

impl<S> Layer<S> for ChannelLayer {
    type Service = ChannelService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ChannelService {
            inner,
            signer: self.signer.clone(),
            path_prefix: self.path_prefix.clone(),
            clock_offset: self.clock_offset,
        }
    }
}

/// The request-signing service returned by [`ChannelLayer`].
#[derive(Clone)]
pub struct ChannelService<S> {
    inner: S,
    signer: RequestSigner,
    path_prefix: String,
    clock_offset: i64,
}

impl<S, B> Service<Request<B>> for ChannelService<S>
where
    S: Service<Request<B>>,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map(|result| result.map_err(Into::into))
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let signed = (|| -> anyhow::Result<()> {
            prefix_path(request.uri_mut(), &self.path_prefix)?;
            let nonce_sender = request
                .extensions_mut()
                .remove::<OpeningNonce>()
                .ok_or_else(|| anyhow!("missing channel nonce receiver"))?;
            let local_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("read signing clock")?;
            let created = local_time
                .as_secs()
                .checked_add_signed(self.clock_offset)
                .ok_or_else(|| anyhow!("signed request timestamp out of range"))?;
            let headers = self.signer.sign(Tag::Connect, request.method(), None, created)?;
            request.headers_mut().insert("signature-input", headers.signature_input);
            request.headers_mut().insert("signature", headers.signature);
            nonce_sender.send(headers.nonce)?;
            Ok(())
        })();

        match signed {
            Ok(()) => {
                let future = self.inner.call(request);
                Box::pin(async move { future.await.map_err(Into::into) })
            }
            Err(error) => Box::pin(async move { Err(error.into()) }),
        }
    }
}

fn prefix_path(uri: &mut Uri, prefix: &str) -> anyhow::Result<()> {
    if prefix.is_empty() || uri.path().strip_suffix(CONNECT_RPC_PATH) == Some(prefix) {
        return Ok(());
    }

    let mut parts = uri.clone().into_parts();
    let path_and_query = parts.path_and_query.as_ref().map_or("/", PathAndQuery::as_str);
    let separator = if path_and_query.starts_with('/') { "" } else { "/" };
    parts.path_and_query = Some(format!("{prefix}{separator}{path_and_query}").parse()?);
    *uri = Uri::from_parts(parts)?;
    Ok(())
}

#[cfg(test)]
mod tests;
