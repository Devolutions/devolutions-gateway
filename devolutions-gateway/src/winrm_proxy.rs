use std::convert::Infallible;
use std::sync::Arc;

use anyhow::Context as _;
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HOST, WWW_AUTHENTICATE};
use hyper::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use jmux_proxy::DestinationUrl;
use secrecy::ExposeSecret as _;
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation, EncryptionFlags, Ntlm,
    SecurityBuffer, SecurityBufferRef, SecurityStatus, ServerRequestFlags, Sspi, SspiImpl, Username,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::credential::ArcCredentialEntry;

const ENCRYPTED_CONTENT_TYPE: &str =
    r#"multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary""#;
const ENCRYPTED_BOUNDARY: &[u8] = b"Encrypted Boundary";
const MAXIMUM_WINRM_HTTP_BODY_SIZE: usize = 16 * 1024 * 1024;

type ProxyBody = Full<Bytes>;

async fn collect_body<B>(body: B, error_context: &'static str) -> anyhow::Result<Bytes>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    Limited::new(body, MAXIMUM_WINRM_HTTP_BODY_SIZE)
        .collect()
        .await
        .map_err(anyhow::Error::from_boxed)
        .context(error_context)
        .map(|body| body.to_bytes())
}

pub async fn run<C, S>(
    destination: DestinationUrl,
    client_stream: C,
    target_stream: S,
    credential_entry: ArcCredentialEntry,
) -> anyhow::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let credential_mapping = credential_entry.mapping.as_ref().context("no credential mapping")?;
    let (proxy_username, proxy_password) = credential_mapping.proxy.decrypt_password()?;
    let (target_username, target_password) = credential_mapping.target.decrypt_password()?;
    let proxy_identity = AuthIdentity {
        username: Username::parse(&proxy_username).context("invalid proxy username")?,
        password: proxy_password.expose_secret().to_owned().into(),
    };
    let target_identity = AuthIdentity {
        username: Username::parse(&target_username).context("invalid target username")?,
        password: target_password.expose_secret().to_owned().into(),
    };

    let (target_sender, target_connection) = http1::handshake(TokioIo::new(target_stream))
        .await
        .context("perform WinRM target HTTP handshake")?;
    tokio::spawn(async move {
        if let Err(error) = target_connection.await {
            warn!(?error, "WinRM target HTTP connection failed");
        }
    });

    let proxy = Arc::new(Mutex::new(WinRmProxy::new(
        proxy_identity,
        target_identity,
        destination,
        target_sender,
    )?));
    let service = service_fn(move |request| {
        let proxy = Arc::clone(&proxy);
        async move {
            let response = match proxy.lock().await.handle(request).await {
                Ok(response) => response,
                Err(error) => {
                    warn!(?error, "WinRM credential proxy request failed");
                    response(StatusCode::BAD_GATEWAY, HeaderMap::new(), Bytes::new())
                }
            };

            Ok::<_, Infallible>(response)
        }
    });

    server_http1::Builder::new()
        .serve_connection(TokioIo::new(client_stream), service)
        .await
        .context("serve WinRM client HTTP connection")
}

struct WinRmProxy {
    client_ntlm: Ntlm,
    client_credentials: Option<sspi::AuthIdentityBuffers>,
    client_authenticated: bool,
    client_send_sequence: u32,
    client_receive_sequence: u32,
    target_ntlm: Ntlm,
    target_credentials: Option<sspi::AuthIdentityBuffers>,
    target_authenticated: bool,
    target_token: Vec<u8>,
    target_send_sequence: u32,
    target_receive_sequence: u32,
    target_host: String,
    target_sender: http1::SendRequest<ProxyBody>,
}

impl WinRmProxy {
    fn new(
        proxy_identity: AuthIdentity,
        target_identity: AuthIdentity,
        destination: DestinationUrl,
        target_sender: http1::SendRequest<ProxyBody>,
    ) -> anyhow::Result<Self> {
        let mut client_ntlm = Ntlm::new();
        let client_credentials = client_ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Inbound)
            .with_auth_data(&proxy_identity)
            .execute(&mut client_ntlm)
            .context("acquire WinRM proxy credentials")?
            .credentials_handle;

        let mut target_ntlm = Ntlm::new();
        let target_credentials = target_ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&target_identity)
            .execute(&mut target_ntlm)
            .context("acquire WinRM target credentials")?
            .credentials_handle;

        Ok(Self {
            client_ntlm,
            client_credentials,
            client_authenticated: false,
            client_send_sequence: 0,
            client_receive_sequence: 0,
            target_ntlm,
            target_credentials,
            target_authenticated: false,
            target_token: Vec::new(),
            target_send_sequence: 0,
            target_receive_sequence: 0,
            target_host: format!("{}:{}", destination.host(), destination.port()),
            target_sender,
        })
    }

    async fn handle(&mut self, request: Request<Incoming>) -> anyhow::Result<Response<ProxyBody>> {
        let (parts, body) = request.into_parts();
        let body = collect_body(body, "read WinRM request body").await?;

        if let Some(response) = self.authenticate_client(&parts.headers)? {
            return Ok(response);
        }

        let body = if is_encrypted(&parts.headers) {
            decrypt_multipart(&mut self.client_ntlm, &body, &mut self.client_receive_sequence)?
        } else {
            body
        };
        let target_response = self
            .send_to_target(&parts.method, &parts.uri, &parts.headers, body)
            .await?;
        self.forward_target_response(target_response).await
    }

    fn authenticate_client(&mut self, headers: &HeaderMap) -> anyhow::Result<Option<Response<ProxyBody>>> {
        if self.client_authenticated {
            return Ok(None);
        }

        if !headers.contains_key(AUTHORIZATION) {
            return Ok(Some(unauthorized(&[])?));
        }
        let token = authorization_token(headers)?;
        let mut input = [SecurityBuffer::new(token, BufferType::Token)];
        let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let builder = self
            .client_ntlm
            .accept_security_context()
            .with_credentials_handle(&mut self.client_credentials)
            .with_context_requirements(
                ServerRequestFlags::ALLOCATE_MEMORY
                    | ServerRequestFlags::CONFIDENTIALITY
                    | ServerRequestFlags::INTEGRITY,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut input)
            .with_output(&mut output);
        let result = self
            .client_ntlm
            .accept_security_context_impl(builder)
            .context("start WinRM proxy client authentication")?
            .resolve_to_result()
            .context("authenticate WinRM proxy client")?;
        match result.status {
            SecurityStatus::ContinueNeeded | SecurityStatus::CompleteAndContinue => {
                if result.status == SecurityStatus::CompleteAndContinue {
                    self.client_ntlm
                        .complete_auth_token(&mut output)
                        .context("complete WinRM proxy client authentication")?;
                }
                Ok(Some(unauthorized(&output[0].buffer)?))
            }
            SecurityStatus::Ok | SecurityStatus::CompleteNeeded => {
                if result.status == SecurityStatus::CompleteNeeded {
                    self.client_ntlm
                        .complete_auth_token(&mut output)
                        .context("complete WinRM proxy client authentication")?;
                }
                self.client_authenticated = true;
                Ok(None)
            }
            status => anyhow::bail!("unexpected WinRM proxy authentication status: {status:?}"),
        }
    }

    async fn send_to_target(
        &mut self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: Bytes,
    ) -> anyhow::Result<Response<Incoming>> {
        loop {
            let (authorization, authentication_complete) = if self.target_authenticated {
                (None, false)
            } else {
                let (authorization, authentication_complete) = self.next_target_authorization()?;
                (Some(authorization), authentication_complete)
            };
            let is_encrypted = self.target_authenticated || authentication_complete;
            let body = if is_encrypted {
                encrypt_multipart(&mut self.target_ntlm, &body, &mut self.target_send_sequence)?
            } else {
                Bytes::new()
            };
            let request = target_request(
                method,
                uri,
                headers,
                &self.target_host,
                authorization,
                body,
                is_encrypted,
            )?;
            let response = self
                .target_sender
                .send_request(request)
                .await
                .context("send WinRM request to target")?;

            if response.status() != StatusCode::UNAUTHORIZED {
                if authentication_complete {
                    self.target_authenticated = true;
                }
                return Ok(response);
            }

            if self.target_authenticated || authentication_complete {
                anyhow::bail!("target rejected WinRM credentials");
            }

            let target_token = www_authenticate_token(response.headers()).context("missing WinRM target challenge")?;
            collect_body(response.into_body(), "read WinRM target authentication response body").await?;
            self.target_token = target_token;
        }
    }

    fn next_target_authorization(&mut self) -> anyhow::Result<(HeaderValue, bool)> {
        let mut input = [SecurityBuffer::new(
            std::mem::take(&mut self.target_token),
            BufferType::Token,
        )];
        let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let target_name = target_name(&self.target_host);
        let mut builder = self
            .target_ntlm
            .initialize_security_context()
            .with_credentials_handle(&mut self.target_credentials)
            .with_context_requirements(
                ClientRequestFlags::ALLOCATE_MEMORY
                    | ClientRequestFlags::CONFIDENTIALITY
                    | ClientRequestFlags::INTEGRITY,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(&target_name)
            .with_input(&mut input)
            .with_output(&mut output);
        let result = self
            .target_ntlm
            .initialize_security_context_impl(&mut builder)
            .context("start WinRM target authentication")?
            .resolve_to_result()
            .context("authenticate with WinRM target")?;

        let authentication_complete = match result.status {
            SecurityStatus::ContinueNeeded => false,
            SecurityStatus::CompleteAndContinue => {
                self.target_ntlm
                    .complete_auth_token(&mut output)
                    .context("complete WinRM target authentication token")?;
                false
            }
            SecurityStatus::Ok => true,
            SecurityStatus::CompleteNeeded => {
                self.target_ntlm
                    .complete_auth_token(&mut output)
                    .context("complete WinRM target authentication token")?;
                true
            }
            status => anyhow::bail!("unexpected WinRM target authentication status: {status:?}"),
        };

        let value = format!(
            "Negotiate {}",
            base64::engine::general_purpose::STANDARD.encode(&output[0].buffer)
        );
        let authorization = HeaderValue::from_str(&value).context("build WinRM target authorization header")?;
        Ok((authorization, authentication_complete))
    }

    async fn forward_target_response(
        &mut self,
        target_response: Response<Incoming>,
    ) -> anyhow::Result<Response<ProxyBody>> {
        let (parts, body) = target_response.into_parts();
        let body = collect_body(body, "read WinRM target response body").await?;
        let body = if is_encrypted(&parts.headers) {
            let body = decrypt_multipart(&mut self.target_ntlm, &body, &mut self.target_receive_sequence)?;
            encrypt_multipart(&mut self.client_ntlm, &body, &mut self.client_send_sequence)?
        } else {
            body
        };

        let mut headers = copy_response_headers(&parts.headers);
        if is_encrypted(&parts.headers) {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static(ENCRYPTED_CONTENT_TYPE));
        }
        Ok(response(parts.status, headers, body))
    }
}

fn target_request(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    target_host: &str,
    authorization: Option<HeaderValue>,
    body: Bytes,
    is_encrypted: bool,
) -> anyhow::Result<Request<ProxyBody>> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Full::new(body.clone()))
        .context("build WinRM target request")?;
    copy_request_headers(headers, request.headers_mut());
    request.headers_mut().insert(
        HOST,
        HeaderValue::from_str(target_host).context("build WinRM target host header")?,
    );
    if let Some(authorization) = authorization {
        request.headers_mut().insert(AUTHORIZATION, authorization);
    }
    request.headers_mut().insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string()).context("encode WinRM content length")?,
    );
    if is_encrypted {
        request
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(ENCRYPTED_CONTENT_TYPE));
    }

    Ok(request)
}

fn copy_request_headers(source: &HeaderMap, target: &mut HeaderMap) {
    for (name, value) in source {
        if !should_strip_request_header(name) {
            target.append(name, value.clone());
        }
    }
}

fn copy_response_headers(source: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in source {
        if !should_strip_response_header(name) {
            headers.append(name, value.clone());
        }
    }

    headers
}

fn should_strip_request_header(name: &hyper::http::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization" | "host" | "content-length" | "content-type"
    ) || is_hop_by_hop_header(name)
}

fn should_strip_response_header(name: &hyper::http::HeaderName) -> bool {
    name == CONTENT_LENGTH || is_hop_by_hop_header(name)
}

fn is_hop_by_hop_header(name: &hyper::http::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn response(status: StatusCode, mut headers: HeaderMap, body: Bytes) -> Response<ProxyBody> {
    if is_encrypted(&headers) {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(ENCRYPTED_CONTENT_TYPE));
    }
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string()).expect("body length is a valid HTTP header value"),
    );
    let mut response = Response::builder()
        .status(status)
        .body(Full::new(body))
        .expect("WinRM response is valid");
    *response.headers_mut() = headers;
    response
}

fn unauthorized(token: &[u8]) -> anyhow::Result<Response<ProxyBody>> {
    let mut headers = HeaderMap::new();
    let value = if token.is_empty() {
        "Negotiate".to_owned()
    } else {
        format!("Negotiate {}", base64::engine::general_purpose::STANDARD.encode(token))
    };
    headers.insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(&value).context("build WinRM proxy challenge header")?,
    );
    Ok(response(StatusCode::UNAUTHORIZED, headers, Bytes::new()))
}

fn authorization_token(headers: &HeaderMap) -> anyhow::Result<Vec<u8>> {
    let value = headers
        .get(AUTHORIZATION)
        .context("authorization header missing")?
        .to_str()
        .context("authorization header is not valid UTF-8")?;
    decode_negotiate_token(value)
}

fn www_authenticate_token(headers: &HeaderMap) -> Option<Vec<u8>> {
    headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| decode_negotiate_token(value).ok())
}

fn decode_negotiate_token(value: &str) -> anyhow::Result<Vec<u8>> {
    let (_, token) = value
        .split_once(' ')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("negotiate") || scheme.eq_ignore_ascii_case("ntlm"))
        .context("authorization scheme is not NTLM")?;
    base64::engine::general_purpose::STANDARD
        .decode(token.trim())
        .context("decode WinRM authorization token")
}

fn target_name(host: &str) -> String {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| host.rsplit_once(':').map_or(host, |(host, _)| host));
    format!("HTTP/{host}")
}

fn is_encrypted(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let mut parts = value.split(';');
            parts
                .next()
                .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("multipart/encrypted"))
                && parts.any(|parameter| {
                    parameter.split_once('=').is_some_and(|(name, value)| {
                        name.trim().eq_ignore_ascii_case("protocol")
                            && value
                                .trim()
                                .trim_matches('"')
                                .eq_ignore_ascii_case("application/HTTP-SPNEGO-session-encrypted")
                    })
                })
        })
}

fn encrypt_multipart(context: &mut Ntlm, body: &[u8], sequence: &mut u32) -> anyhow::Result<Bytes> {
    let mut token = vec![0; context.query_context_sizes()?.security_trailer as usize];
    let mut encrypted = body.to_vec();
    let mut buffers = [
        SecurityBufferRef::token_buf(&mut token),
        SecurityBufferRef::data_buf(&mut encrypted),
    ];
    context
        .encrypt_message(EncryptionFlags::empty(), &mut buffers, *sequence)
        .context("encrypt WinRM body")?;
    *sequence = sequence.wrapping_add(1);

    let mut envelope = Vec::with_capacity(body.len() + token.len() + 256);
    envelope.extend_from_slice(b"--");
    envelope.extend_from_slice(ENCRYPTED_BOUNDARY);
    envelope.extend_from_slice(b"\r\nContent-Type: application/HTTP-SPNEGO-session-encrypted\r\nOriginalContent: type=application/soap+xml;charset=UTF-8;Length=");
    envelope.extend_from_slice(body.len().to_string().as_bytes());
    envelope.extend_from_slice(b"\r\n--");
    envelope.extend_from_slice(ENCRYPTED_BOUNDARY);
    envelope.extend_from_slice(b"\r\nContent-Type: application/octet-stream\r\n");
    envelope.extend_from_slice(&(u32::try_from(token.len()).context("security token is too long")?).to_le_bytes());
    envelope.extend_from_slice(&token);
    envelope.extend_from_slice(&encrypted);
    envelope.extend_from_slice(b"--");
    envelope.extend_from_slice(ENCRYPTED_BOUNDARY);
    envelope.extend_from_slice(b"--\r\n");

    Ok(Bytes::from(envelope))
}

fn decrypt_multipart(context: &mut Ntlm, body: &[u8], sequence: &mut u32) -> anyhow::Result<Bytes> {
    let payload = encrypted_payload(body)?;
    let token_length = payload
        .get(..4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("slice length is checked")))
        .context("encrypted WinRM body is missing a security token length")?;
    let token_length = usize::try_from(token_length).expect("u32 always fits usize on supported platforms");
    let token_end = 4 + token_length;
    let token = payload
        .get(4..token_end)
        .context("encrypted WinRM body is missing a security token")?;
    let mut encrypted = payload
        .get(token_end..)
        .context("encrypted WinRM body is missing data")?
        .to_vec();
    let mut token = token.to_vec();
    let mut buffers = [
        SecurityBufferRef::token_buf(&mut token),
        SecurityBufferRef::data_buf(&mut encrypted),
    ];
    context
        .decrypt_message(&mut buffers, *sequence)
        .context("decrypt WinRM body")?;
    *sequence = sequence.wrapping_add(1);

    Ok(Bytes::copy_from_slice(buffers[1].data()))
}

fn encrypted_payload(body: &[u8]) -> anyhow::Result<&[u8]> {
    const CONTENT_TYPE: &[u8] = b"Content-Type: application/octet-stream";
    let content_type_end = find_subsequence(body, CONTENT_TYPE)
        .map(|position| position + CONTENT_TYPE.len())
        .context("encrypted WinRM body has no binary part")?;
    let payload = body
        .get(content_type_end..)
        .and_then(|body| body.strip_prefix(b"\r\n"))
        .context("encrypted WinRM body has an invalid binary part")?;
    let payload = payload.strip_prefix(b"\r\n").unwrap_or(payload);
    let payload_start = body.len() - payload.len();
    let mut closing_boundary = b"--".to_vec();
    closing_boundary.extend_from_slice(ENCRYPTED_BOUNDARY);
    closing_boundary.extend_from_slice(b"--\r\n");
    let payload_end = body
        .strip_suffix(closing_boundary.as_slice())
        .map(|body| body.len())
        .context("encrypted WinRM body has no closing boundary")?;
    body.get(payload_start..payload_end)
        .context("encrypted WinRM body has an invalid binary part")
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_payload_extracts_binary_section() {
        let body = b"--Encrypted Boundary\r\n\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=3\r\n--Encrypted Boundary\r\n\tContent-Type: application/octet-stream\r\n\x10\0\0\0security-tokenpayload--Encrypted Boundary--\r\n";

        assert_eq!(
            encrypted_payload(body).expect("the WinRM envelope has a binary section"),
            b"\x10\0\0\0security-tokenpayload"
        );
    }

    #[test]
    fn target_name_removes_port() {
        assert_eq!(target_name("server.example:5985"), "HTTP/server.example");
    }

    #[test]
    fn response_preserves_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(WWW_AUTHENTICATE, HeaderValue::from_static("Negotiate token"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/soap+xml"));

        let response = response(StatusCode::UNAUTHORIZED, copy_response_headers(&headers), Bytes::new());

        assert_eq!(response.headers()[WWW_AUTHENTICATE], "Negotiate token");
        assert_eq!(response.headers()[CONTENT_TYPE], "application/soap+xml");
    }

    #[test]
    fn encrypted_content_type_requires_winrm_protocol() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(r#"multipart/encrypted; protocol="application/pkcs7-mime""#),
        );
        assert!(!is_encrypted(&headers));

        headers.insert(CONTENT_TYPE, HeaderValue::from_static(ENCRYPTED_CONTENT_TYPE));
        assert!(is_encrypted(&headers));
    }

    #[tokio::test]
    async fn oversized_body_is_rejected() {
        let body = Full::new(Bytes::from(vec![0; MAXIMUM_WINRM_HTTP_BODY_SIZE + 1]));

        let error = collect_body(body, "read body")
            .await
            .expect_err("the body exceeds the WinRM proxy limit");

        assert_eq!(format!("{error:#}"), "read body: length limit exceeded");
    }
}
