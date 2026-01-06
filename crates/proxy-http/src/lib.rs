//! Client and acceptor for HTTP(S) proxying / tunneling
//!
//! See [RFC 7231](https://datatracker.ietf.org/doc/html/rfc7231):
//! - [Section 4.3.6](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.6)
//!
//! And [RFC 7230](https://datatracker.ietf.org/doc/html/rfc7230):
//! - [Section 2.3](https://datatracker.ietf.org/doc/html/rfc7230#section-2.3)
//! - [Section 5.3.2](https://datatracker.ietf.org/doc/html/rfc7230#section-5.3.2)
//! - [Section 5.7](https://datatracker.ietf.org/doc/html/rfc7230#section-5.7)

// TODO: support for Proxy-Authorization: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authorization

use core::fmt;
use std::io;

use bytes::{BufMut as _, Bytes, BytesMut};
use pin_project_lite::pin_project;
use proxy_types::{DestAddr, ToDestAddr};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

#[derive(Debug, Copy, Clone)]
pub enum ErrorCode {
    /// 300 - Multiple Choices
    MultipleChoices,
    /// 301 – Moved Permanently
    MovedPermanently,
    /// 302 – Found (resource changed temporarily)
    Found,
    /// 303 – See Other (see another resource)
    SeeOther,
    /// 304 – Not Modified
    NotModified,
    /// 305 – Use Proxy
    UseProxy,
    /// 306 – Switch Proxy
    SwitchProxy,
    /// 307 – Temporary Redirect
    TemporaryRedirect,
    /// 308 – Permanent Redirect
    PermanentRedirect,
    /// 400 – Bad Request
    BadRequest,
    /// 401 – Unauthorized
    Unauthorized,
    /// 402 – Payment Required
    PaymentRequired,
    /// 403 – Forbidden
    Forbidden,
    /// 404 – Not Found
    NotFound,
    /// 405 – Method Not Allowed
    MethodNotAllowed,
    /// 406 – Not Acceptable
    NotAcceptable,
    /// 407 – Proxy Authentication Required
    ProxyAuthenticationRequired,
    /// 408 – Request Timeout
    RequestTimeout,
    /// 409 – Conflict
    Conflict,
    /// 410 – Gone
    Gone,
    /// 411 – Length Required
    LengthRequired,
    /// 412 – Precondition Failed
    PreconditionFailed,
    /// 413 – Request Entity Too Large
    PayloadTooLarge,
    /// 414 – Request-URL Too Long
    UriTooLong,
    /// 415 – Unsupported Media Type
    UnsupportedMediaType,
    /// 416 – Requested Range Not Satisfiable
    RangeNotSatisfiable,
    /// 417 – Expectation Failed
    ExpectationFailed,
    /// 429 – Too Many Requests
    TooManyRequests,
    /// 500 – Internal Server Error
    InternalServerError,
    /// 501 – Not Implemented
    NotImplemented,
    /// 502 – Bad Gateway
    BadGateway,
    /// 503 – Services Unavailable
    ServicesUnavailable,
    /// 504 – Gateway Timeout
    GatewayTimeout,
    /// 505 – HTTP Version Not Supported
    HttpVersionNotSupported,
    /// 507 – Insufficient Space
    InsufficientSpace,
    /// 510 – Not Extended
    NotExtended,
}

impl ErrorCode {
    pub const fn reason_phrase(self) -> &'static str {
        match self {
            Self::MultipleChoices => "Multiple Choices",
            Self::MovedPermanently => "Moved Permanently",
            Self::Found => "Found",
            Self::SeeOther => "See Other",
            Self::NotModified => "Not Modified",
            Self::UseProxy => "Use Proxy",
            Self::SwitchProxy => "Switch Proxy",
            Self::TemporaryRedirect => "Temporary Redirect",
            Self::PermanentRedirect => "Permanent Redirect",
            Self::BadRequest => "Bad Request",
            Self::Unauthorized => "Unauthorized",
            Self::PaymentRequired => "Payment Required",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "Not Found",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::NotAcceptable => "Not Acceptable",
            Self::ProxyAuthenticationRequired => "Proxy Authentication Required",
            Self::RequestTimeout => "Request Timeout",
            Self::Conflict => "Conflict",
            Self::Gone => "Gone",
            Self::LengthRequired => "Length Required",
            Self::PreconditionFailed => "Precondition Failed",
            Self::PayloadTooLarge => "Payload Too Large",
            Self::UriTooLong => "URI Too Long",
            Self::UnsupportedMediaType => "Unsupported Media Type",
            Self::RangeNotSatisfiable => "Range Not Satisfiable",
            Self::ExpectationFailed => "Expectation Failed",
            Self::TooManyRequests => "Too Many Requests",
            Self::InternalServerError => "Internal Server Error",
            Self::NotImplemented => "Not Implemented",
            Self::BadGateway => "Bad Gateway",
            Self::ServicesUnavailable => "Services Unavailable",
            Self::GatewayTimeout => "Gateway Timeout",
            Self::HttpVersionNotSupported => "HTTP Version Not Supported",
            Self::InsufficientSpace => "Insufficient Space",
            Self::NotExtended => "Not Extended",
        }
    }
}

impl From<ErrorCode> for u16 {
    fn from(code: ErrorCode) -> Self {
        match code {
            ErrorCode::MultipleChoices => 300,
            ErrorCode::MovedPermanently => 301,
            ErrorCode::Found => 302,
            ErrorCode::SeeOther => 303,
            ErrorCode::NotModified => 304,
            ErrorCode::UseProxy => 305,
            ErrorCode::SwitchProxy => 306,
            ErrorCode::TemporaryRedirect => 307,
            ErrorCode::PermanentRedirect => 308,
            ErrorCode::BadRequest => 400,
            ErrorCode::Unauthorized => 401,
            ErrorCode::PaymentRequired => 402,
            ErrorCode::Forbidden => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::MethodNotAllowed => 405,
            ErrorCode::NotAcceptable => 406,
            ErrorCode::ProxyAuthenticationRequired => 407,
            ErrorCode::RequestTimeout => 408,
            ErrorCode::Conflict => 409,
            ErrorCode::Gone => 410,
            ErrorCode::LengthRequired => 411,
            ErrorCode::PreconditionFailed => 412,
            ErrorCode::PayloadTooLarge => 413,
            ErrorCode::UriTooLong => 414,
            ErrorCode::UnsupportedMediaType => 415,
            ErrorCode::RangeNotSatisfiable => 416,
            ErrorCode::ExpectationFailed => 417,
            ErrorCode::TooManyRequests => 429,
            ErrorCode::InternalServerError => 500,
            ErrorCode::NotImplemented => 501,
            ErrorCode::BadGateway => 502,
            ErrorCode::ServicesUnavailable => 503,
            ErrorCode::GatewayTimeout => 504,
            ErrorCode::HttpVersionNotSupported => 505,
            ErrorCode::InsufficientSpace => 507,
            ErrorCode::NotExtended => 510,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", u16::from(*self), self.reason_phrase())
    }
}

#[derive(Debug)]
pub struct HttpRegularProxyRequest<S> {
    stream: S,
    read_bytes: Bytes,
    method: String,
    dest_addr: DestAddr,
}

impl<S> HttpRegularProxyRequest<S> {
    /// Destination address requested by client.
    pub fn dest_addr(&self) -> &DestAddr {
        &self.dest_addr
    }

    /// HTTP method in client's request
    pub fn method(&self) -> &str {
        &self.method
    }
}

impl<S> HttpRegularProxyRequest<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Responds with the given error status code.
    pub async fn failure(self, error_code: ErrorCode) -> io::Result<ProxyStream<S>> {
        respond_impl(self.stream, self.read_bytes, StatusCode::Failure(error_code)).await
    }

    /// Returns the underlying stream ready for forwarding without any request rewriting.
    pub fn success_without_rewrite(self) -> ProxyStream<S> {
        ProxyStream {
            stream: self.stream,
            read_leftover: self.read_bytes,
        }
    }

    /// Rewrite request and returns the underlying stream ready for forwarding.
    pub fn success_with_rewrite(self) -> io::Result<ProxyStream<S>> {
        Ok(ProxyStream {
            stream: self.stream,
            read_leftover: rewrite_req_absolute_to_origin_form(self.read_bytes)?,
        })
    }
}

#[derive(Debug)]
pub struct HttpsTunnelRequest<S> {
    stream: S,
    read_leftover: Bytes,
    dest_addr: DestAddr,
}

impl<S> HttpsTunnelRequest<S> {
    /// Destination address requested by client.
    pub fn dest_addr(&self) -> &DestAddr {
        &self.dest_addr
    }
}

impl<S> HttpsTunnelRequest<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Responds with the given error status code.
    pub async fn failure(self, error_code: ErrorCode) -> io::Result<ProxyStream<S>> {
        respond_impl(self.stream, self.read_leftover, StatusCode::Failure(error_code)).await
    }

    /// Responds with success status code and returns the underlying stream ready for forwarding.
    pub async fn success(self) -> io::Result<ProxyStream<S>> {
        respond_impl(self.stream, self.read_leftover, StatusCode::ConnectionEstablished).await
    }
}

#[derive(Debug, Clone)]
enum StatusCode {
    ConnectionEstablished,
    Failure(ErrorCode),
}

impl StatusCode {
    pub(crate) const fn reason_phrase(&self) -> &'static str {
        match self {
            Self::ConnectionEstablished => "Connection Established",
            Self::Failure(error_code) => error_code.reason_phrase(),
        }
    }
}

impl From<&StatusCode> for u16 {
    fn from(code: &StatusCode) -> Self {
        match code {
            StatusCode::ConnectionEstablished => 200,
            StatusCode::Failure(error_code) => u16::from(*error_code),
        }
    }
}

impl From<StatusCode> for u16 {
    fn from(code: StatusCode) -> Self {
        Self::from(&code)
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", u16::from(self), self.reason_phrase())
    }
}

async fn respond_impl<S>(mut stream: S, read_leftover: Bytes, status_code: StatusCode) -> io::Result<ProxyStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut buf = BytesMut::new();
    encode_response(&mut buf, status_code);
    stream.write_all(&buf).await?;

    Ok(ProxyStream { stream, read_leftover })
}

/// HTTP(S) proxy acceptor.
#[derive(Debug)]
pub enum HttpProxyAcceptor<S> {
    RegularRequest(HttpRegularProxyRequest<S>),
    TunnelRequest(HttpsTunnelRequest<S>),
}

impl<S> HttpProxyAcceptor<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Accepts HTTP forwarding request without requiring any authentication.
    pub async fn accept(mut stream: S) -> io::Result<Self> {
        let frame = Frame::read(&mut stream).await?;
        let request = decode_request(frame.payload())?;
        let dest_addr = request.dest_addr;

        if request.method == "CONNECT" {
            // Request payload is eaten, only leftover must be forwarded
            let read_leftover = frame.into_read_leftover();
            Ok(Self::TunnelRequest(HttpsTunnelRequest {
                stream,
                dest_addr,
                read_leftover,
            }))
        } else {
            // All read bytes are kept to be forwarded
            let method = request.method.to_owned();
            let read_bytes = frame.into_inner();
            Ok(Self::RegularRequest(HttpRegularProxyRequest {
                stream,
                method,
                dest_addr,
                read_bytes,
            }))
        }
    }

    /// Destination address requested by client.
    pub fn dest_addr(&self) -> &DestAddr {
        match self {
            HttpProxyAcceptor::RegularRequest(request) => request.dest_addr(),
            HttpProxyAcceptor::TunnelRequest(request) => request.dest_addr(),
        }
    }

    /// Responds with the given error status code.
    pub async fn failure(self, error_code: ErrorCode) -> io::Result<ProxyStream<S>> {
        match self {
            HttpProxyAcceptor::RegularRequest(request) => request.failure(error_code).await,
            HttpProxyAcceptor::TunnelRequest(request) => request.failure(error_code).await,
        }
    }
}

pin_project! {
    /// HTTP(S) proxy stream.
    #[derive(Debug)]
    pub struct ProxyStream<S> {
        #[pin]
        stream: S,
        read_leftover: Bytes,
    }
}

impl<S> ProxyStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Send HTTP proxying CONNECT request to open a tunnel.
    pub async fn connect(mut stream: S, dest: impl ToDestAddr) -> io::Result<Self> {
        let dest = dest.to_dest_addr()?;

        // request
        let mut write_buf = BytesMut::new();
        encode_request(&mut write_buf, &dest);
        write_frame(&mut stream, &mut write_buf).await?;

        // response
        let frame = Frame::read(&mut stream).await?;
        let status_code = decode_response(frame.payload())?;

        if !(200..300).contains(&status_code) {
            return Err(Error::Rejected.into());
        }

        let read_leftover = frame.into_read_leftover();

        Ok(ProxyStream { stream, read_leftover })
    }

    /// Gets underlying stream and leftover bytes
    pub fn into_parts(self) -> (S, Bytes) {
        (self.stream, self.read_leftover)
    }
}

impl<S> AsyncRead for ProxyStream<S>
where
    S: AsyncRead,
{
    #[inline]
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.project();

        // Hands remaining leftover if any
        if !this.read_leftover.is_empty() {
            let dst = buf.initialize_unfilled();
            let nb_to_copy = std::cmp::min(dst.len(), this.read_leftover.len());
            let to_copy = this.read_leftover.split_to(nb_to_copy);
            dst[..nb_to_copy].copy_from_slice(&to_copy);
            buf.advance(nb_to_copy);
            return std::task::Poll::Ready(Ok(()));
        }

        this.stream.poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for ProxyStream<S>
where
    S: AsyncWrite,
{
    #[inline]
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        self.project().stream.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Truncated,
    InvalidPayload,
    Rejected,
    UnsupportedMethod,
    Oversized,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => {
                write!(f, "Truncated packet")
            }
            Error::InvalidPayload => write!(f, "Packet is invalid",),
            Error::Rejected => {
                write!(f, "Rejected by server")
            }
            Error::UnsupportedMethod => {
                write!(f, "Unsupported method")
            }
            Error::Oversized => {
                write!(f, "Oversized packet received")
            }
        }
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        let kind = match e {
            Error::Truncated => io::ErrorKind::UnexpectedEof,
            Error::InvalidPayload => io::ErrorKind::InvalidData,
            Error::Rejected => io::ErrorKind::ConnectionRefused,
            Error::UnsupportedMethod => io::ErrorKind::ConnectionRefused,
            Error::Oversized => io::ErrorKind::InvalidData,
        };
        io::Error::new(kind, e)
    }
}

/// A frame containing the request line and headers of the HTTP request.
///
/// May contains leftover bytes resulting from over reading the stream.
struct Frame {
    buffer: Bytes,
    headers_end: usize,
}

impl Frame {
    async fn read<S>(stream: &mut S) -> io::Result<Self>
    where
        S: AsyncRead + Unpin,
    {
        let mut buffer = BytesMut::new();
        let mut scan_cursor: usize = 0;

        let headers_end = loop {
            // Attempt to read more from stream
            buffer.reserve(128);
            let bytect = stream.read_buf(&mut buffer).await?;
            if bytect == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stream eofed"));
            }

            if let Some(headers_end) = find_frame_length(&buffer[scan_cursor..]) {
                // Found a frame
                break headers_end + scan_cursor;
            }

            // Remember how far we scanned for end of frame
            scan_cursor = buffer.len();
        };

        Ok(Self {
            buffer: buffer.freeze(),
            headers_end,
        })
    }

    fn payload(&self) -> &[u8] {
        &self.buffer[..self.headers_end]
    }

    fn into_read_leftover(mut self) -> Bytes {
        self.buffer.split_off(self.headers_end)
    }

    fn into_inner(self) -> Bytes {
        self.buffer
    }
}

async fn write_frame<S>(stream: &mut S, buf: &mut BytesMut) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(buf).await?;
    buf.clear();
    Ok(())
}

fn encode_request(buf: &mut BytesMut, dest: &DestAddr) {
    const FIXED_PART_SIZE: usize = b"CONNECT  HTTP/1.1\r\nHost: \r\nProxy-Connection: Keep-Alive\r\n\r\n".len();

    let host = match dest {
        DestAddr::Ip(addr) => addr.to_string(),
        DestAddr::Domain(domain, port) => {
            format!("{domain}:{port}")
        }
    };

    buf.reserve(FIXED_PART_SIZE + host.len() * 2);

    put(buf, b"CONNECT ");
    put(buf, host.as_bytes());
    put(buf, b" HTTP/1.1\r\n");

    put(buf, b"Host: ");
    put(buf, host.as_bytes());
    put(buf, b"\r\n");

    put(buf, b"Proxy-Connection: Keep-Alive\r\n");

    put(buf, b"\r\n");
}

#[derive(Debug)]
struct Request<'a> {
    method: &'a str,
    dest_addr: DestAddr,
}

fn decode_request(buf: &[u8]) -> Result<Request<'_>, Error> {
    let method_end_idx = find(buf, b" ").ok_or(Error::Truncated)?;
    let (method, buf) = buf.split_at(method_end_idx);
    let method = core::str::from_utf8(method).map_err(|_| Error::InvalidPayload)?;

    // Parse destination address directly from the request target
    // so that we don't need to parse headers (which are case-insensitives)

    let buf = &buf[1..];
    let request_target_end_idx = find(buf, b" ").ok_or(Error::Truncated)?;
    let request_target = core::str::from_utf8(&buf[..request_target_end_idx]).map_err(|_| Error::InvalidPayload)?;

    let dest_addr = if let Some(request_target) = request_target.strip_prefix("http://") {
        if let Some(idx) = request_target.find('/') {
            &request_target[..idx]
        } else {
            request_target
        }
    } else {
        request_target
    };

    let dest_addr = if dest_addr.find(':').is_some() {
        dest_addr.to_dest_addr()
    } else {
        (dest_addr, 80).to_dest_addr()
    }
    .map_err(|_| Error::InvalidPayload)?;

    Ok(Request { method, dest_addr })
}

/// Rewrite request to convert request URI from absolute-form to origin-form
///
/// See [section 5.3 of RFC 7230](https://datatracker.ietf.org/doc/html/rfc7230#section-5.3).
fn rewrite_req_absolute_to_origin_form(request: Bytes) -> Result<Bytes, Error> {
    let mut out = BytesMut::new();
    out.reserve(request.len());

    let method_end_idx = find(&request, b" ").ok_or(Error::Truncated)?;
    let (method, rest) = request.split_at(method_end_idx);
    out.put(method);

    let rest = &rest[1..];
    put(&mut out, b" ");

    let rest = rest.strip_prefix(b"http://").ok_or(Error::InvalidPayload)?;
    let origin_form_start = find(rest, b"/").ok_or(Error::InvalidPayload)?;
    let rest = &rest[origin_form_start..];
    put(&mut out, rest);

    Ok(out.freeze())
}

fn encode_response(buf: &mut BytesMut, status_code: StatusCode) {
    // Reason phrases are optional

    const LONGEST_REASON_SIZE: usize = ErrorCode::ProxyAuthenticationRequired.reason_phrase().len();
    const SIZE: usize = b"HTTP/1.1 XXX\r\n\r\n".len() + LONGEST_REASON_SIZE;

    buf.reserve(SIZE);

    put(buf, b"HTTP/1.1 ");
    put(buf, status_code.to_string().as_bytes());
    put(buf, b"\r\n\r\n");
}

fn decode_response(buf: &[u8]) -> Result<u16, Error> {
    let status_line_end_idx = find(buf, b"\r\n").ok_or(Error::Truncated)?;
    let status_line = core::str::from_utf8(&buf[..status_line_end_idx]).map_err(|_| Error::InvalidPayload)?;
    let status_code = status_line.split(' ').nth(1).ok_or(Error::InvalidPayload)?;
    let status_code: u16 = status_code.parse().map_err(|_| Error::InvalidPayload)?;
    Ok(status_code)
}

/// Helper to work around verbose `buf.put(&b"hello"[..])`
fn put(buf: &mut BytesMut, bytes: &[u8]) {
    buf.put(bytes);
}

/// Basically str::find but on &[u8]
fn find(buf: &[u8], pat: &[u8]) -> Option<usize> {
    buf.windows(pat.len()).position(|win| win == pat)
}

/// Finds end of headers part
fn find_frame_length(buf: &[u8]) -> Option<usize> {
    find(buf, b"\r\n\r\n").map(|len| len + 4)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code can panic on errors")]

    use proptest::prelude::*;
    use proxy_generators as generators;

    use super::*;

    fn status_code() -> impl Strategy<Value = StatusCode> {
        prop_oneof![
            Just(StatusCode::ConnectionEstablished),
            Just(StatusCode::Failure(ErrorCode::MultipleChoices)),
            Just(StatusCode::Failure(ErrorCode::MovedPermanently)),
            Just(StatusCode::Failure(ErrorCode::Found)),
            Just(StatusCode::Failure(ErrorCode::SeeOther)),
            Just(StatusCode::Failure(ErrorCode::NotModified)),
            Just(StatusCode::Failure(ErrorCode::UseProxy)),
            Just(StatusCode::Failure(ErrorCode::SwitchProxy)),
            Just(StatusCode::Failure(ErrorCode::TemporaryRedirect)),
            Just(StatusCode::Failure(ErrorCode::PermanentRedirect)),
            Just(StatusCode::Failure(ErrorCode::BadRequest)),
            Just(StatusCode::Failure(ErrorCode::Unauthorized)),
            Just(StatusCode::Failure(ErrorCode::PaymentRequired)),
            Just(StatusCode::Failure(ErrorCode::Forbidden)),
            Just(StatusCode::Failure(ErrorCode::NotFound)),
            Just(StatusCode::Failure(ErrorCode::MethodNotAllowed)),
            Just(StatusCode::Failure(ErrorCode::NotAcceptable)),
            Just(StatusCode::Failure(ErrorCode::ProxyAuthenticationRequired)),
            Just(StatusCode::Failure(ErrorCode::RequestTimeout)),
            Just(StatusCode::Failure(ErrorCode::Conflict)),
            Just(StatusCode::Failure(ErrorCode::Gone)),
            Just(StatusCode::Failure(ErrorCode::LengthRequired)),
            Just(StatusCode::Failure(ErrorCode::PreconditionFailed)),
            Just(StatusCode::Failure(ErrorCode::PayloadTooLarge)),
            Just(StatusCode::Failure(ErrorCode::UriTooLong)),
            Just(StatusCode::Failure(ErrorCode::UnsupportedMediaType)),
            Just(StatusCode::Failure(ErrorCode::RangeNotSatisfiable)),
            Just(StatusCode::Failure(ErrorCode::ExpectationFailed)),
            Just(StatusCode::Failure(ErrorCode::TooManyRequests)),
            Just(StatusCode::Failure(ErrorCode::InternalServerError)),
            Just(StatusCode::Failure(ErrorCode::NotImplemented)),
            Just(StatusCode::Failure(ErrorCode::BadGateway)),
            Just(StatusCode::Failure(ErrorCode::ServicesUnavailable)),
            Just(StatusCode::Failure(ErrorCode::GatewayTimeout)),
            Just(StatusCode::Failure(ErrorCode::HttpVersionNotSupported)),
            Just(StatusCode::Failure(ErrorCode::InsufficientSpace)),
            Just(StatusCode::Failure(ErrorCode::NotExtended)),
        ]
    }

    fn method() -> impl Strategy<Value = String> {
        "(CONNECT|GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE)"
    }

    #[test]
    fn tunnel_request_encode_decode_roundtrip() {
        proptest!(|(
            dest_addr in generators::dest_addr()
        )| {
            let stringified = match &dest_addr {
                DestAddr::Ip(ip_addr) => ip_addr.to_string(),
                DestAddr::Domain(host, port) => format!("{host}:{port}"),
            };
            let expected = format!("CONNECT {stringified} HTTP/1.1\r\nHost: {stringified}\r\nProxy-Connection: Keep-Alive\r\n\r\n");

            let mut encoded = BytesMut::new();
            encode_request(&mut encoded, &dest_addr);
            assert_eq!(encoded, expected);

            let decoded_request = decode_request(expected.as_bytes()).unwrap();
            assert_eq!(decoded_request.dest_addr, dest_addr);
        })
    }

    #[test]
    fn request_decode() {
        proptest!(|(
            method in method(),
            dest_addr in generators::dest_addr()
        )| {
            let stringified = match &dest_addr {
                DestAddr::Ip(ip_addr) => ip_addr.to_string(),
                DestAddr::Domain(host, port) => format!("{host}:{port}"),
            };
            let request_payload = format!("{method} {stringified} HTTP/1.1\r\nHost: {stringified}\r\nProxy-Connection: Keep-Alive\r\n\r\n").into_bytes();
            let decoded_request = decode_request(&request_payload).unwrap();
            assert_eq!(decoded_request.dest_addr, dest_addr);
        })
    }

    #[test]
    fn response_encode_decode_roundtrip() {
        proptest!(|(
            status_code in status_code(),
        )| {
            let expected_without_phrase = format!("HTTP/1.1 {}\r\n\r\n", u16::from(&status_code));
            let expected_with_phrase = format!("HTTP/1.1 {status_code}\r\n\r\n");

            let mut encoded = BytesMut::new();
            encode_response(&mut encoded, status_code.clone());
            assert_eq!(encoded, expected_with_phrase);

            for to_decode in [expected_with_phrase, expected_without_phrase] {
                let decoded_status_code = decode_response(to_decode.as_bytes()).unwrap();
                assert_eq!(decoded_status_code, u16::from(&status_code));
            }
        })
    }

    #[test]
    fn decode_response_truncated() {
        let response = b"HTTP/1";
        let e = decode_response(response).err().unwrap();
        assert!(matches!(e, Error::Truncated));
    }

    #[test]
    fn decode_response_invalid() {
        let response = b"HTTP/1.1\r\n\r\n";
        let e = decode_response(response).err().unwrap();
        assert!(matches!(e, Error::InvalidPayload));
    }

    #[test]
    fn decode_frame_length() {
        let payload = b"Hello Sir.\r\n\r\nThis is unrelated";
        let length = find_frame_length(payload).unwrap();
        assert_eq!(length, 14);
        assert_eq!(&payload[..length], b"Hello Sir.\r\n\r\n");
    }
}
