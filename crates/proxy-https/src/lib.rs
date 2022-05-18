use bytes::{BufMut as _, Bytes, BytesMut};
use core::fmt;
use pin_project_lite::pin_project;
use proxy_types::{DestAddr, ToDestAddr};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// HTTPS proxy acceptor.
///
/// See related [RFC](https://tools.ietf.org/html/rfc7231#section-4.3.6)
#[derive(Debug)]
pub struct HttpsProxyAcceptor<S> {
    stream: S,
    read_leftover: Bytes,
    dest_addr: DestAddr,
}

impl<S> HttpsProxyAcceptor<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Accepts HTTP CONNECT operation without requiring any authentication.
    pub async fn accept(mut stream: S) -> io::Result<Self> {
        let mut framed = Framed::new(&mut stream);
        let frame = framed.read_next().await?;
        let dest_addr = decode_request(&frame)?;
        let read_leftover = framed.into_read_leftover();

        Ok(Self {
            stream,
            read_leftover,
            dest_addr,
        })
    }

    /// Destination address requested by client.
    pub fn dest_addr(&self) -> &DestAddr {
        &self.dest_addr
    }

    /// Responds with the given status code.
    ///
    /// Any non 2xx code will be interpreted as an error on client side.
    pub async fn respond(mut self, status_code: u16) -> io::Result<HttpsProxyStream<S>> {
        let mut buf = BytesMut::new();
        encode_response(&mut buf, status_code);
        self.stream.write_all(&buf).await?;

        Ok(HttpsProxyStream {
            stream: self.stream,
            read_leftover: self.read_leftover,
        })
    }
}

pin_project! {
    /// HTTPS proxy client.
    ///
    /// See related [RFC](https://tools.ietf.org/html/rfc7231#section-4.3.6)
    #[derive(Debug)]
    pub struct HttpsProxyStream<S> {
        #[pin]
        stream: S,
        read_leftover: Bytes,
    }
}

impl<S> HttpsProxyStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Performs HTTP proxying CONNECT operation.
    pub async fn connect(mut stream: S, dest: impl ToDestAddr) -> io::Result<Self> {
        let dest = dest.to_dest_addr()?;
        let mut framed = Framed::new(&mut stream);
        let mut write_buf = BytesMut::new();

        // request
        encode_request(&mut write_buf, &dest);
        framed.write_next(&mut write_buf).await?;

        // response
        let frame = framed.read_next().await?;
        let status_code = decode_response(&frame)?;

        if !(200..300).contains(&status_code) {
            return Err(Error::Rejected.into());
        }

        let read_leftover = framed.into_read_leftover();

        Ok(HttpsProxyStream { stream, read_leftover })
    }

    /// Gets underlying stream and leftover bytes
    pub fn into_parts(self) -> (S, Bytes) {
        (self.stream, self.read_leftover)
    }
}

impl<S> AsyncRead for HttpsProxyStream<S>
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

impl<S> AsyncWrite for HttpsProxyStream<S>
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

pin_project! {
    struct Framed<'a, S> {
        buffer: BytesMut,
        stream: &'a mut S,
        scan_cursor: usize,
    }
}

impl<'a, S> Framed<'a, S> {
    fn new(stream: &'a mut S) -> Self {
        Self {
            buffer: BytesMut::with_capacity(256),
            stream,
            scan_cursor: 0,
        }
    }

    fn into_read_leftover(self) -> Bytes {
        self.buffer.freeze()
    }
}

impl<'a, S: AsyncRead + Unpin> Framed<'a, S> {
    async fn read_next(&mut self) -> io::Result<Bytes> {
        loop {
            if let Some(length) = find_frame_length(&self.buffer[self.scan_cursor..]) {
                // Found a frame
                let frame = self.buffer.split_to(self.scan_cursor + length).freeze();
                self.scan_cursor = 0;
                return Ok(frame);
            }

            // Remember how far we scanned for end of frame
            self.scan_cursor = self.buffer.len();

            // Attempt to read more from stream
            self.buffer.reserve(128);
            let bytect = self.stream.read_buf(&mut self.buffer).await?;
            if bytect == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stream eofed"));
            }
        }
    }
}

impl<'a, S: AsyncWrite + Unpin> Framed<'a, S> {
    async fn write_next(&mut self, buf: &mut BytesMut) -> io::Result<()> {
        self.stream.write_all(buf).await?;
        buf.clear();
        Ok(())
    }
}

// TODO: support for Proxy-Authorization: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authorization

fn encode_request(buf: &mut BytesMut, dest: &DestAddr) {
    const FIXED_PART_SIZE: usize = b"CONNECT  HTTP/1.1\r\nHost: \r\nProxy-Connection: Keep-Alive\r\n\r\n".len();

    let host = match dest {
        DestAddr::Ip(addr) => addr.to_string(),
        DestAddr::Domain(domain, port) => {
            format!("{}:{}", domain, port)
        }
    };

    buf.reserve(FIXED_PART_SIZE + host.as_bytes().len() * 2);

    put(buf, b"CONNECT ");
    put(buf, host.as_bytes());
    put(buf, b" HTTP/1.1\r\n");

    put(buf, b"Host: ");
    put(buf, host.as_bytes());
    put(buf, b"\r\n");

    put(buf, b"Proxy-Connection: Keep-Alive\r\n");

    put(buf, b"\r\n");
}

fn decode_request(buf: &[u8]) -> Result<DestAddr, Error> {
    let method_end_idx = find(buf, b" ").ok_or(Error::Truncated)?;
    let (method, buf) = buf.split_at(method_end_idx);

    if method != b"CONNECT" {
        return Err(Error::UnsupportedMethod);
    }

    let buf = &buf[1..];
    let request_target_end_idx = find(buf, b" ").ok_or(Error::Truncated)?;
    let request_target = core::str::from_utf8(&buf[..request_target_end_idx]).map_err(|_| Error::InvalidPayload)?;
    let dest_addr = request_target.to_dest_addr().map_err(|_| Error::InvalidPayload)?;

    Ok(dest_addr)
}

fn encode_response(buf: &mut BytesMut, status_code: u16) {
    // Reason phrases are optional

    const SIZE: usize = b"HTTP/1.1 XXX\r\n\r\n".len();

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

fn find_frame_length(buf: &[u8]) -> Option<usize> {
    find(buf, b"\r\n\r\n").map(|len| len + 4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proxy_generators as generators;

    #[test]
    fn request_encode_decode_roundtrip() {
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

            let decoded_dest_addr = decode_request(expected.as_bytes()).unwrap();
            assert_eq!(decoded_dest_addr, dest_addr);
        })
    }

    #[test]
    fn response_encode_decode_roundtrip() {
        proptest!(|(
            status_code in generators::status_code(),
            reason_phrase in proptest::option::of("[A-Za-z ]{2,20}"),
        )| {
            let expected = format!("HTTP/1.1 {status_code}\r\n\r\n");
            let expected_with_reason = if let Some(reason_phrase) = reason_phrase {
                format!("HTTP/1.1 {status_code} {reason_phrase}\r\n\r\n")
            } else {
                format!("HTTP/1.1 {status_code}\r\n\r\n")
            };

            let mut encoded = BytesMut::new();
            encode_response(&mut encoded, status_code);
            assert_eq!(encoded, expected);

            let decoded_status_code = decode_response(expected_with_reason.as_bytes()).unwrap();
            assert_eq!(decoded_status_code, status_code);
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
