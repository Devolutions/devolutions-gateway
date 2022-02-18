use proxy_types::{DestAddr, ToDestAddr};
use std::io;
use std::io::Write;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// We need a super-trait in order to have additional non-auto-trait traits in trait objects.
///
/// The reason for using trait objects is monomorphization prevention in generic code.
/// This is for reducing code size by avoiding function duplication.
///
/// See:
/// - https://doc.rust-lang.org/std/keyword.dyn.html
/// - https://doc.rust-lang.org/reference/types/trait-object.html
trait ReadWriteStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<S> ReadWriteStream for S where S: AsyncRead + AsyncWrite + Unpin + Send {}

/// HTTP proxy client.
///
/// See related [RFC](https://tools.ietf.org/html/rfc7231#section-4.3.6)
#[derive(Debug)]
pub struct HttpProxyStream<S> {
    inner: S,
}

impl<S> HttpProxyStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub async fn connect(mut stream: S, dest: impl ToDestAddr) -> io::Result<Self> {
        let dest = dest.to_dest_addr()?;

        // request
        let mut buf = Vec::new();
        write_request(&mut buf, &dest)?;
        stream.write_all(&buf).await?;

        // reply
        check_reply(&mut stream).await?;

        Ok(HttpProxyStream { inner: stream })
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> AsyncRead for HttpProxyStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for HttpProxyStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn write_request(writer: &mut dyn Write, dest: &DestAddr) -> io::Result<()> {
    let host = match dest {
        DestAddr::Ip(addr) => addr.to_string(),
        DestAddr::Domain(domain, port) => {
            format!("{}:{}", domain, port)
        }
    };

    writer.write_all(b"CONNECT ")?;
    writer.write_all(host.as_bytes())?;
    writer.write_all(b" HTTP/1.1\r\n")?;

    writer.write_all(b"Host: ")?;
    writer.write_all(host.as_bytes())?;
    writer.write_all(b"\r\n")?;

    writer.write_all(b"Proxy-Connection: Keep-Alive\r\n")?;

    writer.write_all(b"\r\n")?;

    Ok(())
}

async fn check_reply(stream: &mut dyn ReadWriteStream) -> io::Result<()> {
    let mut reply = Vec::new();
    let mut buf = [0; 256];

    loop {
        let n = stream.read(&mut buf).await?;
        reply.extend_from_slice(&buf[..n]);

        let len = reply.len();
        if len > 4 && &reply[len - 4..] == b"\r\n\r\n" {
            break;
        }
    }

    let reply = String::from_utf8(reply).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let status = reply
        .split("\r\n")
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty reply"))?;

    let code = status
        .split(' ')
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid status"))?;

    // Any 2xx (successful) response indicates that the sender (and all inbound proxies)
    // will switch to tunnel mode immediately after the
    // blank line that concludes the successful response's header section
    if !code.starts_with('2') {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("request rejected: {}", status),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_encoding(addr: DestAddr, encoded: &[u8]) {
        let mut buf = Vec::new();
        write_request(&mut buf, &addr).unwrap();
        println!("{}", String::from_utf8_lossy(&buf));
        assert_eq!(buf.as_slice(), encoded);
    }

    #[tokio::test]
    async fn ipv4_addr() {
        assert_encoding(
            "192.168.0.39:80".to_dest_addr().unwrap(),
            &[
                67, 79, 78, 78, 69, 67, 84, 32, 49, 57, 50, 46, 49, 54, 56, 46, 48, 46, 51, 57, 58, 56, 48, 32, 72, 84,
                84, 80, 47, 49, 46, 49, 13, 10, 72, 111, 115, 116, 58, 32, 49, 57, 50, 46, 49, 54, 56, 46, 48, 46, 51,
                57, 58, 56, 48, 13, 10, 80, 114, 111, 120, 121, 45, 67, 111, 110, 110, 101, 99, 116, 105, 111, 110, 58,
                32, 75, 101, 101, 112, 45, 65, 108, 105, 118, 101, 13, 10, 13, 10,
            ],
        );
    }

    #[tokio::test]
    async fn ipv6_addr() {
        assert_encoding(
            "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443".to_dest_addr().unwrap(),
            &[
                67, 79, 78, 78, 69, 67, 84, 32, 91, 50, 48, 48, 49, 58, 100, 98, 56, 58, 56, 53, 97, 51, 58, 56, 100,
                51, 58, 49, 51, 49, 57, 58, 56, 97, 50, 101, 58, 51, 55, 48, 58, 55, 51, 52, 56, 93, 58, 52, 52, 51,
                32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 72, 111, 115, 116, 58, 32, 91, 50, 48, 48, 49, 58, 100, 98,
                56, 58, 56, 53, 97, 51, 58, 56, 100, 51, 58, 49, 51, 49, 57, 58, 56, 97, 50, 101, 58, 51, 55, 48, 58,
                55, 51, 52, 56, 93, 58, 52, 52, 51, 13, 10, 80, 114, 111, 120, 121, 45, 67, 111, 110, 110, 101, 99,
                116, 105, 111, 110, 58, 32, 75, 101, 101, 112, 45, 65, 108, 105, 118, 101, 13, 10, 13, 10,
            ],
        );
    }

    #[tokio::test]
    async fn domain_addr() {
        assert_encoding(
            "devolutions.net:80".to_dest_addr().unwrap(),
            &[
                67, 79, 78, 78, 69, 67, 84, 32, 100, 101, 118, 111, 108, 117, 116, 105, 111, 110, 115, 46, 110, 101,
                116, 58, 56, 48, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 72, 111, 115, 116, 58, 32, 100, 101, 118,
                111, 108, 117, 116, 105, 111, 110, 115, 46, 110, 101, 116, 58, 56, 48, 13, 10, 80, 114, 111, 120, 121,
                45, 67, 111, 110, 110, 101, 99, 116, 105, 111, 110, 58, 32, 75, 101, 101, 112, 45, 65, 108, 105, 118,
                101, 13, 10, 13, 10,
            ],
        );
    }
}
