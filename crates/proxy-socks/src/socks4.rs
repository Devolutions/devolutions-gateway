use crate::ReadWriteStream;
use proxy_types::{DestAddr, ToDestAddr};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS4 CONNECT client.
#[derive(Debug)]
pub struct Socks4Stream<S> {
    inner: S,
    dest_addr: SocketAddrV4,
}

impl<S> Socks4Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Initiates a CONNECT request to the specified proxy.
    pub async fn connect(mut stream: S, dest: impl ToDestAddr, userid: &str) -> io::Result<Self> {
        let dest = dest.to_dest_addr()?;

        // SOCKS request
        write_socks_request(&mut stream, &dest, userid).await?;

        // SOCKS reply
        let dest_addr = read_socks_reply(&mut stream).await?;

        Ok(Socks4Stream {
            inner: stream,
            dest_addr,
        })
    }

    /// Returns the destination address that the proxy server connects to.
    pub fn dest_addr(&self) -> SocketAddrV4 {
        self.dest_addr
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> AsyncRead for Socks4Stream<S>
where
    S: AsyncRead + Unpin,
{
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for Socks4Stream<S>
where
    S: AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn write_socks_request(stream: &mut dyn ReadWriteStream, dest: &DestAddr, userid: &str) -> io::Result<()> {
    // https://www.openssh.com/txt/socks4.protocol
    //             +----+----+----+----+----+----+----+----+----+----+....+----+
    //             | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
    //             +----+----+----+----+----+----+----+----+----+----+....+----+
    // # of bytes:   1    1      2              4           variable       1
    //
    // VN is the SOCKS protocol version number and should be 4. CD is the
    // SOCKS command code and should be 1 for CONNECT request. NULL is a byte
    // of all zero bits.

    let mut packet = vec![
        4, // version
        1, // command (1 = CONNECT)
    ];

    match dest {
        DestAddr::Ip(SocketAddr::V4(addr)) => {
            packet.extend_from_slice(&addr.port().to_be_bytes());
            packet.extend_from_slice(&u32::from(*addr.ip()).to_be_bytes());
            packet.extend_from_slice(userid.as_bytes());
            packet.push(0);
        }
        DestAddr::Ip(SocketAddr::V6(_)) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS4 does not support IPv6",
            ));
        }
        DestAddr::Domain(domain, port) => {
            packet.extend_from_slice(&port.to_be_bytes());
            packet.extend_from_slice(&u32::from(Ipv4Addr::new(0, 0, 0, 1)).to_be_bytes());
            packet.extend_from_slice(userid.as_bytes());
            packet.push(0);
            packet.extend_from_slice(domain.as_bytes());
            packet.push(0);
        }
    }

    stream.write_all(&packet).await?;

    Ok(())
}

async fn read_socks_reply(stream: &mut dyn ReadWriteStream) -> io::Result<SocketAddrV4> {
    // https://www.openssh.com/txt/socks4.protocol
    //	        	+----+----+----+----+----+----+----+----+
    //	        	| VN | CD | DSTPORT |      DSTIP        |
    //	        	+----+----+----+----+----+----+----+----+
    // # of bytes:	   1    1      2              4
    //
    // VN is the version of the reply code and should be 0. CD is the result code.

    if stream.read_u8().await? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid version of reply code",
        ));
    }

    match stream.read_u8().await? {
        90 => {}
        91 => return Err(io::Error::other("request rejected or failed")),
        92 => {
            return Err(io::Error::other(
                "request rejected because SOCKS server cannot connect to identd on the client",
            ));
        }
        93 => {
            return Err(io::Error::other(
                "request rejected because the client program and identd report different user-ids",
            ));
        }
        _ => return Err(io::Error::other("invalid result code")),
    }

    let port = stream.read_u16().await?;
    let ip = stream.read_u32().await?;

    Ok(SocketAddrV4::new(Ipv4Addr::from(ip), port))
}

#[expect(clippy::unwrap_used, reason = "Test code can panic on errors")]
#[cfg(test)]
mod tests {
    use super::*;

    async fn assert_encoding(addr: DestAddr, userid: &str, encoded: &[u8]) {
        let mut writer = tokio_test::io::Builder::new().write(encoded).build();
        write_socks_request(&mut writer, &addr, userid).await.unwrap();
    }

    #[tokio::test]
    async fn ipv4_addr() {
        assert_encoding(
            "192.168.0.39:80".to_dest_addr().unwrap(),
            "david",
            &[4, 1, 0, 80, 192, 168, 0, 39, 100, 97, 118, 105, 100, 0],
        )
        .await;
    }

    #[tokio::test]
    async fn domain_addr() {
        assert_encoding(
            "devolutions.net:80".to_dest_addr().unwrap(),
            "david",
            &[
                4, 1, 0, 80, 0, 0, 0, 1, 100, 97, 118, 105, 100, 0, 100, 101, 118, 111, 108, 117, 116, 105, 111, 110,
                115, 46, 110, 101, 116, 0,
            ],
        )
        .await;
    }
}
