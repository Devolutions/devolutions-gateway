use crate::{DestAddr, ToDestAddr};
use std::convert::TryFrom;
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_ADDR_LEN: usize = 260;
const METHOD_NO_AUTH_REQUIRED: u8 = 0x00;
const METHOD_USERNAME_PASSWORD: u8 = 0x02;

/// SOCKS5 CONNECT client.
#[derive(Debug)]
pub struct Socks5Stream<S> {
    inner: S,
    dest_addr: DestAddr,
}

impl<S> Socks5Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Initiates a CONNECT request to the specified proxy.
    pub async fn connect(stream: S, dest: impl ToDestAddr) -> io::Result<Self> {
        connect_impl(Command::Connect, stream, dest, AuthMethod::None).await
    }

    /// Initiates a CONNECT request to the specified proxy with username and password.
    pub async fn connect_with_password(
        stream: S,
        dest: impl ToDestAddr,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> io::Result<Self> {
        connect_impl(
            Command::Connect,
            stream,
            dest,
            AuthMethod::Password {
                username: username.into(),
                password: password.into(),
            },
        )
        .await
    }

    /// Returns the destination address that the proxy server connects to.
    pub fn dest_addr(&self) -> &DestAddr {
        &self.dest_addr
    }
}

impl<S> AsyncRead for Socks5Stream<S>
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

impl<S> AsyncWrite for Socks5Stream<S>
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

/// SOCKS5 BIND client.
#[derive(Debug)]
pub struct Socks5Listener<S>(Socks5Stream<S>);

impl<S> Socks5Listener<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Initiates a BIND request to the specified proxy.
    ///
    /// Incoming connections are filtered based on the value of `dest`.
    pub async fn bind(stream: S, dest: impl ToDestAddr) -> io::Result<Self> {
        let stream = connect_impl(Command::Bind, stream, dest, AuthMethod::None).await?;
        Ok(Self(stream))
    }

    /// Initiates a BIND request to the specified proxy with username and password.
    ///
    /// Incoming connections are filtered based on the value of `dest`.
    pub async fn bind_with_password(
        stream: S,
        dest: impl ToDestAddr,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> io::Result<Self> {
        let stream = connect_impl(
            Command::Bind,
            stream,
            dest,
            AuthMethod::Password {
                username: username.into(),
                password: password.into(),
            },
        )
        .await?;

        Ok(Self(stream))
    }

    /// Returns the address of the proxy-side TCP listener.
    ///
    /// This should be forwarded to the remote process, which should open a
    /// connection to it.
    pub fn bind_addr(&self) -> &DestAddr {
        &self.0.dest_addr
    }

    /// Waits for the remote process to connect to the proxy server.
    ///
    /// The value of `bind_addr` should be forwarded to the remote process,
    /// which should open a connection to it.
    pub async fn accept(self) -> io::Result<Socks5Stream<S>> {
        let mut stream = self.0;
        Ok(Socks5Stream {
            dest_addr: read_socks_reply(&mut stream.inner).await?,
            inner: stream.inner,
        })
    }
}

#[repr(u8)]
enum Command {
    Connect = 0x01,
    Bind = 0x02,
    // UdpAssociate = 0x03,
}

enum AuthMethod {
    Password { username: String, password: String },
    None,
}

async fn connect_impl<S>(
    command: Command,
    mut stream: S,
    dest: impl ToDestAddr,
    auth: AuthMethod,
) -> io::Result<Socks5Stream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let dest = dest.to_dest_addr()?;

    let auth_methods = {
        let mut methods: Vec<u8> = vec![METHOD_NO_AUTH_REQUIRED];
        if let AuthMethod::Password { .. } = &auth {
            methods.push(METHOD_USERNAME_PASSWORD);
        }
        methods
    };

    {
        // negotation request

        let mut packet = vec![5, auth_methods.len() as u8];
        packet.extend_from_slice(&auth_methods);
        stream.write_all(&packet).await?;
    }

    {
        // negotiation response

        let mut buffer = [0; 2];
        stream.read_exact(&mut buffer).await?;
        let [resp_version, resp_auth_method] = buffer;

        if resp_version != 5 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid response version"));
        }

        // actual authentication if required

        match (resp_auth_method, auth) {
            (METHOD_NO_AUTH_REQUIRED, _) => {}
            (METHOD_USERNAME_PASSWORD, AuthMethod::Password { username, password }) => {
                password_authentication(&mut stream, username, password).await?
            }
            (method, _) if !auth_methods.contains(&method) => {
                // as per RFC server should send 0xFF as method if none of the methods
                // listed by client are acceptable.
                // However some implementation ignores this (ie: CCProxy 8.0).
                return Err(io::Error::new(io::ErrorKind::Other, "no acceptable auth method"));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "unknown / unsupported auth method",
                ))
            }
        }
    }

    {
        // SOCKS request

        let mut packet = [0; MAX_ADDR_LEN + 3];
        packet[0] = 5; // protocol version
        packet[1] = command as u8; // command
        packet[2] = 0; // reserved
        let len = write_addr(&mut packet[3..], &dest)?;
        stream.write_all(&packet[..len + 3]).await?;
    }

    // SOCKS reply
    let dest_addr = read_socks_reply(&mut stream).await?;

    Ok(Socks5Stream {
        inner: stream,
        dest_addr,
    })
}

async fn read_socks_reply<S>(stream: &mut S) -> io::Result<DestAddr>
where
    S: AsyncRead + Unpin,
{
    if stream.read_u8().await? != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid response version"));
    }

    match stream.read_u8().await? {
        0 => {}
        1 => return Err(io::Error::new(io::ErrorKind::Other, "general SOCKS server failure")),
        2 => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "connection not allowed by ruleset",
            ))
        }
        3 => return Err(io::Error::new(io::ErrorKind::Other, "network unreachable")),
        4 => return Err(io::Error::new(io::ErrorKind::Other, "host unreachable")),
        5 => return Err(io::Error::new(io::ErrorKind::Other, "connection refused")),
        6 => return Err(io::Error::new(io::ErrorKind::Other, "TTL expired")),
        7 => return Err(io::Error::new(io::ErrorKind::Other, "command not supported")),
        8 => return Err(io::Error::new(io::ErrorKind::Other, "address kind not supported")),
        _ => return Err(io::Error::new(io::ErrorKind::Other, "unknown error")),
    }

    if stream.read_u8().await? != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid reserved byte"));
    }

    read_addr(stream).await
}

async fn password_authentication<S>(socket: &mut S, username: String, password: String) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let username_len = match u8::try_from(username.len()) {
        Ok(len) if len > 0 => len,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid username")),
    };

    let password_len = match u8::try_from(password.len()) {
        Ok(len) if len > 0 => len,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid password")),
    };

    let mut packet = [0; 515];
    let mut writer: &mut [u8] = &mut packet;
    writer.write_all(&[
        1, // version
        username_len,
    ])?;
    writer.write_all(username.as_bytes())?;
    writer.write_all(&[password_len])?;
    writer.write_all(password.as_bytes())?;

    let packet_size = 3 + username.len() + password.len();
    socket.write_all(&packet[..packet_size]).await?;

    let mut buffer = [0; 2];
    socket.read_exact(&mut buffer).await?;
    let [resp_version, resp_result] = buffer;

    if resp_version != 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid response version"));
    }

    if resp_result != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "password authentication failed",
        ));
    }

    Ok(())
}

// https://www.ietf.org/rfc/rfc1928.txt
// o  ATYP (1 byte)  address type of following addresses:
//     o  IP V4 address: X'01'
//     o  DOMAINNAME: X'03'
//     o  IP V6 address: X'04'
// o  DST.ADDR (variable)
//      desired destination address
// o  DST.PORT (2 bytes)
//      desired destination port

async fn read_addr<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<DestAddr> {
    match stream.read_u8().await? {
        1 => {
            let ip = Ipv4Addr::from(stream.read_u32().await?);
            let port = stream.read_u16().await?;
            Ok(DestAddr::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port))))
        }
        3 => {
            let len = stream.read_u8().await?;
            let mut domain = vec![0; len as usize];
            stream.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let port = stream.read_u16().await?;
            Ok(DestAddr::Domain(domain, port))
        }
        4 => {
            let mut ip = [0; 16];
            stream.read_exact(&mut ip).await?;
            let ip = Ipv6Addr::from(ip);
            let port = stream.read_u16().await?;
            Ok(DestAddr::Ip(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))))
        }
        _ => Err(io::Error::new(io::ErrorKind::Other, "unsupported address type")),
    }
}

fn write_addr(mut addr_buf: &mut [u8], dest: &DestAddr) -> io::Result<usize> {
    let initial_len = addr_buf.len();
    match dest {
        DestAddr::Ip(SocketAddr::V4(addr)) => {
            addr_buf.write_all(&[1])?;
            addr_buf.write_all(&u32::from(*addr.ip()).to_be_bytes())?;
            addr_buf.write_all(&addr.port().to_be_bytes())?;
        }
        DestAddr::Ip(SocketAddr::V6(addr)) => {
            addr_buf.write_all(&[4])?;
            addr_buf.write_all(&addr.ip().octets())?;
            addr_buf.write_all(&addr.port().to_be_bytes())?;
        }
        DestAddr::Domain(domain, port) => {
            if let Ok(len) = u8::try_from(domain.len()) {
                addr_buf.write_all(&[3, len])?;
            } else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "domain name too long"));
            }
            addr_buf.write_all(domain.as_bytes())?;
            addr_buf.write_all(&port.to_be_bytes())?;
        }
    }

    Ok(initial_len - addr_buf.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{AsyncStdIo, DummyStream};

    const GOOGLE_ADDR: &str = "google.com:80";

    fn socks5_dummy() -> DummyStream {
        DummyStream(vec![5, METHOD_USERNAME_PASSWORD])
    }

    #[tokio::test]
    async fn invalid_username() {
        let err = Socks5Stream::connect_with_password(socks5_dummy(), GOOGLE_ADDR, "", "x".repeat(255))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "invalid username");

        let err = Socks5Stream::connect_with_password(socks5_dummy(), GOOGLE_ADDR, "x".repeat(256), "x".repeat(255))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "invalid username");
    }

    #[tokio::test]
    async fn invalid_password() {
        let err = Socks5Stream::connect_with_password(socks5_dummy(), GOOGLE_ADDR, "x".repeat(255), "")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "invalid password");

        let err = Socks5Stream::connect_with_password(socks5_dummy(), GOOGLE_ADDR, "x".repeat(255), "x".repeat(256))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "invalid password");
    }

    async fn assert_encoding(addr: DestAddr, encoded: &[u8]) {
        // encode
        let mut buf = [0; MAX_ADDR_LEN];
        let len = write_addr(&mut buf, &addr).unwrap();
        assert_eq!(&buf[..len], encoded);

        // decode
        let mut reader = AsyncStdIo(encoded);
        let decoded = read_addr(&mut reader).await.unwrap();
        assert_eq!(decoded, addr);
    }

    #[tokio::test]
    async fn ipv4_addr() {
        assert_encoding("192.168.0.39:80".to_dest_addr().unwrap(), &[1, 192, 168, 0, 39, 0, 80]).await;
    }

    #[tokio::test]
    async fn ipv6_addr() {
        assert_encoding(
            "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443".to_dest_addr().unwrap(),
            &[
                4, 32, 1, 13, 184, 133, 163, 8, 211, 19, 25, 138, 46, 3, 112, 115, 72, 1, 187,
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn domain_addr() {
        assert_encoding(
            "devolutions.net:80".to_dest_addr().unwrap(),
            &[
                3, 15, 100, 101, 118, 111, 108, 117, 116, 105, 111, 110, 115, 46, 110, 101, 116, 0, 80,
            ],
        )
        .await;
    }
}
