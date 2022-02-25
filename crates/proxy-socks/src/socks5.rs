use crate::ReadWriteStream;
use proxy_types::{BoundAddr, DestAddr, ToDestAddr};
use std::convert::TryFrom;
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const SOCKS_VERSION: u8 = 0x05;
const PASSWORD_NEGOTIATION_VERSION: u8 = 0x01;
const ADDR_MAX_LEN: usize = 260;

/// SOCKS5 CONNECT client.
#[derive(Debug)]
pub struct Socks5Stream<S> {
    inner: S,
    bound_addr: BoundAddr,
}

impl<S> Socks5Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Initiates a CONNECT request to the specified proxy.
    pub async fn connect(mut stream: S, dest: impl ToDestAddr) -> io::Result<Self> {
        let dest_addr = connect_impl(Command::Connect, &mut stream, dest.to_dest_addr()?, AuthMethod::None).await?;

        Ok(Self {
            inner: stream,
            bound_addr: dest_addr,
        })
    }

    /// Initiates a CONNECT request to the specified proxy with username and password.
    pub async fn connect_with_password(
        mut stream: S,
        dest: impl ToDestAddr,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> io::Result<Self> {
        let dest_addr = connect_impl(
            Command::Connect,
            &mut stream,
            dest.to_dest_addr()?,
            AuthMethod::Password {
                username: username.into(),
                password: password.into(),
            },
        )
        .await?;

        Ok(Self {
            inner: stream,
            bound_addr: dest_addr,
        })
    }

    /// Returns the server bound address (and port)
    ///
    /// This is the port number that the server assigned to connect to the target and
    /// the associated IP address.
    pub fn bound_addr(&self) -> &BoundAddr {
        &self.bound_addr
    }

    pub fn into_inner(self) -> S {
        self.inner
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
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Initiates a BIND request to the specified proxy.
    ///
    /// Incoming connections are filtered based on the value of `dest`.
    pub async fn bind(mut stream: S, dest: impl ToDestAddr) -> io::Result<Self> {
        let dest_addr = connect_impl(Command::Bind, &mut stream, dest.to_dest_addr()?, AuthMethod::None).await?;

        Ok(Self(Socks5Stream {
            inner: stream,
            bound_addr: dest_addr,
        }))
    }

    /// Initiates a BIND request to the specified proxy with username and password.
    ///
    /// Incoming connections are filtered based on the value of `dest`.
    pub async fn bind_with_password(
        mut stream: S,
        dest: impl ToDestAddr,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> io::Result<Self> {
        let dest_addr = connect_impl(
            Command::Bind,
            &mut stream,
            dest.to_dest_addr()?,
            AuthMethod::Password {
                username: username.into(),
                password: password.into(),
            },
        )
        .await?;

        Ok(Self(Socks5Stream {
            inner: stream,
            bound_addr: dest_addr,
        }))
    }

    /// Returns the address of the proxy-side TCP listener.
    ///
    /// This should be forwarded to the remote process, which should open a
    /// connection to it.
    pub fn bound_addr(&self) -> &BoundAddr {
        &self.0.bound_addr
    }

    /// Waits for the remote process to connect to the proxy server.
    ///
    /// The SOCKS server sends the second reply only after the anticipated incoming connection
    /// succeeds or fails.
    pub async fn accept(self) -> io::Result<Socks5Stream<S>> {
        let mut stream = self.0;
        Ok(Socks5Stream {
            bound_addr: SocksResponse::read(&mut stream.inner).await?.bnd,
            inner: stream.inner,
        })
    }
}

async fn connect_impl(
    command: Command,
    stream: &mut dyn ReadWriteStream,
    dest: DestAddr,
    auth: AuthMethod,
) -> io::Result<BoundAddr> {
    // Client greeting
    let negotiation_request = {
        let mut methods: Vec<u8> = vec![AuthMethod::NO_AUTH_REQUIRED];
        if let AuthMethod::Password { .. } = &auth {
            methods.push(AuthMethod::USERNAME_PASSWORD);
        }
        NegotiationRequest { methods }
    };
    negotiation_request.write(stream).await?;

    // Server choice
    let negotiation_response = NegotiationResponse::read(stream).await?;

    // Actual authentication if required
    match (negotiation_response.method, auth) {
        (AuthMethod::NO_AUTH_REQUIRED, _) => {}
        (AuthMethod::USERNAME_PASSWORD, AuthMethod::Password { username, password }) => {
            client_password_authentication(stream, username, password).await?
        }
        (method, _) if !negotiation_request.methods.contains(&method) => {
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

    // SOCKS request
    SocksRequest {
        cmd: command,
        dst: dest,
    }
    .write(stream)
    .await?;

    // SOCKS reply
    let socks_reply = SocksResponse::read(stream).await?;

    Ok(socks_reply.bnd)
}

/// Configuration for a SOCKS5 acceptor.
#[derive(Debug, Default)]
pub struct Socks5AcceptorConfig {
    pub no_auth_required: bool,
    /// Optional list of tuples (user / password) for password authentication
    pub users: Option<Vec<(String, String)>>,
}

/// SOCKS5 failure codes defined in RFC1928.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Socks5FailureCode {
    GeneralSocksServerFailure = 0x01,
    ConnectionNotAllowedByRuleset = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl std::error::Error for Socks5FailureCode {}

impl core::fmt::Display for Socks5FailureCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Socks5FailureCode::GeneralSocksServerFailure => write!(f, "general SOCKS server failure"),
            Socks5FailureCode::ConnectionNotAllowedByRuleset => write!(f, "connection not allowed by ruleset"),
            Socks5FailureCode::NetworkUnreachable => write!(f, "network unreachable"),
            Socks5FailureCode::HostUnreachable => write!(f, "host unreachable"),
            Socks5FailureCode::ConnectionRefused => write!(f, "connection refused"),
            Socks5FailureCode::TtlExpired => write!(f, "TTL expired"),
            Socks5FailureCode::CommandNotSupported => write!(f, "command not supported"),
            Socks5FailureCode::AddressTypeNotSupported => write!(f, "address type not supported"),
        }
    }
}

impl Socks5FailureCode {
    fn to_u8(self) -> u8 {
        self as u8
    }
}

impl From<std::io::ErrorKind> for Socks5FailureCode {
    fn from(kind: std::io::ErrorKind) -> Socks5FailureCode {
        match kind {
            std::io::ErrorKind::ConnectionRefused => Socks5FailureCode::ConnectionRefused,
            std::io::ErrorKind::TimedOut => Socks5FailureCode::TtlExpired,
            #[cfg(feature = "nightly")] // https://github.com/rust-lang/rust/issues/86442
            std::io::ErrorKind::HostUnreachable => Socks5FailureCode::HostUnreachable,
            #[cfg(feature = "nightly")] // https://github.com/rust-lang/rust/issues/86442
            std::io::ErrorKind::NetworkUnreachable => Socks5FailureCode::NetworkUnreachable,
            _ => Socks5FailureCode::GeneralSocksServerFailure,
        }
    }
}

impl From<std::io::Error> for Socks5FailureCode {
    fn from(e: std::io::Error) -> Socks5FailureCode {
        Socks5FailureCode::from(e.kind())
    }
}

impl From<&std::io::Error> for Socks5FailureCode {
    fn from(e: &std::io::Error) -> Socks5FailureCode {
        Socks5FailureCode::from(e.kind())
    }
}

/// SOCKS5 request acceptor for usage in proxy server.
#[derive(Debug)]
pub struct Socks5Acceptor<S> {
    inner: S,
    socks_request: SocksRequest,
}

impl<S> Socks5Acceptor<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Accepts SOCKS5 stream without requiring any authentication.
    pub async fn accept(mut stream: S) -> io::Result<Self> {
        let conf = Socks5AcceptorConfig {
            no_auth_required: true,
            ..Socks5AcceptorConfig::default()
        };
        let req = accept_impl(&mut stream, &conf).await?;
        Ok(Self {
            inner: stream,
            socks_request: req,
        })
    }

    /// Accepts SOCKS5 stream using a user-defined configuration.
    pub async fn accept_with_config(mut stream: S, conf: &Socks5AcceptorConfig) -> io::Result<Self> {
        let req = accept_impl(&mut stream, conf).await?;
        Ok(Self {
            inner: stream,
            socks_request: req,
        })
    }

    /// Returns the destination address that the proxy server should connects to.
    pub fn dest_addr(&self) -> &DestAddr {
        &self.socks_request.dst
    }

    pub fn is_bind_command(&self) -> bool {
        matches!(self.socks_request.cmd, Command::Bind)
    }

    pub fn is_connect_command(&self) -> bool {
        matches!(self.socks_request.cmd, Command::Connect)
    }

    pub fn is_udp_associate_command(&self) -> bool {
        matches!(self.socks_request.cmd, Command::UdpAssociate)
    }

    /// Sends first reply after a BIND request.
    ///
    /// `binded_address` is the address of the freshly created and binded socket.
    pub async fn binded(&mut self, binded_address: impl ToDestAddr) -> io::Result<()> {
        SocksResponse::success(binded_address.to_dest_addr()?)
            .write(&mut self.inner)
            .await
    }

    /// Sends final SOCKS reply.
    ///
    /// `bound_address` is either the address of the connecting host for a BIND command or the
    /// local address used to connect to the target host by the SOCKS server for a CONNECT command.
    pub async fn connected(mut self, bound_address: impl ToDestAddr) -> io::Result<S> {
        SocksResponse::success(bound_address.to_dest_addr()?)
            .write(&mut self.inner)
            .await?;
        Ok(self.inner)
    }

    /// Sends a SOCKS failure reply and consumes the stream.
    pub async fn failed(mut self, code: Socks5FailureCode) -> io::Result<()> {
        SocksResponse::failure(code).write(&mut self.inner).await
    }
}

async fn accept_impl(stream: &mut dyn ReadWriteStream, conf: &Socks5AcceptorConfig) -> io::Result<SocksRequest> {
    let negotiation_request = NegotiationRequest::read(stream).await?;

    let selected_method = negotiation_request.methods.into_iter().find(|&m| match m {
        AuthMethod::NO_AUTH_REQUIRED if conf.no_auth_required => true,
        AuthMethod::USERNAME_PASSWORD if conf.users.is_some() => true,
        _ => false,
    });

    if let Some(method) = selected_method {
        NegotiationResponse::new(method).write(stream).await?;

        if method == AuthMethod::USERNAME_PASSWORD {
            // this should not panic because it is checked above
            let users = conf.users.as_deref().expect("username / password list");
            server_password_authentication(stream, users).await?;
        }
    } else {
        NegotiationResponse::new(AuthMethod::NO_ACCEPTABLE_METHODS)
            .write(stream)
            .await?;

        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no acceptable methods provided",
        ));
    }

    let socks_request = SocksRequest::read(stream).await?;

    Ok(socks_request)
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

enum AuthMethod {
    Password { username: String, password: String },
    None,
}

impl AuthMethod {
    const NO_AUTH_REQUIRED: u8 = 0x00;
    const USERNAME_PASSWORD: u8 = 0x02;
    const NO_ACCEPTABLE_METHODS: u8 = 0xFF;
}

// Negotation request (client greeting)
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+
struct NegotiationRequest {
    methods: Vec<u8>,
}

impl NegotiationRequest {
    async fn write(&self, stream: &mut dyn ReadWriteStream) -> io::Result<()> {
        let nauth = u8::try_from(self.methods.len()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut packet = vec![SOCKS_VERSION, nauth];
        packet.extend_from_slice(&self.methods);
        stream.write_all(&packet).await?;
        Ok(())
    }

    async fn read(stream: &mut dyn ReadWriteStream) -> io::Result<Self> {
        let mut fixed_part = [0; 2];
        stream.read_exact(&mut fixed_part).await?;
        let [req_version, req_nmethods] = fixed_part;

        if req_version != SOCKS_VERSION {
            NegotiationResponse::new(AuthMethod::NO_ACCEPTABLE_METHODS)
                .write(stream)
                .await?;

            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request version"));
        }

        let mut methods = vec![0; usize::from(req_nmethods)];
        stream.read_exact(&mut methods).await?;

        Ok(Self { methods })
    }
}

/// Negotiation response (server choice)
/// +----+--------+
/// |VER | METHOD |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
struct NegotiationResponse {
    method: u8,
}

impl NegotiationResponse {
    fn new(method: u8) -> Self {
        Self { method }
    }

    async fn write(&self, stream: &mut dyn ReadWriteStream) -> io::Result<()> {
        stream.write_all(&[SOCKS_VERSION, self.method]).await?;
        Ok(())
    }

    async fn read(stream: &mut dyn ReadWriteStream) -> io::Result<Self> {
        let mut buffer = [0; 2];
        stream.read_exact(&mut buffer).await?;
        let [ver, method] = buffer;

        if ver != SOCKS_VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid response version"));
        }

        Ok(Self { method })
    }
}

/// SOCKS request
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
#[derive(Debug)]
struct SocksRequest {
    cmd: Command,
    dst: DestAddr,
}

impl SocksRequest {
    const FIXED_PART_LEN: usize = 3;

    async fn write(&self, stream: &mut dyn ReadWriteStream) -> io::Result<()> {
        let mut packet = [0x00; ADDR_MAX_LEN + Self::FIXED_PART_LEN];

        // fixed part
        packet[0] = 0x05; // protocol version
        packet[1] = self.cmd as u8; // command
        packet[2] = 0x00; // reserved

        // variable part
        let variable_part_len = write_addr(&self.dst, &mut packet[Self::FIXED_PART_LEN..])?;

        // send packet
        let packet_len = Self::FIXED_PART_LEN + variable_part_len;
        stream.write_all(&packet[..packet_len]).await?;

        Ok(())
    }

    async fn read(stream: &mut dyn ReadWriteStream) -> io::Result<Self> {
        if stream.read_u8().await? != SOCKS_VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request version"));
        }

        let cmd = stream.read_u8().await?;
        let cmd = match cmd {
            0x01 => Command::Connect,
            0x02 => Command::Bind,
            0x03 => Command::UdpAssociate,
            _ => return Err(io::Error::new(io::ErrorKind::Other, "unknown command")),
        };

        if stream.read_u8().await? != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid reserved byte"));
        }

        let dest_addr = read_addr(stream).await?;

        Ok(Self { cmd, dst: dest_addr })
    }
}

/// SOCKS reply
/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
struct SocksResponse {
    rep: u8,
    bnd: BoundAddr,
}

impl SocksResponse {
    const FIXED_PART_LEN: usize = 3;

    fn failure(code: Socks5FailureCode) -> Self {
        Self {
            rep: code.to_u8(),
            bnd: BoundAddr::Ip(SocketAddr::from(([0, 0, 0, 0], 0))),
        }
    }

    fn success(bound_address: BoundAddr) -> Self {
        Self {
            rep: 0x00,
            bnd: bound_address,
        }
    }

    async fn write(&self, stream: &mut dyn ReadWriteStream) -> io::Result<()> {
        let mut packet = [0x00; ADDR_MAX_LEN + Self::FIXED_PART_LEN];

        // fixed part
        packet[0] = 0x05; // protocol version
        packet[1] = self.rep; // reply code
        packet[2] = 0x00; // reserved

        // variable part
        let variable_part_len = write_addr(&self.bnd, &mut packet[Self::FIXED_PART_LEN..])?;

        // send packet
        let packet_len = Self::FIXED_PART_LEN + variable_part_len;
        stream.write_all(&packet[..packet_len]).await?;

        Ok(())
    }

    async fn read(stream: &mut dyn ReadWriteStream) -> io::Result<Self> {
        if stream.read_u8().await? != SOCKS_VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid response version"));
        }

        let rep = stream.read_u8().await?;

        match rep {
            0 => {} // succeeded
            1 => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    Socks5FailureCode::GeneralSocksServerFailure,
                ))
            }
            2 => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    Socks5FailureCode::ConnectionNotAllowedByRuleset,
                ))
            }
            3 => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    Socks5FailureCode::NetworkUnreachable,
                ))
            }
            4 => return Err(io::Error::new(io::ErrorKind::Other, Socks5FailureCode::HostUnreachable)),
            5 => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    Socks5FailureCode::ConnectionRefused,
                ))
            }
            6 => return Err(io::Error::new(io::ErrorKind::TimedOut, Socks5FailureCode::TtlExpired)),
            7 => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    Socks5FailureCode::CommandNotSupported,
                ))
            }
            8 => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    Socks5FailureCode::AddressTypeNotSupported,
                ))
            }
            _ => return Err(io::Error::new(io::ErrorKind::Other, "unknown SOCKS error")),
        }

        if stream.read_u8().await? != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid reserved byte"));
        }

        let bound_addr = read_addr(stream).await?;

        Ok(Self { rep, bnd: bound_addr })
    }
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

async fn read_addr(stream: &mut dyn ReadWriteStream) -> io::Result<DestAddr> {
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

fn write_addr(addr: &DestAddr, mut addr_buf: &mut [u8]) -> io::Result<usize> {
    let initial_len = addr_buf.len();

    match addr {
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

// https://datatracker.ietf.org/doc/html/rfc1929
// +----+------+----------+------+----------+
// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
// +----+------+----------+------+----------+
// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
// +----+------+----------+------+----------+
struct PasswordNegotiationRequest {
    username: String,
    password: String,
}

impl PasswordNegotiationRequest {
    const STR_MAX_LEN: usize = u8::MAX as usize;
    const FIXED_PART_LEN: usize = 3;
    const MAX_LEN: usize = Self::FIXED_PART_LEN + Self::STR_MAX_LEN * 2;

    async fn write(&self, stream: &mut dyn ReadWriteStream) -> io::Result<()> {
        let username_len = match u8::try_from(self.username.len()) {
            Ok(len) if len > 0 => len,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid username")),
        };

        let password_len = match u8::try_from(self.password.len()) {
            Ok(len) if len > 0 => len,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid password")),
        };

        let packet_size = Self::FIXED_PART_LEN + self.username.len() + self.password.len();

        // Write request packet
        let mut packet = [0; Self::MAX_LEN];
        let mut buf: &mut [u8] = &mut packet;
        buf.write_all(&[PASSWORD_NEGOTIATION_VERSION, username_len])?;
        buf.write_all(self.username.as_bytes())?;
        buf.write_all(&[password_len])?;
        buf.write_all(self.password.as_bytes())?;

        // Send request
        stream.write_all(&packet[..packet_size]).await?;

        Ok(())
    }

    async fn read(stream: &mut dyn ReadWriteStream) -> io::Result<Self> {
        if stream.read_u8().await? != PASSWORD_NEGOTIATION_VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid response version"));
        }

        let username_len = usize::from(stream.read_u8().await?);
        let mut username = vec![0; username_len];
        stream.read_exact(&mut username).await?;
        let username = String::from_utf8(username)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad utf8 for username"))?;

        let password_len = usize::from(stream.read_u8().await?);
        let mut password = vec![0; password_len];
        stream.read_exact(&mut password).await?;
        let password = String::from_utf8(password)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad utf8 for password"))?;

        Ok(Self { username, password })
    }
}

/// https://datatracker.ietf.org/doc/html/rfc1929
/// +----+--------+
/// |VER | STATUS |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
struct PasswordNegotiationResponse {
    status: u8,
}

impl PasswordNegotiationResponse {
    async fn read(stream: &mut dyn ReadWriteStream) -> io::Result<Self> {
        let mut buffer = [0; 2];
        stream.read_exact(&mut buffer).await?;
        let [ver, status] = buffer;

        if ver != PASSWORD_NEGOTIATION_VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid response version"));
        }

        Ok(Self { status })
    }

    async fn write(&self, stream: &mut dyn ReadWriteStream) -> io::Result<()> {
        let packet = [PASSWORD_NEGOTIATION_VERSION, self.status];
        stream.write_all(&packet).await?;
        Ok(())
    }
}

async fn client_password_authentication(
    stream: &mut dyn ReadWriteStream,
    username: String,
    password: String,
) -> io::Result<()> {
    PasswordNegotiationRequest { username, password }.write(stream).await?;

    let rsp = PasswordNegotiationResponse::read(stream).await?;

    if rsp.status != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "password authentication failed",
        ));
    }

    Ok(())
}

async fn server_password_authentication(
    stream: &mut dyn ReadWriteStream,
    users: &[(String, String)],
) -> io::Result<()> {
    const STATUS_SUCCESS: u8 = 0x00;
    const STATUS_FAILURE: u8 = 0xFF; // this could be any value other than 0x00

    let req = PasswordNegotiationRequest::read(stream).await?;

    let success = users
        .iter()
        .any(|(usr, pwd)| usr.eq(&req.username) && pwd.eq(&req.password));

    if success {
        PasswordNegotiationResponse { status: STATUS_SUCCESS }
            .write(stream)
            .await?;
    } else {
        PasswordNegotiationResponse { status: STATUS_FAILURE }
            .write(stream)
            .await?;

        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "password authentication failed",
        ));
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: for more comprehensive tests, see `proxy-tester`.

    // Greeting messages tests using dummy stream to validate errors

    const GOOGLE_ADDR: &str = "google.com:80";

    fn socks5_dummy() -> tokio_test::io::Mock {
        tokio_test::io::Builder::new()
            .write(&[5, 2, AuthMethod::NO_AUTH_REQUIRED, AuthMethod::USERNAME_PASSWORD])
            .read(&[5, AuthMethod::USERNAME_PASSWORD])
            .build()
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

    // address encoding tests

    async fn assert_encoding(addr: DestAddr, encoded: &[u8]) {
        // encode
        let mut buf = [0; ADDR_MAX_LEN];
        let len = write_addr(&addr, &mut buf).unwrap();
        assert_eq!(&buf[..len], encoded);

        // decode
        let mut reader = tokio_test::io::Builder::new().read(encoded).build();
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
