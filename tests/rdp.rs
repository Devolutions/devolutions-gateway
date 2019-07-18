mod common;

use std::{
    io::{self, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
    time::Duration,
};

use bytes::BytesMut;
use lazy_static::lazy_static;
use serde_derive::{Deserialize, Serialize};
use sspi::CredSsp;

use common::run_proxy;

lazy_static! {
    static ref X224_REQUEST_PROTOCOL: ironrdp::SecurityProtocol =
        ironrdp::SecurityProtocol::HYBRID | ironrdp::SecurityProtocol::SSL;
    static ref X224_REQUEST_FLAGS: ironrdp::NegotiationRequestFlags = ironrdp::NegotiationRequestFlags::empty();
    static ref X224_RESPONSE_PROTOCOL: ironrdp::SecurityProtocol = ironrdp::SecurityProtocol::HYBRID;
    static ref X224_RESPONSE_FLAGS: ironrdp::NegotiationResponseFlags =
        ironrdp::NegotiationResponseFlags::DYNVC_GFX_PROTOCOL_SUPPORTED
            | ironrdp::NegotiationResponseFlags::RDP_NEG_RSP_RESERVED
            | ironrdp::NegotiationResponseFlags::RESTRICTED_ADMIN_MODE_SUPPORTED
            | ironrdp::NegotiationResponseFlags::REDIRECTED_AUTHENTICATION_MODE_SUPPORTED;
    static ref PROXY_CREDENTIALS: sspi::Credentials = sspi::Credentials::new(
        String::from("Username1"),
        String::from("Password1"),
        Some(String::from("Domain1")),
    );
    static ref SERVER_CREDENTIALS: sspi::Credentials = sspi::Credentials::new(
        String::from("Username2"),
        String::from("Password2"),
        Some(String::from("Domain2")),
    );
    static ref ROUTING_URL: String = format!("rdp://{}", ROUTING_ADDR);
    static ref CERT_PKCS12_DER: Vec<u8> = include_bytes!("../src/cert/certificate.p12").to_vec();
}

const TLS_PUBLIC_KEY_HEADER: usize = 24;
const PROXY_ADDR: &str = "127.0.0.1:8080";
const ROUTING_ADDR: &str = "127.0.0.1:8081";
const JET_SERVER: &str = "rdp://127.0.0.1:8082";
const CERT_PKCS12_PASS: &str = "";

type RdpResult<T> = Result<T, RdpError>;

#[derive(Debug)]
pub struct RdpError(String);

#[derive(Clone, Serialize, Deserialize)]
pub struct RdpIdentity {
    pub proxy: sspi::Credentials,
    pub target: sspi::Credentials,
    pub destination: String,
}

#[derive(Clone)]
pub struct IdentitiesProxy {
    rdp_identity: sspi::Credentials,
}

struct RdpClient {
    proxy_addr: &'static str,
    proxy_credentials: sspi::Credentials,
    server_credentials: sspi::Credentials,
}

struct RdpServer {
    routing_addr: &'static str,
    identities_proxy: IdentitiesProxy,
}

#[test]
fn rdp_with_nla_ntlm() {
    let mut identities_file = tempfile::NamedTempFile::new().expect("Failed to create a named temporary file");
    let rdp_identities = vec![RdpIdentity::new(
        PROXY_CREDENTIALS.clone(),
        SERVER_CREDENTIALS.clone(),
        ROUTING_ADDR.to_string(),
    )];
    RdpIdentity::list_to_buffer(rdp_identities.as_ref(), identities_file.as_file_mut())
        .expect("Failed to write identities to file");

    let _proxy = run_proxy(
        PROXY_ADDR,
        Some(JET_SERVER),
        Some(
            identities_file
                .path()
                .to_str()
                .expect("Failed to get path to a temporary file"),
        ),
    );

    let server_thread = thread::spawn(move || {
        let mut server = RdpServer::new(ROUTING_ADDR, IdentitiesProxy::new(SERVER_CREDENTIALS.clone()));
        server.run().expect("Error in server");
    });
    let client_thread = thread::spawn(move || {
        let client = RdpClient::new(PROXY_ADDR, PROXY_CREDENTIALS.clone(), SERVER_CREDENTIALS.clone());
        client.run().expect("Error in client");
    });

    server_thread.join().expect("Failed to join the server thread");
    client_thread.join().expect("Failed to join the client thread");
}

impl RdpClient {
    fn new(
        proxy_addr: &'static str,
        proxy_credentials: sspi::Credentials,
        server_credentials: sspi::Credentials,
    ) -> Self {
        Self {
            proxy_addr,
            proxy_credentials,
            server_credentials,
        }
    }

    fn run(&self) -> RdpResult<()> {
        let mut stream = connect_tcp_stream(self.proxy_addr);
        self.write_negotiation_request(&mut stream).map_err(|e| {
            RdpError::new(format!(
                "Error in the client during writing an negotiation request: {}",
                e
            ))
        })?;
        self.read_negotiation_response(&mut stream).map_err(|e| {
            RdpError::new(format!(
                "Error in the client during reading an negotiation response: {}",
                e
            ))
        })?;

        let mut tls_stream = connect_tls(self.proxy_addr, stream, true)
            .map_err(|e| RdpError::new(format!("Failed to connect with TLS: {}", e)))?;
        let tls_pubkey = get_tls_peer_pubkey(&tls_stream)
            .map_err(|e| RdpError::new(format!("Failed to get tls peer public key from the certificate: {}", e)))?;

        let cred_ssp_mode =
            if X224_REQUEST_FLAGS.contains(ironrdp::NegotiationRequestFlags::RESTRICTED_ADMIN_MODE_REQUIRED) {
                sspi::CredSspMode::CredentialLess
            } else {
                sspi::CredSspMode::WithCredentials
            };
        let mut cred_ssp_context =
            sspi::CredSspClient::with_default_version(tls_pubkey, self.proxy_credentials.clone(), cred_ssp_mode)
                .map_err(|e| RdpError::new(format!("Failed to create a CredSSP client: {}", e)))?;

        self.write_negotiate_message(&mut tls_stream, &mut cred_ssp_context)
            .map_err(|e| {
                RdpError::new(format!(
                    "Error in the client during writing an negotiate message: {}",
                    e
                ))
            })?;
        self
            .read_challenge_message_and_write_authenticate_message_with_pub_key_auth(&mut tls_stream, &mut cred_ssp_context)
            .map_err(|e| RdpError::new(format!("Error in the client during reading challenge message and writing autheticate message with a client public key: {}", e)))?;
        self.read_pub_key_auth_and_write_ts_credentials(&mut tls_stream, &mut cred_ssp_context)
            .map_err(|e| {
                RdpError::new(format!(
                    "Error in the client during reading public key and writing TSCredentials: {}",
                    e
                ))
            })?;

        Ok(())
    }

    fn write_negotiation_request(&self, stream: &mut TcpStream) -> RdpResult<()> {
        let cookie = &self.server_credentials.username;
        let mut request_data = BytesMut::with_capacity(ironrdp::NEGOTIATION_REQUEST_LEN + cookie.len());
        request_data.resize(ironrdp::NEGOTIATION_REQUEST_LEN + cookie.len(), 0x00);
        ironrdp::write_negotiation_request(
            request_data.as_mut(),
            &cookie,
            *X224_REQUEST_PROTOCOL,
            *X224_REQUEST_FLAGS,
        )
        .map_err(|e| RdpError::new(format!("Failed to write negotiation request: {}", e)))?;
        let x224_len = ironrdp::TPDU_REQUEST_LENGTH + request_data.len();
        let mut x224_encoded_request = BytesMut::with_capacity(x224_len);
        x224_encoded_request.resize(ironrdp::TPDU_REQUEST_LENGTH, 0);
        ironrdp::encode_x224(
            ironrdp::X224TPDUType::ConnectionRequest,
            request_data,
            &mut x224_encoded_request,
        )
        .map_err(|e| RdpError::new(format!("Failed to encode negotiation request: {}", e)))?;

        stream
            .write_all(x224_encoded_request.as_ref())
            .map_err(|e| RdpError::new(format!("Failed to send negotiation request: {}", e)))?;

        Ok(())
    }

    fn read_negotiation_response(&self, mut stream: &mut TcpStream) -> RdpResult<()> {
        let mut buffer = read_stream_buffer(&mut stream);
        let (code, data) = ironrdp::decode_x224(&mut buffer)
            .map_err(|e| RdpError::new(format!("Failed to decode negotiation response: {}", e)))?;
        assert_eq!(code, ironrdp::X224TPDUType::ConnectionConfirm);
        let (protocol, flags) = ironrdp::parse_negotiation_response(code, data.as_ref())
            .map_err(|e| RdpError::new(format!("Failed to parse negotiation response: {}", e)))?;
        assert_eq!(*X224_RESPONSE_PROTOCOL, protocol);
        assert_eq!(*X224_RESPONSE_FLAGS, flags);

        Ok(())
    }

    fn write_negotiate_message(
        &self,
        tls_stream: &mut native_tls::TlsStream<TcpStream>,
        cred_ssp_context: &mut sspi::CredSspClient,
    ) -> RdpResult<()> {
        process_cred_ssp_phase_with_reply_needed(sspi::TsRequest::default(), cred_ssp_context, tls_stream)
            .map_err(|e| RdpError::new(format!("Failed to process a credssp phase: {}", e)))?;

        Ok(())
    }

    fn read_challenge_message_and_write_authenticate_message_with_pub_key_auth(
        &self,
        mut tls_stream: &mut native_tls::TlsStream<TcpStream>,
        cred_ssp_context: &mut sspi::CredSspClient,
    ) -> RdpResult<()> {
        let buffer = read_stream_buffer(&mut tls_stream);
        let read_ts_request = sspi::TsRequest::from_buffer(buffer.as_ref())
            .map_err(|e| RdpError::new(format!("Failed to parse ts request: {}", e)))?;

        process_cred_ssp_phase_with_reply_needed(read_ts_request, cred_ssp_context, tls_stream)
    }

    fn read_pub_key_auth_and_write_ts_credentials(
        &self,
        tls_stream: &mut native_tls::TlsStream<TcpStream>,
        cred_ssp_context: &mut sspi::CredSspClient,
    ) -> RdpResult<()> {
        let buffer = read_stream_buffer(tls_stream);
        let read_ts_request = sspi::TsRequest::from_buffer(buffer.as_ref())
            .map_err(|e| RdpError::new(format!("Failed to parse ts request with ntlm challenge message: {}", e)))?;

        let reply = cred_ssp_context
            .process(read_ts_request)
            .map_err(|e| RdpError::new(format!("CredSSP process call error: {}", e)))?;
        match reply {
            sspi::CredSspResult::FinalMessage(ts_request) => {
                let mut ts_request_buffer = Vec::with_capacity(ts_request.buffer_len() as usize);
                ts_request
                    .encode_ts_request(&mut ts_request_buffer)
                    .map_err(|e| RdpError::new(format!("Failed to encode ts request with ts credentials: {}", e)))?;

                tls_stream
                    .write_all(&ts_request_buffer)
                    .map_err(|e| RdpError::new(format!("Failed to send encrypted ts credentials: {}", e)))?;
            }
            _ => panic!("The CredSSP server has returned unexpected result: {:?}", reply),
        };

        Ok(())
    }
}

impl RdpServer {
    fn new(routing_addr: &'static str, identities_proxy: IdentitiesProxy) -> Self {
        Self {
            routing_addr,
            identities_proxy,
        }
    }

    fn run(&mut self) -> RdpResult<()> {
        let mut stream = accept_tcp_stream(self.routing_addr)
            .map_err(|e| RdpError::new(format!("Failed to accept tcp stream: {}", e)))?;
        self.read_negotiation_request(&mut stream).map_err(|e| {
            RdpError::new(format!(
                "Error in the server during reading an negotiation request: {}",
                e
            ))
        })?;
        self.write_negotiation_response(&mut stream).map_err(|e| {
            RdpError::new(format!(
                "Error in the server during writing an negotiation response: {}",
                e
            ))
        })?;

        let mut tls_stream = accept_tls(stream, CERT_PKCS12_DER.clone(), CERT_PKCS12_PASS)?;
        let tls_pubkey = get_tls_pubkey(CERT_PKCS12_DER.clone().as_ref(), CERT_PKCS12_PASS)
            .map_err(|e| RdpError::new(format!("Failed to get tls public key: {}", e)))?;

        let mut cred_ssp_context = sspi::CredSspServer::with_default_version(tls_pubkey, self.identities_proxy.clone())
            .map_err(|e| RdpError::new(format!("Failed to create a CredSSP server: {}", e)))?;

        self.read_negotiate_message_and_write_challenge_message(&mut tls_stream, &mut cred_ssp_context)
            .map_err(|e| {
                RdpError::new(format!(
                    "Error in the server during reading an negotiate message and writing challenge message: {}",
                    e
                ))
            })?;
        self
            .read_authenticate_message_with_pub_key_auth_and_write_pub_key_auth(&mut tls_stream, &mut cred_ssp_context)
            .map_err(|e| RdpError::new(format!("Error in the server during reading an authenticate message with an encrypted client public key and writing an encrypted server public key: {}", e)))?;
        self.read_ts_credentials(&mut tls_stream, &mut cred_ssp_context)
            .map_err(|e| RdpError::new(format!("Error in the server during reading a TSCredentials: {}", e)))?;

        Ok(())
    }

    fn read_negotiation_request(&self, stream: &mut TcpStream) -> RdpResult<()> {
        let mut buffer = read_stream_buffer(stream);

        let (code, data) = ironrdp::decode_x224(&mut buffer)
            .map_err(|e| RdpError::new(format!("Failed to decode negotiation request: {}", e)))?;
        assert_eq!(code, ironrdp::X224TPDUType::ConnectionRequest);
        let (_nego_data, _protocol, _flags) = ironrdp::parse_negotiation_request(code, data.as_ref())
            .map_err(|e| RdpError::new(format!("Failed to parse negotiation request: {}", e)))?;

        Ok(())
    }

    fn write_negotiation_response(&self, stream: &mut TcpStream) -> RdpResult<()> {
        let mut response_data = BytesMut::with_capacity(ironrdp::NEGOTIATION_RESPONSE_LEN);
        response_data.resize(ironrdp::NEGOTIATION_RESPONSE_LEN, 0x00);
        ironrdp::write_negotiation_response(response_data.as_mut(), *X224_RESPONSE_FLAGS, *X224_RESPONSE_PROTOCOL)
            .map_err(|e| RdpError::new(format!("Failed to write negotiation response: {}", e)))?;
        let x224_len = ironrdp::TPDU_REQUEST_LENGTH + response_data.len();
        let mut x224_encoded_response = BytesMut::with_capacity(x224_len);
        x224_encoded_response.resize(ironrdp::TPDU_REQUEST_LENGTH, 0);
        ironrdp::encode_x224(
            ironrdp::X224TPDUType::ConnectionConfirm,
            response_data,
            &mut x224_encoded_response,
        )
        .map_err(|e| RdpError::new(format!("Failed to encode negotiation response: {}", e)))?;

        stream
            .write_all(x224_encoded_response.as_ref())
            .map_err(|e| RdpError::new(format!("Failed to send negotiation response: {}", e)))?;

        Ok(())
    }

    fn read_negotiate_message_and_write_challenge_message<C: sspi::CredentialsProxy>(
        &self,
        tls_stream: &mut native_tls::TlsStream<TcpStream>,
        cred_ssp_context: &mut sspi::CredSspServer<C>,
    ) -> RdpResult<()> {
        let buffer = read_stream_buffer(tls_stream);
        let read_ts_request = sspi::TsRequest::from_buffer(buffer.as_ref())
            .map_err(|e| RdpError::new(format!("Failed to parse ts request with ntlm negotiate message: {}", e)))?;

        process_cred_ssp_phase_with_reply_needed(read_ts_request, cred_ssp_context, tls_stream)
    }

    fn read_authenticate_message_with_pub_key_auth_and_write_pub_key_auth<C: sspi::CredentialsProxy>(
        &self,
        tls_stream: &mut native_tls::TlsStream<TcpStream>,
        cred_ssp_context: &mut sspi::CredSspServer<C>,
    ) -> RdpResult<()> {
        let buffer = read_stream_buffer(tls_stream);
        let read_ts_request = sspi::TsRequest::from_buffer(buffer.as_ref())
            .map_err(|e| RdpError::new(format!("Failed to parse ts request with ntlm negotiate message: {}", e)))?;

        process_cred_ssp_phase_with_reply_needed(read_ts_request, cred_ssp_context, tls_stream)
    }

    fn read_ts_credentials<C: sspi::CredentialsProxy>(
        &self,
        tls_stream: &mut native_tls::TlsStream<TcpStream>,
        cred_ssp_context: &mut sspi::CredSspServer<C>,
    ) -> RdpResult<()> {
        let buffer = read_stream_buffer(tls_stream);
        let read_ts_request = sspi::TsRequest::from_buffer(buffer.as_ref())
            .map_err(|e| RdpError::new(format!("Failed to parse ts request with ntlm negotiate message: {}", e)))?;

        let reply = cred_ssp_context.process(read_ts_request).map_err(|e| {
            RdpError::new(format!(
                "Failed to parse ntlm authenticate message and write pub key auth: {}",
                e
            ))
        })?;
        match reply {
            sspi::CredSspResult::ClientCredentials(client_credentials) => {
                let expected_credentials = &self.identities_proxy.rdp_identity;
                assert_eq!(expected_credentials.username, client_credentials.username);
                assert_eq!(expected_credentials.domain, client_credentials.domain);
                assert_eq!(expected_credentials.password, client_credentials.password);
            }
            _ => panic!("The CredSSP server has returned unexpected result: {:?}", reply),
        };

        Ok(())
    }
}

impl RdpError {
    fn new(error: String) -> Self {
        Self(error)
    }
}
impl std::error::Error for RdpError {}
impl std::fmt::Display for RdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl RdpIdentity {
    fn new(proxy: sspi::Credentials, target: sspi::Credentials, destination: String) -> Self {
        Self {
            proxy,
            target,
            destination,
        }
    }

    fn list_to_buffer(rdp_identities: &[Self], mut file: impl io::Write) -> RdpResult<()> {
        let identities_buffer = serde_json::to_string(&rdp_identities)
            .map_err(|e| RdpError::new(format!("Failed to convert identities to json: {}", e)))?;
        file.write_all(identities_buffer.as_bytes())
            .map_err(|e| RdpError::new(format!("Failed to write identities to file: {}", e)))?;

        Ok(())
    }
}

impl IdentitiesProxy {
    pub fn new(rdp_identity: sspi::Credentials) -> Self {
        Self { rdp_identity }
    }
}

impl sspi::CredentialsProxy for IdentitiesProxy {
    fn password_by_user(&mut self, username: String, domain: Option<String>) -> io::Result<String> {
        assert_eq!(username, self.rdp_identity.username);
        assert_eq!(domain, self.rdp_identity.domain);

        Ok(self.rdp_identity.password.clone())
    }
}

fn process_cred_ssp_phase_with_reply_needed(
    ts_request: sspi::TsRequest,
    cred_ssp_context: &mut impl sspi::CredSsp,
    tls_stream: &mut (impl io::Write + io::Read),
) -> RdpResult<()> {
    let reply = cred_ssp_context
        .process(ts_request)
        .map_err(|e| RdpError::new(format!("Failed to process CredSSP phase: {}", e)))?;
    match reply {
        sspi::CredSspResult::ReplyNeeded(ts_request) => {
            let mut ts_request_buffer = Vec::with_capacity(ts_request.buffer_len() as usize);
            ts_request
                .encode_ts_request(&mut ts_request_buffer)
                .map_err(|e| RdpError::new(format!("Failed to encode ts request: {}", e)))?;

            tls_stream
                .write_all(&ts_request_buffer)
                .map_err(|e| RdpError::new(format!("Failed to send CredSSP message: {}", e)))?;

            Ok(())
        }
        _ => Err(RdpError::new(format!(
            "The CredSSP server has returned unexpected result: {:?}",
            reply
        ))),
    }
}

fn read_stream_buffer(stream: &mut impl io::Read) -> BytesMut {
    let mut buffer = BytesMut::with_capacity(1024);
    buffer.resize(1024, 0u8);
    loop {
        match stream.read(&mut buffer) {
            Ok(n) => {
                buffer.truncate(n);

                return buffer;
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn connect_tcp_stream(addr: &str) -> TcpStream {
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => return stream,
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn accept_tcp_stream(addr: &str) -> RdpResult<TcpStream> {
    let listener_addr = addr
        .parse::<SocketAddr>()
        .map_err(|e| RdpError::new(format!("Failed to parse an addr: {}", e)))?;
    let listener = TcpListener::bind(&listener_addr)
        .map_err(|e| RdpError::new(format!("Failed to exec TcpListener::bind(): {}", e)))?;
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => return Ok(stream),
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn accept_tls<S>(stream: S, cert_pkcs12_der: Vec<u8>, cert_pass: &str) -> RdpResult<native_tls::TlsStream<S>>
where
    S: io::Read + io::Write + std::fmt::Debug + 'static,
{
    let cert = native_tls::Identity::from_pkcs12(cert_pkcs12_der.as_ref(), cert_pass).unwrap();
    let tls_acceptor = native_tls::TlsAcceptor::builder(cert)
        .build()
        .map_err(|e| RdpError::new(format!("Failed to create TlsStreamAcceptor: {}", e)))?;

    tls_acceptor
        .accept(stream)
        .map_err(|e| RdpError::new(format!("Failed to accept the ssl connection: {}", e)))
}

fn connect_tls<S>(
    addr: &str,
    stream: S,
    accept_invalid_certs_and_hostnames: bool,
) -> RdpResult<native_tls::TlsStream<S>>
where
    S: io::Read + io::Write + std::fmt::Debug + 'static,
{
    let tls_connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(accept_invalid_certs_and_hostnames)
        .danger_accept_invalid_hostnames(accept_invalid_certs_and_hostnames)
        .build()
        .map_err(|e| RdpError::new(format!("Failed to create TlsStreamConnector: {}", e)))?;

    tls_connector
        .connect(addr, stream)
        .map_err(|e| RdpError::new(format!("Failed to connect to the ssl connection: {}", e)))
}

pub fn get_tls_pubkey(der: &[u8], pass: &str) -> io::Result<Vec<u8>> {
    let cert = openssl::pkcs12::Pkcs12::from_der(der)?.parse(pass)?.cert;
    get_tls_pubkey_from_cert(cert)
}

pub fn get_tls_peer_pubkey<S>(stream: &native_tls::TlsStream<S>) -> io::Result<Vec<u8>>
where
    S: io::Read + io::Write,
{
    let der = get_der_cert_from_stream(&stream)?;
    let cert = openssl::x509::X509::from_der(&der)?;

    get_tls_pubkey_from_cert(cert)
}

fn get_der_cert_from_stream<S>(stream: &native_tls::TlsStream<S>) -> io::Result<Vec<u8>>
where
    S: io::Read + io::Write,
{
    stream
        .peer_certificate()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to get the peer certificate: {}", e),
            )
        })?
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "A server must provide the certificate"))?
        .to_der()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to convert the peer certificate to der: {}", e),
            )
        })
}

fn get_tls_pubkey_from_cert(cert: openssl::x509::X509) -> io::Result<Vec<u8>> {
    Ok(cert.public_key()?.public_key_to_der()?.split_off(TLS_PUBLIC_KEY_HEADER))
}