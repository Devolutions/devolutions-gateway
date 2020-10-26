mod common;

use std::{
    collections::HashMap,
    fmt, fs,
    io::{self, BufReader, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    process::{Child, Command},
    sync::Arc,
    thread,
    time::Duration,
};

use tokio_rustls::rustls;
use bytes::BytesMut;
use ironrdp::{
    gcc, mcs,
    nego::{Request, Response, ResponseData, ResponseFlags, SecurityProtocol},
    rdp::{
        self, capability_sets,
        server_license::{
            InitialMessageType, InitialServerLicenseMessage, LicenseErrorCode, LicenseHeader, LicensingErrorMessage,
            LicensingStateTransition, PreambleFlags, PreambleType, PreambleVersion, PREAMBLE_SIZE,
        },
        vc,
    },
    ClientConfirmActive, ClientInfoPdu, ConnectInitial, ConnectResponse, Data, McsPdu, PduParsing, SendDataContext,
    ServerDemandActive, ShareControlHeader,
};
use lazy_static::lazy_static;
use serde_derive::{Deserialize, Serialize};
use sspi::internal::credssp;
use x509_parser::{parse_x509_der, pem::pem_to_der};

use common::run_proxy;

lazy_static! {
    static ref PROXY_CREDENTIALS: sspi::AuthIdentity = sspi::AuthIdentity {
        username: String::from("ProxyUserName"),
        password: String::from("ProxyPassword"),
        domain: Some(String::from("ProxyDomainName")),
    };
    static ref SERVER_CREDENTIALS: sspi::AuthIdentity = sspi::AuthIdentity {
        username: String::from("TargetServerUserName"),
        password: String::from("TargetServerPassword"),
        domain: Some(String::from("TargetServerDomainName")),
    };
    static ref CERT_PKCS12_DER: Vec<u8> = include_bytes!("../src/cert/certificate.p12").to_vec();
}

const IRONRDP_CLIENT_PATH: &str = "ironrdp_client";
const JET_PROXY_SERVER_ADDR: &str = "127.0.0.1:8080";
const TARGET_SERVER_ADDR: &str = "127.0.0.1:8081";
const DEVOLUTIONS_IDENTITIES_SERVER_URL: &str = "rdp://127.0.0.1:8082";
const CLIENT_IP_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
const MCS_INITIATOR_ID: u16 = 1001;
const MCS_IO_CHANNEL_ID: u16 = 1003;
const MCS_STATIC_CHANNELS_START_ID: u16 = 1004;
const SHARE_ID: u32 = 66_538;
const SERVER_PDU_SOURCE: u16 = 0x03ea;
const CHANNEL_INITIATOR_ID: u16 = 1002;
const GRAPHICS_DVC_ID: u32 = 0x06;
const DRDYNVC_CHANNEL_NAME: &str = "drdynvc";

const PUBLIC_CERT_PATH: &str = "src/cert/publicCert.pem";
const PRIVATE_CERT_PATH: &str = "src/cert/private.pem";
const GRAPHICS_CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Graphics";

fn run_client() -> Child {
    let mut client_command = Command::new(IRONRDP_CLIENT_PATH);
    client_command
        .arg(JET_PROXY_SERVER_ADDR)
        .args(&["--security_protocol", "hybrid"])
        .args(&["--username", PROXY_CREDENTIALS.username.as_str()])
        .args(&["--password", PROXY_CREDENTIALS.password.as_str()]);

    if let Some(ref domain) = PROXY_CREDENTIALS.domain {
        client_command.args(&["--domain", domain]);
    }

    client_command.spawn().expect("failed to run IronRDP client")
}

// NOTE: The following test is disabled by default as it requires specific environment with
// ironrdp_client executable in PATH variable
#[test]
#[ignore]
fn rdp_with_nla_ntlm() {
    let mut identities_file = tempfile::NamedTempFile::new().expect("failed to create a named temporary file");
    let rdp_identities = vec![RdpIdentity::new(
        PROXY_CREDENTIALS.clone(),
        SERVER_CREDENTIALS.clone(),
        TARGET_SERVER_ADDR.to_string(),
    )];
    RdpIdentity::list_to_buffer(rdp_identities.as_ref(), identities_file.as_file_mut());

    let _proxy = run_proxy(
        JET_PROXY_SERVER_ADDR,
        None,
        Some(DEVOLUTIONS_IDENTITIES_SERVER_URL),
        Some(
            identities_file
                .path()
                .to_str()
                .expect("failed to get path to a temporary file"),
        ),
    );

    let server_thread = thread::spawn(move || {
        let mut server = RdpServer::new(TARGET_SERVER_ADDR, IdentitiesProxy::new(SERVER_CREDENTIALS.clone()));
        server.run();
    });
    let client_thread = thread::spawn(move || loop {
        let mut client = run_client();
        match client.wait().expect("error occurred in IronRDP client").code() {
            Some(exitcode::NOHOST) => thread::sleep(Duration::from_millis(10)),
            Some(exitcode::OK) => break,
            Some(code) => panic!("The client exited with error code: {}", code),
            None => panic!("Client's exit code is none"),
        }
    });

    client_thread.join().expect("failed to join the client thread");
    server_thread.join().expect("failed to join the server thread");
}

struct RdpServer {
    routing_addr: &'static str,
    identities_proxy: IdentitiesProxy,
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).unwrap();
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let rsa_keys = {
        let keyfile = fs::File::open(filename).unwrap();
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader).expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
}

fn get_pub_key_from_pem_file(file: &str) -> io::Result<Vec<u8>> {
    let pem = &fs::read(file)?;
    let der = pem_to_der(pem).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "get_pub_key_from_pem_file: invalid pem certificate.",
        )
    })?;
    let res = parse_x509_der(&der.1.contents[..]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "get_pub_key_from_pem_file: invalid der certificate.",
        )
    })?;
    let public_key = res.1.tbs_certificate.subject_pki.subject_public_key;
    Ok(public_key.data.to_vec())
}

fn get_server_session(cert_path: &str, priv_key_path: &str) -> rustls::ServerSession {
    let certs = load_certs(cert_path);
    let priv_key = load_private_key(priv_key_path);

    let client_no_auth = rustls::NoClientAuth::new();
    let mut server_config = rustls::ServerConfig::new(client_no_auth);
    server_config.set_single_cert(certs, priv_key).unwrap();

    let config_ref = Arc::new(server_config);

    rustls::ServerSession::new(&config_ref)
}

impl RdpServer {
    fn new(routing_addr: &'static str, identities_proxy: IdentitiesProxy) -> Self {
        Self {
            routing_addr,
            identities_proxy,
        }
    }

    fn run(&mut self) {
        let mut stream = accept_tcp_stream(self.routing_addr);
        self.x224(&mut stream);

        let mut tls_session = get_server_session(PUBLIC_CERT_PATH, PRIVATE_CERT_PATH);
        let mut rustls_stream = rustls::Stream::new(&mut tls_session, &mut stream);

        self.nla(&mut rustls_stream);

        let (client_color_depth, channels) = self.mcs(&mut rustls_stream);

        self.read_client_info(&mut rustls_stream);

        self.write_server_license(&mut rustls_stream);

        let client_pdu_source = self.capabilities_exchange(&mut rustls_stream, client_color_depth);

        self.finalization(&mut rustls_stream, client_pdu_source);

        let drdynvc_channel_id = channels.get(DRDYNVC_CHANNEL_NAME).expect("DRDYNVC must be joined");
        self.dvc_messages_exchange(&mut rustls_stream, *drdynvc_channel_id);
        self.write_disconnect_provider_ultimatum(&mut rustls_stream);
    }

    fn x224(&self, mut stream: &mut TcpStream) {
        self.read_negotiation_request(&mut stream);
        self.write_negotiation_response(&mut stream);
    }

    fn nla(&self, mut tls_stream: &mut (impl io::Write + io::Read)) {
        let tls_pubkey = get_pub_key_from_pem_file("src/cert/publicCert.pem").unwrap();

        let mut cred_ssp_context = credssp::CredSspServer::new(tls_pubkey, self.identities_proxy.clone())
            .expect("failed to create a CredSSP server");

        self.read_negotiate_message_and_write_challenge_message(&mut tls_stream, &mut cred_ssp_context);
        self.read_authenticate_message_with_pub_key_auth_and_write_pub_key_auth(&mut tls_stream, &mut cred_ssp_context);
        self.read_ts_credentials(&mut tls_stream, &mut cred_ssp_context);
    }

    fn mcs(&self, mut tls_stream: &mut (impl io::Write + io::Read)) -> (gcc::ClientColorDepth, HashMap<String, u16>) {
        let (channel_names, client_color_depth) = self.read_mcs_connect_initial(&mut tls_stream);
        let channels = self.write_mcs_connect_response(&mut tls_stream, channel_names.as_ref());
        self.read_mcs_erect_domain_request(&mut tls_stream);
        self.read_mcs_attach_user_request(&mut tls_stream);
        self.write_mcs_attach_user_confirm(&mut tls_stream);
        self.process_mcs_channel_joins(&mut tls_stream, channels.values().copied().collect::<Vec<_>>());

        (client_color_depth, channels)
    }

    fn capabilities_exchange(
        &self,
        mut tls_stream: &mut (impl io::Write + io::Read),
        client_color_depth: gcc::ClientColorDepth,
    ) -> u16 {
        self.write_demand_active(&mut tls_stream, client_color_depth);

        self.read_confirm_active(&mut tls_stream)
    }

    fn finalization(&self, mut tls_stream: &mut (impl io::Write + io::Read), client_pdu_source: u16) {
        self.read_synchronize_pdu(&mut tls_stream);
        self.write_synchronize_pdu(&mut tls_stream, client_pdu_source);
        self.read_control_pdu_cooperate(&mut tls_stream);
        self.write_control_pdu_cooperate(&mut tls_stream);
        self.read_request_control_pdu(&mut tls_stream);
        self.write_granted_control_pdu(&mut tls_stream);
        self.read_font_list(&mut tls_stream);
        self.write_font_map(&mut tls_stream);
    }

    fn dvc_messages_exchange(&self, mut tls_stream: &mut (impl io::Write + io::Read), drdynvc_channel_id: u16) {
        thread::sleep(Duration::from_millis(100));
        self.write_dvc_caps_version(&mut tls_stream, drdynvc_channel_id);
        self.read_dvc_caps_version(&mut tls_stream, drdynvc_channel_id);
        self.write_dvc_create_request(&mut tls_stream, drdynvc_channel_id);
        self.read_dvc_create_response(&mut tls_stream, drdynvc_channel_id);
        self.read_gfx_capabilities(&mut tls_stream, drdynvc_channel_id);
    }

    fn read_negotiation_request(&self, stream: &mut TcpStream) {
        let buffer = read_stream_buffer(stream);
        let _request = Request::from_buffer(buffer.as_ref());
    }

    fn write_negotiation_response(&self, stream: &mut TcpStream) {
        let response = Response {
            response: Some(ResponseData::Response {
                flags: ResponseFlags::all(),
                protocol: SecurityProtocol::HYBRID,
            }),
            dst_ref: 0,
            src_ref: 0,
        };

        let mut response_buffer = BytesMut::with_capacity(response.buffer_length());
        response_buffer.resize(response.buffer_length(), 0x00);
        response
            .to_buffer(response_buffer.as_mut())
            .expect("failed to write negotiation response");

        stream
            .write_all(response_buffer.as_ref())
            .expect("failed to send negotiation response");
    }

    fn read_negotiate_message_and_write_challenge_message<C>(
        &self,
        tls_stream: &mut (impl io::Write + io::Read),
        cred_ssp_context: &mut credssp::CredSspServer<C>,
    ) where
        C: credssp::CredentialsProxy<AuthenticationData = sspi::AuthIdentity>,
    {
        let buffer = read_stream_buffer(tls_stream);
        let read_ts_request = credssp::TsRequest::from_buffer(buffer.as_ref())
            .expect("failed to parse TSRequest with NTLM negotiate message");

        process_cred_ssp_phase_with_reply_needed(read_ts_request, cred_ssp_context, tls_stream);
    }

    fn read_authenticate_message_with_pub_key_auth_and_write_pub_key_auth<C>(
        &self,
        tls_stream: &mut (impl io::Write + io::Read),
        cred_ssp_context: &mut credssp::CredSspServer<C>,
    ) where
        C: credssp::CredentialsProxy<AuthenticationData = sspi::AuthIdentity>,
    {
        let buffer = read_stream_buffer(tls_stream);
        let read_ts_request = credssp::TsRequest::from_buffer(buffer.as_ref())
            .expect("failed to parse ts request with NTLM negotiate message");

        process_cred_ssp_phase_with_reply_needed(read_ts_request, cred_ssp_context, tls_stream);
    }

    fn read_ts_credentials<C>(&self, tls_stream: &mut impl io::Read, cred_ssp_context: &mut credssp::CredSspServer<C>)
    where
        C: credssp::CredentialsProxy<AuthenticationData = sspi::AuthIdentity>,
    {
        let buffer = read_stream_buffer(tls_stream);
        let read_ts_request = credssp::TsRequest::from_buffer(buffer.as_ref())
            .expect("failed to parse ts request with ntlm negotiate message");

        let reply = cred_ssp_context.process(read_ts_request);
        match reply {
            Ok(credssp::ServerState::Finished(ref client_credentials)) => {
                let expected_credentials = &self.identities_proxy.rdp_identity;
                assert_eq!(expected_credentials, client_credentials);
            }
            _ => panic!("the CredSSP server has returned unexpected result: {:?}", reply),
        };
    }

    fn read_mcs_connect_initial(
        &self,
        stream: &mut (impl io::Write + io::Read),
    ) -> (Vec<String>, gcc::ClientColorDepth) {
        let mut buffer = read_stream_buffer(stream);
        let connect_initial = read_x224_data_pdu::<ConnectInitial>(&mut buffer);

        // check that jet removed specific fields
        let gcc_blocks = connect_initial.conference_create_request.gcc_blocks;
        assert_eq!(gcc_blocks.core.version, gcc::RdpVersion::V5Plus);
        assert_eq!(
            gcc_blocks.core.optional_data.early_capability_flags,
            Some(gcc::ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL)
        );
        assert_eq!(gcc_blocks.security, gcc::ClientSecurityData::no_security());
        assert!(gcc_blocks.cluster.is_none());
        assert!(gcc_blocks.monitor.is_none());
        assert!(gcc_blocks.monitor_extended.is_none());
        assert!(gcc_blocks.multi_transport_channel.is_none());
        assert!(gcc_blocks.message_channel.is_none());

        let channels = gcc_blocks
            .channel_names()
            .unwrap_or_default()
            .iter()
            .map(|v| v.name.clone())
            .collect();

        (channels, gcc_blocks.core.client_color_depth())
    }

    fn write_mcs_connect_response(
        &self,
        mut tls_stream: &mut (impl io::Write + io::Read),
        channel_names: &[String],
    ) -> HashMap<String, u16> {
        let channel_ids = (MCS_STATIC_CHANNELS_START_ID..MCS_STATIC_CHANNELS_START_ID + channel_names.len() as u16)
            .collect::<Vec<_>>();
        let connection_response = ConnectResponse {
            conference_create_response: gcc::ConferenceCreateResponse {
                user_id: MCS_INITIATOR_ID,
                gcc_blocks: gcc::ServerGccBlocks {
                    core: gcc::ServerCoreData {
                        version: gcc::RdpVersion::V10_1,
                        optional_data: gcc::ServerCoreOptionalData {
                            client_requested_protocols: Some(SecurityProtocol::HYBRID),
                            early_capability_flags: Some(gcc::ServerEarlyCapabilityFlags::all()),
                        },
                    },
                    network: gcc::ServerNetworkData {
                        io_channel: MCS_IO_CHANNEL_ID,
                        channel_ids: channel_ids.clone(),
                    },
                    security: gcc::ServerSecurityData::no_security(),
                    message_channel: None,
                    multi_transport_channel: None,
                },
            },
            called_connect_id: 1,
            domain_parameters: mcs::DomainParameters::target(),
        };
        write_x224_data_pdu(connection_response, &mut tls_stream, None);

        channel_names
            .iter()
            .map(|v| v.to_string())
            .zip(channel_ids)
            .collect::<HashMap<_, _>>()
    }

    fn read_mcs_erect_domain_request(&self, mut tls_stream: &mut (impl io::Write + io::Read)) {
        let mut buffer = read_stream_buffer(&mut tls_stream);
        match read_x224_data_pdu::<McsPdu>(&mut buffer) {
            McsPdu::ErectDomainRequest(_) => (),
            pdu => panic!("Got unexpected MCS PDU: {:?}", pdu),
        };
    }

    fn read_mcs_attach_user_request(&self, mut tls_stream: &mut (impl io::Write + io::Read)) {
        let mut buffer = read_stream_buffer(&mut tls_stream);
        match read_x224_data_pdu::<McsPdu>(&mut buffer) {
            McsPdu::AttachUserRequest => (),
            pdu => panic!("Got unexpected MCS PDU: {:?}", pdu),
        };
    }

    fn write_mcs_attach_user_confirm(&self, mut tls_stream: &mut (impl io::Write + io::Read)) {
        let attach_user_confirm = McsPdu::AttachUserConfirm(mcs::AttachUserConfirmPdu {
            initiator_id: MCS_INITIATOR_ID,
            result: 1,
        });
        write_x224_data_pdu(attach_user_confirm, &mut tls_stream, None);
    }

    fn read_mcs_channel_join_request(&self, tls_stream: &mut (impl io::Write + io::Read)) -> u16 {
        let mut buffer = read_stream_buffer(tls_stream);
        let mcs_pdu = read_x224_data_pdu(&mut buffer);
        match mcs_pdu {
            McsPdu::ChannelJoinRequest(mcs::ChannelJoinRequestPdu {
                initiator_id,
                channel_id,
            }) => {
                assert_eq!(MCS_INITIATOR_ID, initiator_id);

                channel_id
            }
            pdu => panic!("Got unexpected MCS PDU: {:?}", pdu),
        }
    }

    fn write_mcs_channel_join_confirm(&self, channel_id: u16, mut tls_stream: &mut (impl io::Write + io::Read)) {
        let channel_join_confirm = McsPdu::ChannelJoinConfirm(mcs::ChannelJoinConfirmPdu {
            channel_id,
            result: 1,
            initiator_id: MCS_INITIATOR_ID,
            requested_channel_id: channel_id,
        });
        write_x224_data_pdu(channel_join_confirm, &mut tls_stream, None);
    }

    fn process_mcs_channel_joins(&self, mut tls_stream: &mut (impl io::Write + io::Read), gcc_channel_ids: Vec<u16>) {
        let mut ids = gcc_channel_ids;
        ids.extend_from_slice(&[MCS_IO_CHANNEL_ID, MCS_INITIATOR_ID]);

        while !ids.is_empty() {
            let channel_id = self.read_mcs_channel_join_request(tls_stream);
            ids.retain(|&v| v != channel_id);
            self.write_mcs_channel_join_confirm(channel_id, &mut tls_stream);
        }
    }

    fn read_client_info(&self, stream: &mut (impl io::Write + io::Read)) {
        let mut buffer = read_stream_buffer(stream);
        let client_info =
            read_and_parse_send_data_context_pdu::<ClientInfoPdu>(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        let expected_address_family = match CLIENT_IP_ADDR {
            IpAddr::V4(_) => rdp::AddressFamily::INet,
            IpAddr::V6(_) => rdp::AddressFamily::INet6,
        };
        let expected_address = CLIENT_IP_ADDR.to_string();

        assert_eq!(
            client_info.client_info.credentials,
            auth_identity_to_credentials(SERVER_CREDENTIALS.clone())
        );
        assert_eq!(
            client_info.client_info.extra_info.address_family,
            expected_address_family
        );
        assert_eq!(client_info.client_info.extra_info.address, expected_address);
    }

    fn write_server_license(&self, mut tls_stream: &mut (impl io::Write + io::Read)) {
        let valid_client_message = LicensingErrorMessage {
            error_code: LicenseErrorCode::StatusValidClient,
            state_transition: LicensingStateTransition::NoTransition,
            error_info: Vec::new(),
        };

        let pdu = InitialServerLicenseMessage {
            license_header: LicenseHeader {
                security_header: rdp::BasicSecurityHeader {
                    flags: rdp::BasicSecurityHeaderFlags::LICENSE_PKT,
                },
                preamble_message_type: PreambleType::ErrorAlert,
                preamble_flags: PreambleFlags::empty(),
                preamble_version: PreambleVersion::V3,
                preamble_message_size: (PREAMBLE_SIZE + valid_client_message.buffer_length()) as u16,
            },
            message_type: InitialMessageType::StatusValidClient(valid_client_message),
        };

        encode_and_write_send_data_context_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn write_demand_active(
        &self,
        mut tls_stream: &mut (impl io::Write + io::Read),
        client_color_depth: gcc::ClientColorDepth,
    ) {
        let pref_bits_per_pix = match client_color_depth {
            gcc::ClientColorDepth::Bpp4 => 4,
            gcc::ClientColorDepth::Bpp8 => 8,
            gcc::ClientColorDepth::Rgb555Bpp16 | gcc::ClientColorDepth::Rgb565Bpp16 => 16,
            gcc::ClientColorDepth::Bpp24 => 24,
            gcc::ClientColorDepth::Bpp32 => 32,
        };
        let demand_active = ServerDemandActive {
            pdu: rdp::DemandActive {
                source_descriptor: String::from("RDP"),
                capability_sets: vec![
                    rdp::CapabilitySet::General(capability_sets::General {
                        major_platform_type: capability_sets::MajorPlatformType::Unspecified,
                        minor_platform_type: capability_sets::MinorPlatformType::Unspecified,
                        extra_flags: capability_sets::GeneralExtraFlags::all(),
                        refresh_rect_support: true,
                        suppress_output_support: true,
                    }),
                    rdp::CapabilitySet::Bitmap(capability_sets::Bitmap {
                        pref_bits_per_pix,
                        desktop_width: 1920,
                        desktop_height: 1080,
                        desktop_resize_flag: true,
                        drawing_flags: capability_sets::BitmapDrawingFlags::all(),
                    }),
                    rdp::CapabilitySet::Order(capability_sets::Order::new(
                        capability_sets::OrderFlags::all(),
                        capability_sets::OrderSupportExFlags::all(),
                        480 * 480,
                        0,
                    )),
                    rdp::CapabilitySet::Pointer(capability_sets::Pointer {
                        color_pointer_cache_size: 25,
                        pointer_cache_size: 25,
                    }),
                    rdp::CapabilitySet::Input(capability_sets::Input {
                        input_flags: capability_sets::InputFlags::all(),
                        keyboard_layout: 0,
                        keyboard_type: None,
                        keyboard_subtype: 0,
                        keyboard_function_key: 0,
                        keyboard_ime_filename: String::new(),
                    }),
                    rdp::CapabilitySet::VirtualChannel(capability_sets::VirtualChannel {
                        flags: capability_sets::VirtualChannelFlags::COMPRESSION_CLIENT_TO_SERVER_8K,
                        chunk_size: Some(16256),
                    }),
                ],
            },
        };
        let pdu = rdp::ShareControlPdu::ServerDemandActive(demand_active);
        let header = rdp::ShareControlHeader {
            share_control_pdu: pdu,
            pdu_source: SERVER_PDU_SOURCE,
            share_id: SHARE_ID,
        };
        encode_and_write_send_data_context_pdu(header, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn read_confirm_active(&self, tls_stream: &mut (impl io::Write + io::Read)) -> u16 {
        let mut buffer = read_stream_buffer(tls_stream);
        let mut share_control_header = read_and_parse_send_data_context_pdu::<rdp::ShareControlHeader>(
            &mut buffer,
            MCS_INITIATOR_ID,
            MCS_IO_CHANNEL_ID,
        );
        if share_control_header.share_id != SHARE_ID {
            panic!(
                "Unexpected Client Confirm Active Share Control Header PDU share ID: {} != {}",
                SHARE_ID, share_control_header.share_id
            );
        }

        if let rdp::ShareControlPdu::ClientConfirmActive(ClientConfirmActive { ref mut pdu, .. }) =
            share_control_header.share_control_pdu
        {
            let size = pdu.capability_sets.len();
            pdu.capability_sets.retain(|capability_set| {
                !matches!(capability_set,
                    rdp::CapabilitySet::BitmapCacheHostSupport(_)
                    | rdp::CapabilitySet::Control(_)
                    | rdp::CapabilitySet::WindowActivation(_)
                    | rdp::CapabilitySet::Share(_)
                    | rdp::CapabilitySet::Font(_)
                    | rdp::CapabilitySet::LargePointer(_)
                    | rdp::CapabilitySet::DesktopComposition(_)
                )
            });
            if size != pdu.capability_sets.len() {
                panic!("The Jet did not filter qualitatively capability sets");
            }

            share_control_header.pdu_source
        } else {
            panic!(
                "Got unexpected Share Control PDU while was expected Client Confirm Active PDU: {:?}",
                share_control_header.share_control_pdu
            );
        }
    }

    fn read_synchronize_pdu(&self, tls_stream: &mut (impl io::Write + io::Read)) {
        let mut buffer = read_stream_buffer(tls_stream);
        let share_data_pdu = read_and_parse_finalization_pdu(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        if let rdp::ShareDataPdu::Synchronize(rdp::SynchronizePdu { target_user_id }) = share_data_pdu {
            if target_user_id != MCS_INITIATOR_ID {
                panic!(
                    "Got unexpected target user ID in Synchronize PDU: {} != {}",
                    MCS_INITIATOR_ID, target_user_id
                );
            }
        } else {
            panic!(
                "Unexpected Finalization PDU while was expected Synchronize PDU: {:?}",
                share_data_pdu
            );
        }
    }

    fn write_synchronize_pdu(&self, mut tls_stream: &mut (impl io::Write + io::Read), client_pdu_source: u16) {
        let pdu = rdp::ShareDataPdu::Synchronize(rdp::SynchronizePdu {
            target_user_id: client_pdu_source,
        });
        encode_and_write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn read_control_pdu_cooperate(&self, tls_stream: &mut (impl io::Write + io::Read)) {
        let mut buffer = read_stream_buffer(tls_stream);
        let share_data_pdu = read_and_parse_finalization_pdu(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        if let rdp::ShareDataPdu::Control(rdp::ControlPdu {
            action,
            grant_id,
            control_id,
        }) = share_data_pdu
        {
            if action != rdp::ControlAction::Cooperate {
                panic!("Expected Control Cooperate PDU, got Control {:?} PDU", action);
            }
            if grant_id != 0 || control_id != 0 {
                panic!(
                    "Control Cooperate PDU grant ID and control ID must be set to zero: {} != 0 or {} != 0",
                    grant_id, control_id
                );
            }
        } else {
            panic!(
                "Unexpected Finalization PDU while was expected Control PDU - Cooperate: {:?}",
                share_data_pdu
            );
        }
    }

    fn write_control_pdu_cooperate(&self, mut tls_stream: &mut (impl io::Write + io::Read)) {
        let pdu = rdp::ShareDataPdu::Control(rdp::ControlPdu {
            action: rdp::ControlAction::Cooperate,
            grant_id: 0,
            control_id: 0,
        });
        encode_and_write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn read_request_control_pdu(&self, tls_stream: &mut (impl io::Write + io::Read)) {
        let mut buffer = read_stream_buffer(tls_stream);
        let share_data_pdu = read_and_parse_finalization_pdu(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        if let rdp::ShareDataPdu::Control(rdp::ControlPdu {
            action,
            grant_id,
            control_id,
        }) = share_data_pdu
        {
            if action != rdp::ControlAction::RequestControl {
                panic!("Expected Control Request Control PDU, got Control {:?} PDU", action);
            }
            if grant_id != 0 || control_id != 0 {
                panic!(
                    "Control Request Control PDU grant ID and control ID must be set to zero: {} != 0 or {} != 0",
                    grant_id, control_id
                );
            }
        } else {
            panic!(
                "Unexpected Finalization PDU while was expected Control PDU - Request Control: {:?}",
                share_data_pdu
            );
        }
    }

    fn write_granted_control_pdu(&self, mut tls_stream: &mut (impl io::Write + io::Read)) {
        let pdu = rdp::ShareDataPdu::Control(rdp::ControlPdu {
            action: rdp::ControlAction::GrantedControl,
            grant_id: MCS_INITIATOR_ID,
            control_id: u32::from(SERVER_PDU_SOURCE),
        });
        encode_and_write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn read_font_list(&self, tls_stream: &mut (impl io::Write + io::Read)) {
        let mut buffer = read_stream_buffer(tls_stream);
        let share_data_pdu = read_and_parse_finalization_pdu(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        match share_data_pdu {
            rdp::ShareDataPdu::FontList(_) => (),
            _ => panic!(
                "Unexpected Finalization PDU while was expected Font List PDU: {:?}",
                share_data_pdu
            ),
        }
    }

    fn write_font_map(&self, mut tls_stream: &mut (impl io::Write + io::Read)) {
        let pdu = rdp::ShareDataPdu::FontMap(rdp::FontPdu {
            number: 0,
            total_number: 0,
            flags: rdp::SequenceFlags::FIRST | rdp::SequenceFlags::LAST,
            entry_size: 4,
        });
        encode_and_write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn write_dvc_caps_version(&self, mut tls_stream: &mut (impl io::Write + io::Read), drdynvc_channel_id: u16) {
        let caps_request_pdu = vc::dvc::ServerPdu::CapabilitiesRequest(vc::dvc::CapabilitiesRequestPdu::V1);
        let mut caps_request_buffer = Vec::with_capacity(caps_request_pdu.buffer_length());
        caps_request_pdu
            .to_buffer(&mut caps_request_buffer)
            .expect("failed to write dvc caps request");

        write_dvc_pdu(caps_request_buffer, &mut tls_stream, drdynvc_channel_id);
    }

    fn read_dvc_caps_version(&self, mut tls_stream: &mut (impl io::Write + io::Read), drdynvc_channel_id: u16) {
        let check_caps_response = |channel_data_buffer: BytesMut| {
            match vc::dvc::ClientPdu::from_buffer(channel_data_buffer.as_ref(), channel_data_buffer.len()) {
                Ok(vc::dvc::ClientPdu::CapabilitiesResponse(caps_response)) => {
                    assert_eq!(vc::dvc::CapsVersion::V1, caps_response.version);
                }
                Ok(pdu) => panic!("Got unexpected DVC client PDU: {:?}", pdu),
                Err(err) => panic!("failed to read dvc caps response: {:?}", err),
            };
        };

        read_dvc_pdu(check_caps_response, &mut tls_stream, drdynvc_channel_id);
    }

    fn write_dvc_create_request(&self, mut tls_stream: &mut (impl io::Write + io::Read), drdynvc_channel_id: u16) {
        let create_request_pdu = vc::dvc::ServerPdu::CreateRequest(vc::dvc::CreateRequestPdu {
            channel_id_type: vc::dvc::FieldType::U8,
            channel_id: GRAPHICS_DVC_ID,
            channel_name: GRAPHICS_CHANNEL_NAME.to_string(),
        });

        let mut create_request_buffer = Vec::with_capacity(create_request_pdu.buffer_length());
        create_request_pdu
            .to_buffer(&mut create_request_buffer)
            .expect("failed to write dvc create request");

        write_dvc_pdu(create_request_buffer, &mut tls_stream, drdynvc_channel_id);
    }

    fn read_dvc_create_response(&self, mut tls_stream: &mut (impl io::Write + io::Read), drdynvc_channel_id: u16) {
        let check_create_response = |channel_data_buffer: BytesMut| {
            match vc::dvc::ClientPdu::from_buffer(channel_data_buffer.as_ref(), channel_data_buffer.len()) {
                Ok(vc::dvc::ClientPdu::CreateResponse(create_response)) => {
                    assert_eq!(GRAPHICS_DVC_ID, create_response.channel_id);
                    assert_eq!(vc::dvc::DVC_CREATION_STATUS_OK, create_response.creation_status);
                }
                Ok(pdu) => panic!("Got unexpected DVC client PDU: {:?}", pdu),
                Err(err) => panic!("failed to read dvc caps response: {:?}", err),
            };
        };

        read_dvc_pdu(check_create_response, &mut tls_stream, drdynvc_channel_id);
    }

    fn read_gfx_capabilities(&self, mut tls_stream: &mut (impl io::Write + io::Read), drdynvc_channel_id: u16) {
        let check_create_response = |mut channel_data_buffer: BytesMut| {
            let client_pdu = vc::dvc::ClientPdu::from_buffer(channel_data_buffer.as_ref(), channel_data_buffer.len());
            match &client_pdu {
                Ok(vc::dvc::ClientPdu::Data(data)) => {
                    assert_eq!(GRAPHICS_DVC_ID, data.channel_id);
                    channel_data_buffer.split_to(client_pdu.as_ref().unwrap().buffer_length());
                    if let vc::dvc::gfx::ClientPdu::CapabilitiesAdvertise(caps) =
                        vc::dvc::gfx::ClientPdu::from_buffer(channel_data_buffer.as_ref()).unwrap()
                    {
                        assert_eq!(
                            caps,
                            vc::dvc::gfx::CapabilitiesAdvertisePdu(vec![vc::dvc::gfx::CapabilitySet::V8 {
                                flags: vc::dvc::gfx::CapabilitiesV8Flags::empty()
                            }])
                        );
                    }
                }
                Ok(pdu) => panic!("Got unexpected DVC client PDU: {:?}", pdu),
                Err(err) => panic!("failed to read dvc caps response: {:?}", err),
            };
        };

        read_dvc_pdu(check_create_response, &mut tls_stream, drdynvc_channel_id);
    }

    //    fn write_gfx_capabilities(&self, mut tls_stream: &mut (impl io::Write + io::Read), drdynvc_channel_id: u16) {
    //        let gfx_capabilities = vc::dvc::gfx::ServerPdu::CapabilitiesConfirm()
    //
    //        let data_pdu = vc::dvc::ServerPdu::Data(vc::dvc::DataPdu {
    //            channel_id_type: vc::dvc::FieldType::U8,
    //            channel_id: GRAPHICS_DVC_ID,
    //            data_size: 0,
    //        });
    //
    //        let mut create_request_buffer = Vec::with_capacity(create_request_pdu.buffer_length());
    //        create_request_pdu
    //            .to_buffer(&mut create_request_buffer)
    //            .expect("failed to write dvc create request");
    //
    //        write_dvc_pdu(create_request_buffer, &mut tls_stream, drdynvc_channel_id);
    //    }

    fn write_disconnect_provider_ultimatum(&self, mut tls_stream: &mut (impl io::Write + io::Read)) {
        write_x224_data_pdu(
            McsPdu::DisconnectProviderUltimatum(mcs::DisconnectUltimatumReason::UserRequested),
            &mut tls_stream,
            None,
        );
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RdpIdentity {
    pub proxy: sspi::AuthIdentity,
    pub target: sspi::AuthIdentity,
    pub destination: String,
}

impl RdpIdentity {
    fn new(proxy: sspi::AuthIdentity, target: sspi::AuthIdentity, destination: String) -> Self {
        Self {
            proxy,
            target,
            destination,
        }
    }

    fn list_to_buffer(rdp_identities: &[Self], mut file: impl io::Write) {
        let identities_buffer = serde_json::to_string(&rdp_identities).expect("failed to convert identities to json");
        file.write_all(identities_buffer.as_bytes())
            .expect("failed to write identities to file");
    }
}

#[derive(Clone)]
pub struct IdentitiesProxy {
    rdp_identity: sspi::AuthIdentity,
}

impl IdentitiesProxy {
    pub fn new(rdp_identity: sspi::AuthIdentity) -> Self {
        Self { rdp_identity }
    }
}

impl credssp::CredentialsProxy for IdentitiesProxy {
    type AuthenticationData = sspi::AuthIdentity;

    fn auth_data_by_user(&mut self, username: String, domain: Option<String>) -> io::Result<Self::AuthenticationData> {
        assert_eq!(username, self.rdp_identity.username);
        assert_eq!(domain, self.rdp_identity.domain);

        Ok(self.rdp_identity.clone())
    }
}

fn process_cred_ssp_phase_with_reply_needed<C>(
    ts_request: credssp::TsRequest,
    cred_ssp_context: &mut credssp::CredSspServer<C>,
    tls_stream: &mut (impl io::Write + io::Read),
) where
    C: credssp::CredentialsProxy<AuthenticationData = sspi::AuthIdentity>,
{
    let reply = cred_ssp_context.process(ts_request);
    match reply {
        Ok(credssp::ServerState::ReplyNeeded(ts_request)) => {
            let mut ts_request_buffer = Vec::with_capacity(ts_request.buffer_len() as usize);
            ts_request
                .encode_ts_request(&mut ts_request_buffer)
                .expect("failed to encode TSRequest");

            tls_stream
                .write_all(&ts_request_buffer)
                .expect("failed to send CredSSP message");
        }
        _ => panic!("the CredSSP server has returned unexpected result: {:?}", reply),
    }
}

fn read_x224_data_pdu<T>(buffer: &mut BytesMut) -> T
where
    T: PduParsing,
    T::Error: fmt::Debug,
{
    let data_pdu = Data::from_buffer(buffer.as_ref()).expect("failed to read X224 Data");
    buffer.split_to(data_pdu.buffer_length() - data_pdu.data_length);
    let pdu = T::from_buffer(&buffer[..data_pdu.data_length]).expect("failed to decode X224 Data");
    buffer.split_to(pdu.buffer_length());

    pdu
}

fn write_x224_data_pdu<T>(pdu: T, mut stream: impl io::Write, extra_data: Option<&[u8]>)
where
    T: PduParsing,
    T::Error: fmt::Debug,
{
    let data_length = pdu.buffer_length() + extra_data.map(|v| v.len()).unwrap_or(0);

    Data::new(data_length)
        .to_buffer(&mut stream)
        .expect("failed to write X224 Data");
    pdu.to_buffer(&mut stream).expect("failed to encode X224 Data");
    if let Some(extra_data) = extra_data {
        stream
            .write_all(extra_data)
            .expect("failed to write extra data for X224 Data");
    }
}

fn read_and_parse_send_data_context_pdu<T>(
    mut buffer: &mut BytesMut,
    expected_initiator_id: u16,
    expected_channel_id: u16,
) -> T
where
    T: PduParsing,
    T::Error: fmt::Debug,
{
    match read_x224_data_pdu::<McsPdu>(&mut buffer) {
        mcs::McsPdu::SendDataRequest(send_data_context) => {
            if send_data_context.initiator_id != expected_initiator_id {
                panic!(
                    "Unexpected Send Data Context PDU initiator ID: {} != {}",
                    expected_initiator_id, send_data_context.initiator_id
                );
            }
            if send_data_context.channel_id != expected_channel_id {
                panic!(
                    "Unexpected Send Data Context PDU channel ID: {} != {}",
                    expected_channel_id, send_data_context.channel_id
                );
            }

            let pdu = T::from_buffer(&buffer[..send_data_context.pdu_length])
                .expect("failed to decode Send Data Context PDU");
            buffer.split_to(pdu.buffer_length());

            pdu
        }
        pdu => panic!(
            "Got unexpected MCS PDU, while was expected Channel Join Confirm PDU: {:?}",
            pdu
        ),
    }
}

fn encode_and_write_send_data_context_pdu<T>(pdu: T, initiator_id: u16, channel_id: u16, mut stream: impl io::Write)
where
    T: PduParsing,
    T::Error: fmt::Debug,
{
    let mut pdu_buffer = Vec::with_capacity(pdu.buffer_length());
    pdu.to_buffer(&mut pdu_buffer)
        .expect("failed to encode Send Data Context PDU");

    let send_data_context_pdu = SendDataContext {
        initiator_id,
        channel_id,
        pdu_length: pdu_buffer.len(),
    };

    write_x224_data_pdu(
        McsPdu::SendDataIndication(send_data_context_pdu),
        &mut stream,
        Some(pdu_buffer.as_slice()),
    );
}

fn read_and_parse_finalization_pdu(
    mut buffer: &mut BytesMut,
    expected_initiator_id: u16,
    expected_channel_id: u16,
) -> rdp::ShareDataPdu {
    let share_control_header = read_and_parse_send_data_context_pdu::<ShareControlHeader>(
        &mut buffer,
        expected_initiator_id,
        expected_channel_id,
    );
    if share_control_header.share_id != SHARE_ID {
        panic!(
            "Got unexpected Share ID for Finalization PDU: {} != {}",
            SHARE_ID, share_control_header.share_id
        );
    }

    if let rdp::ShareControlPdu::Data(rdp::ShareDataHeader {
        share_data_pdu,
        compression_flags,
        ..
    }) = share_control_header.share_control_pdu
    {
        if compression_flags != rdp::CompressionFlags::empty() {
            panic!(
                "Unexpected Compression Flags in Share Data Header PDU for Finalization PDU: {:?}",
                compression_flags
            );
        }

        share_data_pdu
    } else {
        panic!(
            "Got unexpected Share Control PDU while was expected Data with Finalization PDU: {:?}",
            share_control_header.share_control_pdu
        );
    }
}

fn encode_and_write_finalization_pdu(
    pdu: rdp::ShareDataPdu,
    initiator_id: u16,
    channel_id: u16,
    mut stream: impl io::Write,
) {
    let share_data_header = rdp::ShareDataHeader {
        share_data_pdu: pdu,
        stream_priority: rdp::StreamPriority::Medium,
        compression_flags: rdp::CompressionFlags::empty(),
        compression_type: rdp::CompressionType::K8,
    };

    let share_control_header = rdp::ShareControlHeader {
        share_control_pdu: rdp::ShareControlPdu::Data(share_data_header),
        pdu_source: SERVER_PDU_SOURCE,
        share_id: SHARE_ID,
    };
    encode_and_write_send_data_context_pdu(share_control_header, initiator_id, channel_id, &mut stream);
}

fn read_stream_buffer(tls_stream: &mut impl io::Read) -> BytesMut {
    let mut buffer = BytesMut::with_capacity(1024);
    buffer.resize(1024, 0u8);
    loop {
        match tls_stream.read(&mut buffer) {
            Ok(n) => {
                buffer.truncate(n);

                return buffer;
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn accept_tcp_stream(addr: &str) -> TcpStream {
    let listener_addr = addr.parse::<SocketAddr>().expect("failed to parse an addr");
    let listener = TcpListener::bind(&listener_addr).expect("failed to bind to stream");
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => return stream,
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn auth_identity_to_credentials(auth_identity: sspi::AuthIdentity) -> ironrdp::rdp::Credentials {
    ironrdp::rdp::Credentials {
        username: auth_identity.username,
        password: auth_identity.password,
        domain: auth_identity.domain,
    }
}

fn write_dvc_pdu(mut pdu: Vec<u8>, mut tls_stream: &mut (impl io::Write + io::Read), drdynvc_channel_id: u16) {
    let channel_header = vc::ChannelPduHeader {
        total_length: pdu.len() as u32,
        flags: vc::ChannelControlFlags::FLAG_FIRST | vc::ChannelControlFlags::FLAG_LAST,
    };

    let mut channel_buffer = Vec::with_capacity(channel_header.buffer_length() + pdu.len());
    channel_header
        .to_buffer(&mut channel_buffer)
        .expect("failed to write channel header");

    channel_buffer.append(&mut pdu);

    let send_data_context_pdu = SendDataContext {
        initiator_id: CHANNEL_INITIATOR_ID,
        channel_id: drdynvc_channel_id,
        pdu_length: channel_buffer.len(),
    };

    write_x224_data_pdu(
        McsPdu::SendDataIndication(send_data_context_pdu),
        &mut tls_stream,
        Some(channel_buffer.as_slice()),
    );
}

fn read_dvc_pdu(
    check_dvc: impl Fn(BytesMut),
    mut tls_stream: &mut (impl io::Write + io::Read),
    drdynvc_channel_id: u16,
) {
    let mut buffer = read_stream_buffer(&mut tls_stream);
    match read_x224_data_pdu::<McsPdu>(&mut buffer) {
        McsPdu::SendDataRequest(data_context) => {
            assert_eq!(CHANNEL_INITIATOR_ID, data_context.initiator_id);
            assert_eq!(drdynvc_channel_id, data_context.channel_id);

            let channel_header =
                vc::ChannelPduHeader::from_buffer(buffer.as_ref()).expect("failed to read channel header");
            buffer.split_to(channel_header.buffer_length());

            assert_eq!(channel_header.total_length, buffer.len() as u32);
            assert!(channel_header
                .flags
                .contains(vc::ChannelControlFlags::FLAG_FIRST | vc::ChannelControlFlags::FLAG_LAST));

            check_dvc(buffer);
        }
        pdu => panic!("Got unexpected MCS PDU: {:?}", pdu),
    };
}
