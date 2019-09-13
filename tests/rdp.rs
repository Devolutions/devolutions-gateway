mod common;

use std::{
    fmt,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    process::{Child, Command},
    thread,
    time::Duration,
};

use bytes::BytesMut;
use ironrdp::{
    gcc, mcs,
    nego::{Request, Response, ResponseData, ResponseFlags, SecurityProtocol},
    rdp::{self, capability_sets},
    ClientConfirmActive, ClientInfoPdu, ConnectInitial, ConnectResponse, Data, McsPdu, PduParsing, SendDataContext,
    ServerDemandActive, ServerLicensePdu, ShareControlHeader,
};
use lazy_static::lazy_static;
use native_tls::{TlsAcceptor, TlsStream};
use serde_derive::{Deserialize, Serialize};
use sspi::CredSsp;

use common::run_proxy;

lazy_static! {
    static ref PROXY_CREDENTIALS: sspi::Credentials = sspi::Credentials::new(
        String::from("ProxyUserName"),
        String::from("ProxyPassword"),
        Some(String::from("ProxyDomainName")),
    );
    static ref SERVER_CREDENTIALS: sspi::Credentials = sspi::Credentials::new(
        String::from("TargetServerUserName"),
        String::from("TargetServerPassword"),
        Some(String::from("TargetServerDomainName")),
    );
    static ref CERT_PKCS12_DER: Vec<u8> = include_bytes!("../src/cert/certificate.p12").to_vec();
}

const IRONRDP_CLIENT_PATH: &str = "ironrdp_client";
const TLS_PUBLIC_KEY_HEADER: usize = 24;
const JET_PROXY_SERVER_ADDR: &str = "127.0.0.1:8080";
const TARGET_SERVER_ADDR: &str = "127.0.0.1:8081";
const DEVOLUTIONS_IDENTITIES_SERVER_URL: &str = "rdp://127.0.0.1:8082";
const CLIENT_IP_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
const CERT_PKCS12_PASS: &str = "password";
const MCS_INITIATOR_ID: u16 = 1001;
const MCS_IO_CHANNEL_ID: u16 = 1003;
const MCS_STATIC_CHANNELS_START_ID: u16 = 1004;
const SHARE_ID: u32 = 66_538;
const SERVER_PDU_SOURCE: u16 = 0x03ea;

fn run_client() -> Child {
    let mut client_command = Command::new(IRONRDP_CLIENT_PATH);
    client_command
        .arg(JET_PROXY_SERVER_ADDR)
        .args(&["--security_protocol", "hybrid"])
        .args(&["--username", PROXY_CREDENTIALS.username.as_str()])
        .args(&["--password", PROXY_CREDENTIALS.password.as_str()]);

    client_command.spawn().expect("failed to run IronRDP client")
}

#[test]
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
    thread::sleep(Duration::from_millis(500));

    let server_thread = thread::spawn(move || {
        let mut server = RdpServer::new(TARGET_SERVER_ADDR, IdentitiesProxy::new(SERVER_CREDENTIALS.clone()));
        server.run();
    });
    let client_thread = thread::spawn(move || {
        let mut client = run_client();
        client.wait().expect("error occurred in IronRDP client");
    });

    client_thread.join().expect("failed to join the client thread");
    server_thread.join().expect("failed to join the server thread");
}

struct RdpServer {
    routing_addr: &'static str,
    identities_proxy: IdentitiesProxy,
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

        let mut tls_stream = accept_tls(stream, CERT_PKCS12_DER.clone(), CERT_PKCS12_PASS);
        self.nla(&mut tls_stream);

        let client_color_depth = self.mcs(&mut tls_stream);

        self.read_client_info(&mut tls_stream);

        self.write_server_license(&mut tls_stream);

        let client_pdu_source = self.capabilities_exchange(&mut tls_stream, client_color_depth);

        self.finalization(&mut tls_stream, client_pdu_source);
    }

    fn x224(&self, mut stream: &mut TcpStream) {
        self.read_negotiation_request(&mut stream);
        self.write_negotiation_response(&mut stream);
    }

    fn nla(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let tls_pubkey = get_tls_pubkey(CERT_PKCS12_DER.clone().as_ref(), CERT_PKCS12_PASS);

        let mut cred_ssp_context = sspi::CredSspServer::with_default_version(tls_pubkey, self.identities_proxy.clone())
            .expect("failed to create a CredSSP server");

        self.read_negotiate_message_and_write_challenge_message(&mut tls_stream, &mut cred_ssp_context);
        self.read_authenticate_message_with_pub_key_auth_and_write_pub_key_auth(&mut tls_stream, &mut cred_ssp_context);
        self.read_ts_credentials(&mut tls_stream, &mut cred_ssp_context);
    }

    fn mcs(&self, mut tls_stream: &mut TlsStream<TcpStream>) -> gcc::ClientColorDepth {
        let (channel_names, client_color_depth) = self.read_mcs_connect_initial(&mut tls_stream);
        let channel_ids = self.write_mcs_connect_response(&mut tls_stream, channel_names.as_ref());
        self.read_mcs_erect_domain_request(&mut tls_stream);
        self.read_mcs_attach_user_request(&mut tls_stream);
        self.write_mcs_attach_user_confirm(&mut tls_stream);
        self.process_mcs_channel_joins(&mut tls_stream, channel_ids);

        client_color_depth
    }

    fn capabilities_exchange(
        &self,
        mut tls_stream: &mut TlsStream<TcpStream>,
        client_color_depth: gcc::ClientColorDepth,
    ) -> u16 {
        self.write_demand_active(&mut tls_stream, client_color_depth);

        self.read_confirm_active(&mut tls_stream)
    }

    fn finalization(&self, mut tls_stream: &mut TlsStream<TcpStream>, client_pdu_source: u16) {
        self.read_synchronize_pdu(&mut tls_stream);
        self.write_synchronize_pdu(&mut tls_stream, client_pdu_source);
        self.read_control_pdu_cooperate(&mut tls_stream);
        self.write_control_pdu_cooperate(&mut tls_stream);
        self.read_request_control_pdu(&mut tls_stream);
        self.write_granted_control_pdu(&mut tls_stream);
        self.read_font_list(&mut tls_stream);
        self.write_font_map(&mut tls_stream);
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

    fn read_negotiate_message_and_write_challenge_message<C: sspi::CredentialsProxy>(
        &self,
        tls_stream: &mut TlsStream<TcpStream>,
        cred_ssp_context: &mut sspi::CredSspServer<C>,
    ) {
        let buffer = read_stream_buffer(tls_stream);
        let read_ts_request = sspi::TsRequest::from_buffer(buffer.as_ref())
            .expect("failed to parse TSRequest with NTLM negotiate message");

        process_cred_ssp_phase_with_reply_needed(read_ts_request, cred_ssp_context, tls_stream);
    }

    fn read_authenticate_message_with_pub_key_auth_and_write_pub_key_auth<C: sspi::CredentialsProxy>(
        &self,
        tls_stream: &mut TlsStream<TcpStream>,
        cred_ssp_context: &mut sspi::CredSspServer<C>,
    ) {
        let buffer = read_stream_buffer(tls_stream);
        let read_ts_request = sspi::TsRequest::from_buffer(buffer.as_ref())
            .expect("failed to parse ts request with NTLM negotiate message");

        process_cred_ssp_phase_with_reply_needed(read_ts_request, cred_ssp_context, tls_stream);
    }

    fn read_ts_credentials<C: sspi::CredentialsProxy>(
        &self,
        tls_stream: &mut TlsStream<TcpStream>,
        cred_ssp_context: &mut sspi::CredSspServer<C>,
    ) {
        let buffer = read_stream_buffer(tls_stream);
        let read_ts_request = sspi::TsRequest::from_buffer(buffer.as_ref())
            .expect("failed to parse ts request with ntlm negotiate message");

        let reply = cred_ssp_context
            .process(read_ts_request)
            .expect("failed to parse NTLM authenticate message and write pub key auth");
        match reply {
            sspi::CredSspResult::ClientCredentials(ref client_credentials) => {
                let expected_credentials = &self.identities_proxy.rdp_identity;
                assert_eq!(expected_credentials, client_credentials);
            }
            _ => panic!("the CredSSP server has returned unexpected result: {:?}", reply),
        };
    }

    fn read_mcs_connect_initial(&self, stream: &mut TlsStream<TcpStream>) -> (Vec<String>, gcc::ClientColorDepth) {
        let mut buffer = read_stream_buffer(stream);
        let connect_initial = read_x224_data_pdu::<ConnectInitial>(&mut buffer);

        // check that jet removed specific fields
        let gcc_blocks = connect_initial.conference_create_request.gcc_blocks;
        assert_eq!(gcc_blocks.core.version, gcc::RdpVersion::V5Plus);
        assert_eq!(
            gcc_blocks.core.optional_data.early_capability_flags,
            Some(gcc::ClientEarlyCapabilityFlags::empty())
        );
        assert_eq!(gcc_blocks.security, gcc::ClientSecurityData::no_security());
        assert!(gcc_blocks.cluster.is_none());
        assert!(gcc_blocks.monitor.is_none());
        assert!(gcc_blocks.monitor_extended.is_none());
        assert!(gcc_blocks.multi_transport_channel.is_none());
        assert!(gcc_blocks.message_channel.is_none());

        let channels = gcc_blocks.channel_names().iter().map(|v| v.name.clone()).collect();

        (channels, gcc_blocks.core.client_color_depth())
    }

    fn write_mcs_connect_response(
        &self,
        mut tls_stream: &mut TlsStream<TcpStream>,
        channel_names: &[String],
    ) -> Vec<u16> {
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
        write_x224_data_pdu(connection_response, &mut tls_stream);

        channel_ids
    }

    fn read_mcs_erect_domain_request(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(&mut tls_stream);
        match read_x224_data_pdu::<McsPdu>(&mut buffer) {
            McsPdu::ErectDomainRequest(_) => (),
            pdu => panic!("Got unexpected MCS PDU: {:?}", pdu),
        };
    }

    fn read_mcs_attach_user_request(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(&mut tls_stream);
        match read_x224_data_pdu::<McsPdu>(&mut buffer) {
            McsPdu::AttachUserRequest => (),
            pdu => panic!("Got unexpected MCS PDU: {:?}", pdu),
        };
    }

    fn write_mcs_attach_user_confirm(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let attach_user_confirm = McsPdu::AttachUserConfirm(mcs::AttachUserConfirmPdu {
            initiator_id: MCS_INITIATOR_ID,
            result: 1,
        });
        write_x224_data_pdu(attach_user_confirm, &mut tls_stream);
    }

    fn read_mcs_channel_join_request(&self, stream: &mut TlsStream<TcpStream>) -> u16 {
        let mut buffer = read_stream_buffer(stream);
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

    fn write_mcs_channel_join_confirm(&self, channel_id: u16, mut tls_stream: &mut TlsStream<TcpStream>) {
        let channel_join_confirm = McsPdu::ChannelJoinConfirm(mcs::ChannelJoinConfirmPdu {
            channel_id,
            result: 1,
            initiator_id: MCS_INITIATOR_ID,
            requested_channel_id: channel_id,
        });
        write_x224_data_pdu(channel_join_confirm, &mut tls_stream);
    }

    fn process_mcs_channel_joins(&self, mut tls_stream: &mut TlsStream<TcpStream>, gcc_channel_ids: Vec<u16>) {
        let mut ids = gcc_channel_ids;
        ids.extend_from_slice(&[MCS_IO_CHANNEL_ID, MCS_INITIATOR_ID]);

        while !ids.is_empty() {
            let channel_id = self.read_mcs_channel_join_request(tls_stream);
            ids.retain(|&v| v != channel_id);
            self.write_mcs_channel_join_confirm(channel_id, &mut tls_stream);
        }
    }

    fn read_client_info(&self, stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(stream);
        let client_info =
            read_and_parse_send_data_context_pdu::<ClientInfoPdu>(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        let expected_address_family = match CLIENT_IP_ADDR {
            IpAddr::V4(_) => rdp::AddressFamily::INet,
            IpAddr::V6(_) => rdp::AddressFamily::INet6,
        };
        let expected_address = CLIENT_IP_ADDR.to_string();

        assert_eq!(client_info.client_info.credentials, *SERVER_CREDENTIALS);
        assert_eq!(
            client_info.client_info.extra_info.address_family,
            expected_address_family
        );
        assert_eq!(client_info.client_info.extra_info.address, expected_address);
    }

    fn write_server_license(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let pdu = ServerLicensePdu {
            security_header: rdp::BasicSecurityHeader {
                flags: rdp::BasicSecurityHeaderFlags::LICENSE_PKT,
            },
            server_license: rdp::ServerLicense {
                preamble: rdp::LicensePreamble {
                    message_type: rdp::PreambleType::ErrorAlert,
                    flags: rdp::PreambleFlags::empty(),
                    version: rdp::PreambleVersion::V3,
                },
                error_message: rdp::LicensingErrorMessage {
                    error_code: rdp::LicensingErrorCode::StatusValidClient,
                    state_transition: rdp::LicensingStateTransition::NoTransition,
                    error_info: rdp::LicensingBinaryBlob {
                        blob_type: rdp::BlobType::Error,
                        data: Vec::new(),
                    },
                },
            },
        };
        encode_and_write_send_data_context_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn write_demand_active(
        &self,
        mut tls_stream: &mut TlsStream<TcpStream>,
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
                        chunk_size: 16256,
                    }),
                ],
            },
        };
        let pdu = rdp::ShareControlPdu::ServerDemandActive(demand_active);
        let header = rdp::ShareControlHeader::new(pdu, SERVER_PDU_SOURCE, SHARE_ID);
        encode_and_write_send_data_context_pdu(header, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn read_confirm_active(&self, tls_stream: &mut TlsStream<TcpStream>) -> u16 {
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

        if let rdp::ShareControlPdu::ClientConfirmActive(ClientConfirmActive { ref mut pdu }) =
            share_control_header.share_control_pdu
        {
            let size = pdu.capability_sets.len();
            pdu.capability_sets.retain(|capability_set| match capability_set {
                rdp::CapabilitySet::BitmapCacheHostSupport(_)
                | rdp::CapabilitySet::Control(_)
                | rdp::CapabilitySet::WindowActivation(_)
                | rdp::CapabilitySet::Share(_)
                | rdp::CapabilitySet::Font(_)
                | rdp::CapabilitySet::LargePointer(_)
                | rdp::CapabilitySet::DesktopComposition(_) => false,
                _ => true,
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

    fn read_synchronize_pdu(&self, tls_stream: &mut TlsStream<TcpStream>) {
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

    fn write_synchronize_pdu(&self, mut tls_stream: &mut TlsStream<TcpStream>, client_pdu_source: u16) {
        let pdu = rdp::ShareDataPdu::Synchronize(rdp::SynchronizePdu::new(client_pdu_source));
        encode_and_write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn read_control_pdu_cooperate(&self, tls_stream: &mut TlsStream<TcpStream>) {
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

    fn write_control_pdu_cooperate(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let pdu = rdp::ShareDataPdu::Control(rdp::ControlPdu::new(rdp::ControlAction::Cooperate, 0, 0));
        encode_and_write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn read_request_control_pdu(&self, tls_stream: &mut TlsStream<TcpStream>) {
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

    fn write_granted_control_pdu(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let pdu = rdp::ShareDataPdu::Control(rdp::ControlPdu::new(
            rdp::ControlAction::GrantedControl,
            MCS_INITIATOR_ID,
            u32::from(SERVER_PDU_SOURCE),
        ));
        encode_and_write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn read_font_list(&self, tls_stream: &mut TlsStream<TcpStream>) {
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

    fn write_font_map(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let pdu = rdp::ShareDataPdu::FontMap(rdp::FontPdu::new(
            0,
            0,
            rdp::SequenceFlags::FIRST | rdp::SequenceFlags::LAST,
            4,
        ));
        encode_and_write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RdpIdentity {
    pub proxy: sspi::Credentials,
    pub target: sspi::Credentials,
    pub destination: String,
}

impl RdpIdentity {
    fn new(proxy: sspi::Credentials, target: sspi::Credentials, destination: String) -> Self {
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
    rdp_identity: sspi::Credentials,
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
) {
    let reply = cred_ssp_context
        .process(ts_request)
        .expect("failed to process CredSSP phase");
    match reply {
        sspi::CredSspResult::ReplyNeeded(ts_request) => {
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
    let pdu = T::from_buffer(buffer.as_ref()).expect("failed to decode X224 Data");
    buffer.split_to(data_pdu.data_length);

    pdu
}

fn write_x224_data_pdu<T>(pdu: T, mut stream: impl io::Write)
where
    T: PduParsing,
    T::Error: fmt::Debug,
{
    Data::new(pdu.buffer_length())
        .to_buffer(&mut stream)
        .expect("failed to write X224 Data");
    pdu.to_buffer(&mut stream).expect("failed to encode X224 Data");
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

            T::from_buffer(send_data_context.pdu.as_slice()).expect("failed to decode Send Data Context PDU")
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

    let send_data_context_pdu = SendDataContext::new(pdu_buffer, initiator_id, channel_id);

    write_x224_data_pdu(McsPdu::SendDataIndication(send_data_context_pdu), &mut stream);
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
    let share_data_header = rdp::ShareDataHeader::new(
        pdu,
        rdp::StreamPriority::Medium,
        rdp::CompressionFlags::empty(),
        rdp::CompressionType::K8,
    );

    let share_control_header = rdp::ShareControlHeader::new(
        rdp::ShareControlPdu::Data(share_data_header),
        SERVER_PDU_SOURCE,
        SHARE_ID,
    );
    encode_and_write_send_data_context_pdu(share_control_header, initiator_id, channel_id, &mut stream);
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

fn accept_tls<S>(stream: S, cert_pkcs12_der: Vec<u8>, cert_pass: &str) -> TlsStream<S>
where
    S: io::Read + io::Write + fmt::Debug + 'static,
{
    let cert = native_tls::Identity::from_pkcs12(cert_pkcs12_der.as_ref(), cert_pass).unwrap();
    let tls_acceptor = TlsAcceptor::builder(cert)
        .build()
        .expect("failed to create TlsAcceptor");

    tls_acceptor
        .accept(stream)
        .expect("failed to accept the SSL connection")
}

pub fn get_tls_pubkey(der: &[u8], pass: &str) -> Vec<u8> {
    let cert = openssl::pkcs12::Pkcs12::from_der(der)
        .expect("failed to get PKCS12 from DER")
        .parse(pass)
        .expect("failed to parse PKCS12 DER")
        .cert;

    get_tls_pubkey_from_cert(cert)
}

pub fn get_tls_peer_pubkey<S>(stream: &TlsStream<S>) -> Vec<u8>
where
    S: io::Read + io::Write,
{
    let der = get_der_cert_from_stream(&stream);
    let cert = openssl::x509::X509::from_der(&der).expect("failed to get X509 cert from DER");

    get_tls_pubkey_from_cert(cert)
}

fn get_der_cert_from_stream<S>(stream: &TlsStream<S>) -> Vec<u8>
where
    S: io::Read + io::Write,
{
    stream
        .peer_certificate()
        .expect("failed to get the peer certificate")
        .expect("A server must provide the certificate")
        .to_der()
        .expect("failed to convert the peer certificate to DER")
}

fn get_tls_pubkey_from_cert(cert: openssl::x509::X509) -> Vec<u8> {
    cert.public_key()
        .expect("failed to get public key from cert")
        .public_key_to_der()
        .expect("failed to convert public key to DER")
        .split_off(TLS_PUBLIC_KEY_HEADER)
}
