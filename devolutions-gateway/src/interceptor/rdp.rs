use crate::interceptor::{MessageReader, PduSource};
use crate::rdp::DvcManager;
use ironrdp::fast_path::{FastPathError, FastPathHeader};
use ironrdp::mcs::DisconnectUltimatumReason;
use ironrdp::nego::NegotiationError;
use ironrdp::rdp::vc;
use ironrdp::{Data, McsPdu, PduParsing, TpktHeader, TPDU_DATA_HEADER_LENGTH, TPKT_HEADER_LENGTH};
use std::collections::HashMap;
use std::io;

pub struct RdpMessageReader {
    static_channels: HashMap<String, u16>,
    dvc_manager: Option<DvcManager>,
}

impl RdpMessageReader {
    pub fn new(static_channels: HashMap<String, u16>, dvc_manager: Option<DvcManager>) -> Self {
        Self {
            static_channels,
            dvc_manager,
        }
    }
}

impl MessageReader for RdpMessageReader {
    fn get_messages(&mut self, data: &mut Vec<u8>, source: PduSource) -> Vec<Vec<u8>> {
        let (tpkt_tpdu_messages, messages_len) = get_tpkt_tpdu_messages(data);
        let mut messages = Vec::new();

        for message in tpkt_tpdu_messages.iter() {
            match parse_tpkt_tpdu_message(message) {
                Ok(ParsedTpktPtdu::VirtualChannel { id, buffer }) => {
                    if let Some(drdynvc_channel_id) = self.static_channels.get(vc::DRDYNVC_CHANNEL_NAME) {
                        if id == *drdynvc_channel_id {
                            let dvc_manager = self
                                .dvc_manager
                                .as_mut()
                                .expect("Can't process drdynvc channel message: DVC manager is missing");
                            match dvc_manager.process(source, buffer) {
                                Ok(Some(message)) => messages.push(message),
                                Ok(None) => continue,
                                Err(err) => {
                                    error!("Error during DVC message parsing: {}", err);
                                }
                            }
                        }
                    }
                }
                Ok(ParsedTpktPtdu::DisconnectionRequest(reason)) => {
                    info!("Disconnection request has been received: {:?}", reason);

                    break;
                }
                Err(err) => {
                    error!("Error during TPKT TPDU message parsing: {}", err);
                }
            }
        }

        data.drain(..messages_len);
        info!("messages - {:?}", messages);
        messages
    }
}

fn get_tpkt_tpdu_messages(mut data: &[u8]) -> (Vec<&[u8]>, usize) {
    let mut tpkt_tpdu_messages = Vec::new();
    let mut messages_len = 0;

    loop {
        match TpktHeader::from_buffer(data) {
            Ok(TpktHeader { length }) => {
                // TPKT&TPDU
                if data.len() >= length as usize {
                    let (new_message, new_data) = data.split_at(length);
                    data = new_data;
                    messages_len += new_message.len();
                    tpkt_tpdu_messages.push(new_message);
                } else {
                    break;
                }
            }
            Err(NegotiationError::TpktVersionError) => {
                // Fast-Path, need to skip
                match FastPathHeader::from_buffer(data) {
                    Ok(header) => {
                        let packet_length = header.buffer_length() + header.data_length;

                        if data.len() >= packet_length {
                            data = &data[packet_length..];

                            messages_len += packet_length
                        } else {
                            break;
                        }
                    }
                    Err(FastPathError::NullLength { bytes_read }) => {
                        data = &data[bytes_read..];
                        messages_len += bytes_read
                    }
                    _ => break,
                }
            }
            Err(_) => break,
        };
    }

    (tpkt_tpdu_messages, messages_len)
}

fn parse_tpkt_tpdu_message(mut tpkt_tpdu: &[u8]) -> Result<ParsedTpktPtdu, io::Error> {
    let data_pdu = Data::from_buffer(tpkt_tpdu)?;
    let expected_data_length = tpkt_tpdu.len() - (TPKT_HEADER_LENGTH + TPDU_DATA_HEADER_LENGTH);
    assert_eq!(expected_data_length, data_pdu.data_length);

    tpkt_tpdu = &tpkt_tpdu[TPKT_HEADER_LENGTH + TPDU_DATA_HEADER_LENGTH..];
    let mcs_pdu = McsPdu::from_buffer(tpkt_tpdu)?;

    match mcs_pdu {
        McsPdu::SendDataIndication(ref send_data_context) | McsPdu::SendDataRequest(ref send_data_context) => {
            Ok(ParsedTpktPtdu::VirtualChannel {
                id: send_data_context.channel_id,
                buffer: &tpkt_tpdu[tpkt_tpdu.len() - send_data_context.pdu_length..],
            })
        }
        McsPdu::DisconnectProviderUltimatum(reason) => Ok(ParsedTpktPtdu::DisconnectionRequest(reason)),
        pdu => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unexpected MCS PDU: {:?}", pdu),
        )),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum ParsedTpktPtdu<'a> {
    VirtualChannel { id: u16, buffer: &'a [u8] },
    DisconnectionRequest(DisconnectUltimatumReason),
}

#[cfg(test)]
mod tests {
    use super::*;

    const TPKT_CLIENT_CONNECTION_REQUEST_PACKET: [u8; 44] = [
        0x03, 0x00, 0x00, 0x2c, 0x27, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a,
        0x20, 0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, 0x3d, 0x65, 0x6c, 0x74, 0x6f, 0x6e, 0x73, 0x0d, 0x0a,
        0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const TPKT_CLIENT_MCS_CONNECT_INITIAL_PACKET: [u8; 416] = [
        0x03, 0x00, 0x01, 0xa0, 0x02, 0xf0, 0x80, 0x7f, 0x65, 0x82, 0x01, 0x94, 0x04, 0x01, 0x01, 0x04, 0x01, 0x01,
        0x01, 0x01, 0xff, 0x30, 0x19, 0x02, 0x01, 0x22, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02,
        0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01, 0x02, 0x30, 0x19, 0x02, 0x01, 0x01, 0x02,
        0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0x04, 0x20,
        0x02, 0x01, 0x02, 0x30, 0x1c, 0x02, 0x02, 0xff, 0xff, 0x02, 0x02, 0xfc, 0x17, 0x02, 0x02, 0xff, 0xff, 0x02,
        0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01, 0x02, 0x04, 0x82, 0x01,
        0x33, 0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x81, 0x2a, 0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00,
        0x44, 0x75, 0x63, 0x61, 0x81, 0x1c, 0x01, 0xc0, 0xd8, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x05, 0x00, 0x04,
        0x01, 0xca, 0x03, 0xaa, 0x09, 0x04, 0x00, 0x00, 0xce, 0x0e, 0x00, 0x00, 0x45, 0x00, 0x4c, 0x00, 0x54, 0x00,
        0x4f, 0x00, 0x4e, 0x00, 0x53, 0x00, 0x2d, 0x00, 0x44, 0x00, 0x45, 0x00, 0x56, 0x00, 0x32, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xca, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x18, 0x00, 0x07, 0x00, 0x01, 0x00, 0x36, 0x00, 0x39, 0x00, 0x37, 0x00, 0x31, 0x00, 0x32, 0x00,
        0x2d, 0x00, 0x37, 0x00, 0x38, 0x00, 0x33, 0x00, 0x2d, 0x00, 0x30, 0x00, 0x33, 0x00, 0x35, 0x00, 0x37, 0x00,
        0x39, 0x00, 0x37, 0x00, 0x34, 0x00, 0x2d, 0x00, 0x34, 0x00, 0x32, 0x00, 0x37, 0x00, 0x31, 0x00, 0x34, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xc0, 0x0c, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0xc0, 0x0c, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xc0, 0x2c, 0x00, 0x03, 0x00,
        0x00, 0x00, 0x72, 0x64, 0x70, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80, 0x63, 0x6c, 0x69, 0x70,
        0x72, 0x64, 0x72, 0x00, 0x00, 0x00, 0xa0, 0xc0, 0x72, 0x64, 0x70, 0x73, 0x6e, 0x64, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xc0,
    ];
    const TPKT_CLIENT_MCS_ERECT_DOMAIN_PACKET: [u8; 12] =
        [0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80, 0x04, 0x01, 0x00, 0x01, 0x00];
    const TPKT_CLIENT_MCS_ATTACH_USER_REQUEST_PACKET: [u8; 8] = [0x03, 0x00, 0x00, 0x08, 0x02, 0xf0, 0x80, 0x28];
    const TPKT_CLIENT_MCS_ATTACH_USER_CONFIRM_PACKET: [u8; 94] = [
        0x03, 0x00, 0x00, 0x5e, 0x02, 0xf0, 0x80, 0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x50, 0x01, 0x02, 0x00, 0x00,
        0x48, 0x00, 0x00, 0x00, 0x91, 0xac, 0x0c, 0x8f, 0x64, 0x8c, 0x39, 0xf4, 0xe7, 0xff, 0x0a, 0x3b, 0x79, 0x11,
        0x5c, 0x13, 0x51, 0x2a, 0xcb, 0x72, 0x8f, 0x9d, 0xb7, 0x42, 0x2e, 0xf7, 0x08, 0x4c, 0x8e, 0xae, 0x55, 0x99,
        0x62, 0xd2, 0x81, 0x81, 0xe4, 0x66, 0xc8, 0x05, 0xea, 0xd4, 0x73, 0x06, 0x3f, 0xc8, 0x5f, 0xaf, 0x2a, 0xfd,
        0xfc, 0xf1, 0x64, 0xb3, 0x3f, 0x0a, 0x15, 0x1d, 0xdb, 0x2c, 0x10, 0x9d, 0x30, 0x11, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    const FASTPATH_PACKET: [u8; 17] = [
        0xc4, 0x11, 0x30, 0x35, 0x6b, 0x5b, 0xb5, 0x34, 0xc8, 0x47, 0x26, 0x18, 0x5e, 0x76, 0x0e, 0xde, 0x28,
    ];

    const TPKT_SERVER_MCS_DATA_INDICATION_DVC_CREATE_REQUEST_PACKET: [u8; 66] = [
        0x03, 0x00, 0x00, 0x42, 0x02, 0xf0, 0x80, 0x68, 0x00, 0x01, 0x03, 0xef, 0xf0, 0x34, 0x2c, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x10, 0x0a, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x3a, 0x3a, 0x57,
        0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x3a, 0x3a, 0x52, 0x44, 0x53, 0x3a, 0x3a, 0x47, 0x65, 0x6f, 0x6d, 0x65,
        0x74, 0x72, 0x79, 0x3a, 0x3a, 0x76, 0x30, 0x38, 0x2e, 0x30, 0x31, 0x00,
    ];

    const TPKT_CLIENT_MCS_DATA_REQUEST_DVC_CREATE_RESPONSE_PACKET: [u8; 28] = [
        0x03, 0x00, 0x00, 0x1c, 0x02, 0xf0, 0x80, 0x64, 0x00, 0x01, 0x03, 0xef, 0xf0, 0x0e, 0x06, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x10, 0x0a, 0x00, 0x00, 0x00, 0x00,
    ];

    const CHANNEL_DVC_CREATE_REQUEST_PACKET: [u8; 52] = [
        0x2c, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10, 0x0a, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66,
        0x74, 0x3a, 0x3a, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x3a, 0x3a, 0x52, 0x44, 0x53, 0x3a, 0x3a, 0x47,
        0x65, 0x6f, 0x6d, 0x65, 0x74, 0x72, 0x79, 0x3a, 0x3a, 0x76, 0x30, 0x38, 0x2e, 0x30, 0x31, 0x00,
    ];

    const TPKT_SERVER_MCS_DATA_INDICATION_DVC_DATA_PACKET: [u8; 70] = [
        0x03, 0x00, 0x00, 0x46, 0x02, 0xf0, 0x80, 0x68, 0x00, 0x01, 0x03, 0xef, 0xf0, 0x38, 0x30, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x34, 0x0a, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
        0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
        0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    ];

    const DVC_DATA_PACKET: [u8; 46] = [
        0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
        0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
        0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    ];

    const DRDYNVC_CHANNEL_ID: u16 = 1007;

    #[test]
    fn correct_reads_single_tpkt_packet() {
        let data = TPKT_CLIENT_CONNECTION_REQUEST_PACKET;

        let (messages, _) = get_tpkt_tpdu_messages(&data);
        assert_eq!(1, messages.len());
        assert_eq!(data.as_ref(), messages.first().unwrap().as_ref());
    }

    #[test]
    fn does_not_read_fastpath_packet() {
        let data = FASTPATH_PACKET;

        let (messages, fast_path_length) = get_tpkt_tpdu_messages(&data);
        assert_eq!(FASTPATH_PACKET.len(), fast_path_length);
        assert!(messages.is_empty());
    }

    #[test]
    fn does_not_read_incomplete_tpkt_packet() {
        let data = &TPKT_CLIENT_CONNECTION_REQUEST_PACKET[..3];

        let (messages, _) = get_tpkt_tpdu_messages(&data);
        assert!(messages.is_empty());
    }

    #[test]
    fn does_not_read_incomplete_packet_on_multiple_calls() {
        let mut data = TPKT_CLIENT_CONNECTION_REQUEST_PACKET.to_vec();
        data.truncate(3);

        let (messages, _) = get_tpkt_tpdu_messages(&data);
        assert!(messages.is_empty());

        let (messages, _) = get_tpkt_tpdu_messages(&data);
        assert!(messages.is_empty());
    }

    #[test]
    fn reads_packet_on_second_call_after_incomplete_read() {
        let packet = TPKT_CLIENT_CONNECTION_REQUEST_PACKET;
        let (packet_first_part, packet_second_part) = packet.split_at(3);
        let mut data = packet_first_part.to_vec();

        let (messages, _) = get_tpkt_tpdu_messages(&data);
        assert!(messages.is_empty());

        data.extend(packet_second_part);
        let (messages, _) = get_tpkt_tpdu_messages(&data);
        assert_eq!(1, messages.len());
        assert_eq!(packet.as_ref(), messages.first().unwrap().as_ref());
    }

    #[test]
    fn reads_multiple_packets_after_incomplete_call() {
        let first_packet = TPKT_CLIENT_CONNECTION_REQUEST_PACKET;
        let second_packet = FASTPATH_PACKET;
        let third_packet = TPKT_CLIENT_CONNECTION_REQUEST_PACKET;
        let (first_packet_first_part, second_packet_second_part) = first_packet.split_at(3);
        let mut data = first_packet_first_part.to_vec();

        let (messages, data_length) = get_tpkt_tpdu_messages(&data);
        assert!(messages.is_empty());
        assert_eq!(0, data_length);

        data.extend_from_slice(second_packet_second_part);
        data.extend_from_slice(second_packet.as_ref());
        data.extend_from_slice(third_packet.as_ref());
        let (messages, data_length) = get_tpkt_tpdu_messages(&data);

        assert_eq!(2, messages.len());
        assert_eq!(first_packet.as_ref(), messages.first().unwrap().as_ref());
        assert_eq!(third_packet.as_ref(), messages.last().unwrap().as_ref());
        assert_eq!(data.len(), data_length);
    }

    #[test]
    fn reads_bunch_of_packets() {
        let packets_without_fastpath = [
            &TPKT_CLIENT_CONNECTION_REQUEST_PACKET[..],
            &TPKT_CLIENT_MCS_CONNECT_INITIAL_PACKET[..],
            &TPKT_CLIENT_MCS_ERECT_DOMAIN_PACKET[..],
            &TPKT_CLIENT_MCS_ATTACH_USER_REQUEST_PACKET[..],
            &TPKT_CLIENT_MCS_ATTACH_USER_CONFIRM_PACKET[..],
        ];
        let data = [
            &TPKT_CLIENT_CONNECTION_REQUEST_PACKET[..],
            &TPKT_CLIENT_MCS_CONNECT_INITIAL_PACKET[..],
            &TPKT_CLIENT_MCS_ERECT_DOMAIN_PACKET[..],
            &TPKT_CLIENT_MCS_ATTACH_USER_REQUEST_PACKET[..],
            &TPKT_CLIENT_MCS_ATTACH_USER_CONFIRM_PACKET[..],
            &FASTPATH_PACKET[..],
        ]
        .concat();
        let (messages, data_length) = get_tpkt_tpdu_messages(&data);

        assert_eq!(data.len(), data_length);

        // because fast-path is skipped
        assert_eq!(packets_without_fastpath.as_ref(), messages.as_slice());
    }

    #[test]
    fn reads_bunch_of_packets_with_last_incomplete_pockets() {
        let packets = [
            &TPKT_CLIENT_CONNECTION_REQUEST_PACKET[..],
            &TPKT_CLIENT_MCS_CONNECT_INITIAL_PACKET[..],
            &TPKT_CLIENT_MCS_ERECT_DOMAIN_PACKET[..],
            &TPKT_CLIENT_MCS_ATTACH_USER_REQUEST_PACKET[..],
        ];
        let data = [
            &TPKT_CLIENT_CONNECTION_REQUEST_PACKET[..],
            &TPKT_CLIENT_MCS_CONNECT_INITIAL_PACKET[..],
            &TPKT_CLIENT_MCS_ERECT_DOMAIN_PACKET[..],
            &TPKT_CLIENT_MCS_ATTACH_USER_REQUEST_PACKET[..],
            &TPKT_CLIENT_MCS_ATTACH_USER_CONFIRM_PACKET[..3],
        ]
        .concat();

        let (messages, _) = get_tpkt_tpdu_messages(&data);
        assert_eq!(packets.as_ref(), messages.as_slice());
    }

    #[test]
    fn reads_windows_style_first_bunch_of_packets() {
        let data = [&[0x00; 4][..], &TPKT_CLIENT_CONNECTION_REQUEST_PACKET[..]].concat();

        let (messages, _) = get_tpkt_tpdu_messages(&data);
        assert_eq!(1, messages.len());
        assert_eq!(
            TPKT_CLIENT_CONNECTION_REQUEST_PACKET.as_ref(),
            messages.first().unwrap().as_ref()
        );
    }

    #[test]
    fn does_not_parse_fast_path_pdu() {
        let packet = FASTPATH_PACKET;

        match parse_tpkt_tpdu_message(&packet) {
            Err(_) => (),
            res => panic!("Expected error, got: {:?}", res),
        }
    }

    #[test]
    fn does_not_parse_invalid_tpkt_tpdu() {
        let packet = &TPKT_SERVER_MCS_DATA_INDICATION_DVC_CREATE_REQUEST_PACKET[3..];

        match parse_tpkt_tpdu_message(&packet) {
            Err(_) => (),
            res => panic!("Expected error, got: {:?}", res),
        }
    }

    #[test]
    fn does_not_parse_unsuitable_tpkt_mcs_pdu() {
        let packet = TPKT_CLIENT_MCS_ATTACH_USER_REQUEST_PACKET;

        match parse_tpkt_tpdu_message(packet.as_ref()) {
            Err(_) => (),
            res => panic!("Expected error, got: {:?}", res),
        }
    }

    #[test]
    fn parses_tpkt_channel_pdu() {
        let packet = TPKT_SERVER_MCS_DATA_INDICATION_DVC_CREATE_REQUEST_PACKET;

        match parse_tpkt_tpdu_message(packet.as_ref()).unwrap() {
            ParsedTpktPtdu::VirtualChannel { id, buffer } => {
                assert_eq!(DRDYNVC_CHANNEL_ID, id);
                assert_eq!(CHANNEL_DVC_CREATE_REQUEST_PACKET.as_ref(), buffer);
            }
            _ => panic!("Unexpected DisconnectionRequest"),
        }
    }

    #[test]
    fn message_reader_correct_reads_dvc_data_packet() {
        let mut channels = HashMap::new();
        channels.insert("drdynvc".to_string(), DRDYNVC_CHANNEL_ID);
        let mut rdp_message_reader = RdpMessageReader::new(
            channels,
            Some(DvcManager::with_allowed_channels(vec![
                "Microsoft::Windows::RDS::Geometry::v08.01".to_string(),
            ])),
        );

        let mut first_packet = TPKT_SERVER_MCS_DATA_INDICATION_DVC_CREATE_REQUEST_PACKET.to_vec();
        let messages = rdp_message_reader.get_messages(&mut first_packet, PduSource::Server);
        assert!(messages.is_empty());

        let mut second_packet = TPKT_CLIENT_MCS_DATA_REQUEST_DVC_CREATE_RESPONSE_PACKET.to_vec();
        let messages = rdp_message_reader.get_messages(&mut second_packet, PduSource::Client);
        assert!(messages.is_empty());

        let mut third_packet = TPKT_SERVER_MCS_DATA_INDICATION_DVC_DATA_PACKET.to_vec();
        let messages = rdp_message_reader.get_messages(&mut third_packet, PduSource::Server);

        assert_eq!(DVC_DATA_PACKET.as_ref(), messages.first().unwrap().as_slice());
    }
}
