#[cfg(test)]
mod tests;

use std::{collections::HashMap, io};

use ironrdp::{
    fast_path::{FastPathHeader, FastPathError},
    mcs::DisconnectUltimatumReason, nego::NegotiationError, rdp::vc, Data, McsPdu, PduParsing,
    TpktHeader, TPDU_DATA_HEADER_LENGTH, TPKT_HEADER_LENGTH,
};
use slog_scope::{error, info};

use crate::{
    interceptor::{MessageReader, PduSource},
    rdp::DvcManager,
};

pub struct RdpMessageReader {
    static_channels: HashMap<String, u16>,
    dvc_manager: DvcManager,
}

impl RdpMessageReader {
    pub fn new(static_channels: HashMap<String, u16>, dvc_manager: DvcManager) -> Self {
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
                    match self.static_channels.get(vc::DRDYNVC_CHANNEL_NAME) {
                        Some(drdynvc_channel_id) => {
                            if id == *drdynvc_channel_id {
                                match self.dvc_manager.process(source, buffer) {
                                    Ok(Some(message)) => messages.push(message),
                                    Ok(None) => continue,
                                    Err(err) => {
                                        error!("Error during DVC message parsing: {}", err);
                                    }
                                }
                            }
                        }
                        None => unreachable!("drdynvc channel must be created"),
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
                    Ok(FastPathHeader {data_length, ..}) => {
                        if data.len() >= data_length as usize {
                            data = &data[data_length as usize..];

                            messages_len += data_length as usize
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
