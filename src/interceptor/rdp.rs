#[cfg(test)]
mod tests;

use std::{collections::HashMap, io};

use ironrdp::{
    parse_fast_path_header, rdp::vc, Data, McsPdu, PduParsing, TpktHeader, TPDU_DATA_HEADER_LENGTH, TPKT_HEADER_LENGTH,
};
use slog_scope::error;

use crate::{
    interceptor::{MessageReader, PduSource},
    rdp::DvcManager,
};

pub struct RdpMessageReader {
    static_channels: HashMap<String, u16>,
    dvc_manager: DvcManager,
}

impl RdpMessageReader {
    pub fn new(static_channels: HashMap<String, u16>) -> Self {
        Self {
            static_channels,
            dvc_manager: DvcManager::new(),
        }
    }
}

impl MessageReader for RdpMessageReader {
    fn get_messages(&mut self, data: &mut Vec<u8>, source: PduSource) -> Vec<Vec<u8>> {
        let (tpkt_tpdu_messages, fast_path_length) = get_tpkt_tpdu_messages(data);
        let mut messages = Vec::new();

        for mut message in tpkt_tpdu_messages.iter() {
            match parse_tpkt_tpdu_message(&mut message) {
                Ok((virtual_channel_id, mut virtual_channel_buffer)) => {
                    match self.static_channels.get(vc::DRDYNVC_CHANNEL_NAME) {
                        Some(drdynvc_channel_id) => {
                            if virtual_channel_id == *drdynvc_channel_id {
                                let dvc_message = self.dvc_manager.process(source, &mut virtual_channel_buffer);
                                match dvc_message {
                                    Ok(message) => match message {
                                        Some(message) => messages.push(message),
                                        None => continue,
                                    },
                                    Err(err) => {
                                        error!("Error during DVC message parsing: {}", err);
                                    }
                                }
                            }
                        }
                        None => break,
                    }
                }
                Err(err) => {
                    error!("Error during TPKT TPDU message parsing: {}", err);
                }
            }
        }

        let messages_len = tpkt_tpdu_messages.iter().map(|v| v.len()).sum::<usize>();
        data.drain(..(messages_len + fast_path_length));

        messages
    }
}

fn get_tpkt_tpdu_messages(mut data: &[u8]) -> (Vec<&[u8]>, usize) {
    let mut tpkt_tpdu_messages = Vec::new();
    let mut fast_path_messages_length = 0;

    loop {
        match TpktHeader::from_buffer(data) {
            Ok(TpktHeader { length }) => {
                // TPKT&TPDU
                if data.len() >= length as usize {
                    let (new_message, new_data) = data.split_at(length);
                    data = new_data;
                    tpkt_tpdu_messages.push(new_message);
                } else {
                    break;
                }
            }
            Err(err)  => {
                match err {
                    ironrdp::nego::NegotiationError::TpktVersionError => {
                        // Fast-Path, need to skip
                        match parse_fast_path_header(data) {
                            Ok((_, len)) => {
                                data = &data[len as usize..];
                                fast_path_messages_length += len as usize
                            }
                            Err(ironrdp::FastPathError::NullLength { bytes_read }) => {
                                data = &data[bytes_read..];
                                fast_path_messages_length += bytes_read as usize
                            }
                            _ => break,
                        }
                    }
                    _ => break,
                }
            }
        };
    }

    (tpkt_tpdu_messages, fast_path_messages_length)
}

fn parse_tpkt_tpdu_message(mut tpkt_tpdu: &[u8]) -> Result<(u16, Vec<u8>), io::Error> {
    let data_pdu = Data::from_buffer(tpkt_tpdu)?;
    let expected_data_length = tpkt_tpdu.len() - (TPKT_HEADER_LENGTH + TPDU_DATA_HEADER_LENGTH);
    assert_eq!(expected_data_length, data_pdu.data_length);

    tpkt_tpdu = &tpkt_tpdu[(TPKT_HEADER_LENGTH + TPDU_DATA_HEADER_LENGTH)..];
    let mcs_pdu = McsPdu::from_buffer(tpkt_tpdu)?;

    match mcs_pdu {
        McsPdu::SendDataIndication(send_data_context) | McsPdu::SendDataRequest(send_data_context) => {
            Ok((send_data_context.channel_id, send_data_context.pdu))
        }
        pdu => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unexpected Mcs pdu: {:?}", pdu),
        )),
    }
}
