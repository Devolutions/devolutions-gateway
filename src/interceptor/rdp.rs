#[cfg(test)]
mod tests;

use std::{cmp::Ordering, collections::HashMap, io};

use ironrdp::{
    parse_fast_path_header,
    rdp::vc::{self, dvc},
    PduParsing, TpktHeader,
};
use slog_scope::{error, info};

const DVC_CREATION_STATUS_OK: u32 = 0x0000_0000;

pub enum PduSource {
    Client,
    Server,
}

pub struct RdpMessageReader;
impl RdpMessageReader {
    pub fn get_messages(data: &mut Vec<u8>) -> Vec<Vec<u8>> {
        let mut messages = Vec::new();

        loop {
            let len = match TpktHeader::from_buffer(data.as_slice()) {
                Ok(TpktHeader { length }) => {
                    // TPKT&TPDU
                    Some(length)
                }
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                _ => {
                    // Fast-Path
                    match parse_fast_path_header(data.as_slice()) {
                        Ok((_, len)) => Some(usize::from(len)),
                        Err(ironrdp::FastPathError::NullLength { bytes_read }) => {
                            data.drain(..bytes_read);

                            None
                        }
                        _ => break,
                    }
                }
            };

            if let Some(len) = len {
                if data.len() >= len as usize {
                    let new_message: Vec<u8> = data.drain(..len as usize).collect();
                    messages.push(new_message);
                } else {
                    break;
                }
            }
        }

        messages
    }
}

struct DvcManager {
    dynamic_channels: HashMap<u32, DynamicChannel>,
}

impl DvcManager {
    fn new() -> Self {
        Self {
            dynamic_channels: HashMap::new(),
        }
    }

    fn process(&mut self, pdu_souce: PduSource, svc_data: &mut Vec<u8>) -> Result<Option<Vec<u8>>, vc::ChannelError> {
        let svc_header = vc::ChannelPduHeader::from_buffer(svc_data.as_slice())?;
        let dvc_data: Vec<u8> = svc_data.drain(svc_header.buffer_length()..).collect();
        if svc_header.total_length as usize != dvc_data.len() {
            return Err(vc::ChannelError::InvalidChannelTotalDataLength);
        }

        let dvc_pdu = match pdu_souce {
            PduSource::Client => {
                let client_dvc_pdu = dvc::ClientPdu::from_buffer(dvc_data.as_slice())?;
                match client_dvc_pdu {
                    dvc::ClientPdu::CapabilitiesResponse(caps_response) => {
                        info!("DVC version client response - {:?}", caps_response.version);
                        None
                    }
                    dvc::ClientPdu::CreateResponse(create_request) => {
                        if DVC_CREATION_STATUS_OK != create_request.creation_status {
                            // remove requested DVC if client could not create it
                            let channel_name = self
                                .dynamic_channels
                                .remove(&create_request.channel_id)
                                .map_or("unknown".to_string(), |channel| channel.name);

                            info!("Closing of {} DVC with {} ID", channel_name, create_request.channel_id);
                        }

                        None
                    }
                    dvc::ClientPdu::DataFirst(mut data_first) => {
                        match self.dynamic_channels.get_mut(&data_first.channel_id) {
                            Some(channel) => channel.process_data_first_pdu(pdu_souce, &mut data_first),
                            None => {
                                error!("DVC with {} ID is not created", data_first.channel_id);
                                None
                            }
                        }
                    }
                    dvc::ClientPdu::Data(mut data) => {
                        let is_complete_message = svc_header
                            .flags
                            .contains(vc::ChannelControlFlags::FLAG_FIRST | vc::ChannelControlFlags::FLAG_LAST);

                        match self.dynamic_channels.get_mut(&data.channel_id) {
                            Some(channel) => channel.process_data_pdu(pdu_souce, &mut data, is_complete_message),
                            None => {
                                error!("DVC with {} ID is not created", data.channel_id);
                                None
                            }
                        }
                    }
                    dvc::ClientPdu::CloseResponse(close_response) => {
                        // remove DVC only here, because the client also can initiate DVC closing
                        let channel_name = self
                            .dynamic_channels
                            .remove(&close_response.channel_id)
                            .map_or("unknown".to_string(), |channel| channel.name);

                        info!("Closing of {} DVC with {} ID", channel_name, close_response.channel_id);
                        None
                    }
                }
            }
            PduSource::Server => {
                let server_dvc_pdu = dvc::ServerPdu::from_buffer(dvc_data.as_slice())?;
                match server_dvc_pdu {
                    dvc::ServerPdu::CapabilitiesRequest(caps_request) => {
                        info!("DVC version server request - {:?}", caps_request);
                        None
                    }
                    dvc::ServerPdu::CreateRequest(create_request) => {
                        self.dynamic_channels.insert(
                            create_request.channel_id,
                            DynamicChannel::new(create_request.channel_name.clone()),
                        );
                        info!(
                            "Creating of {} DVC with {} ID",
                            create_request.channel_name, create_request.channel_id
                        );
                        None
                    }
                    dvc::ServerPdu::DataFirst(mut data_first) => {
                        match self.dynamic_channels.get_mut(&data_first.channel_id) {
                            Some(channel) => channel.process_data_first_pdu(pdu_souce, &mut data_first),
                            None => {
                                error!("DVC with {} ID is not created", data_first.channel_id);
                                None
                            }
                        }
                    }
                    dvc::ServerPdu::Data(mut data) => {
                        let is_complete_message = svc_header
                            .flags
                            .contains(vc::ChannelControlFlags::FLAG_FIRST | vc::ChannelControlFlags::FLAG_LAST);

                        match self.dynamic_channels.get_mut(&data.channel_id) {
                            Some(channel) => channel.process_data_pdu(pdu_souce, &mut data, is_complete_message),
                            None => {
                                error!("DVC with {} ID is not created", data.channel_id);
                                None
                            }
                        }
                    }
                    dvc::ServerPdu::CloseRequest(_) => {
                        // nothing to do because the client must send a response
                        None
                    }
                }
            }
        };

        Ok(dvc_pdu)
    }
}

#[derive(Debug, PartialEq)]
struct DynamicChannel {
    name: String,
    client_data: CompleteData,
    server_data: CompleteData,
}

impl DynamicChannel {
    fn new(name: String) -> Self {
        Self {
            name,
            client_data: CompleteData::new(),
            server_data: CompleteData::new(),
        }
    }

    fn process_data_first_pdu(&mut self, pdu_souce: PduSource, data_first: &mut dvc::DataFirstPdu) -> Option<Vec<u8>> {
        match pdu_souce {
            PduSource::Client => self.client_data.process_data_first_pdu(data_first),
            PduSource::Server => self.server_data.process_data_first_pdu(data_first),
        }
    }

    fn process_data_pdu(
        &mut self,
        pdu_souce: PduSource,
        data: &mut dvc::DataPdu,
        is_complete_message: bool,
    ) -> Option<Vec<u8>> {
        match pdu_souce {
            PduSource::Client => self.client_data.process_data_pdu(data, is_complete_message),
            PduSource::Server => self.server_data.process_data_pdu(data, is_complete_message),
        }
    }
}

#[derive(Debug, PartialEq)]
struct CompleteData {
    total_length: u32,
    data: Vec<u8>,
}

impl CompleteData {
    fn new() -> Self {
        Self {
            total_length: 0,
            data: Vec::new(),
        }
    }

    fn process_data_first_pdu(&mut self, data_first: &mut dvc::DataFirstPdu) -> Option<Vec<u8>> {
        if self.total_length != 0 || !self.data.is_empty() {
            error!("Incomplete DVC message. It will be skipped.");
            self.data.clear();
        }
        self.total_length = data_first.data_length;
        self.data.append(&mut data_first.dvc_data);

        None
    }

    fn process_data_pdu(&mut self, data: &mut dvc::DataPdu, is_complete_message: bool) -> Option<Vec<u8>> {
        if is_complete_message {
            Some(data.dvc_data.clone())
        } else {
            // message is fragmented so need to reassemble it
            let actual_data_length = self.data.len() + data.dvc_data.len();

            match actual_data_length.cmp(&(self.total_length as usize)) {
                Ordering::Less => {
                    // this is one of the fragmented messages, just append it
                    self.data.append(&mut data.dvc_data);
                    None
                }
                Ordering::Equal => {
                    // this is the last fragmented message, need to return the whole reassembled message
                    self.total_length = 0;
                    self.data.append(&mut data.dvc_data);
                    Some(self.data.drain(..).collect())
                }
                Ordering::Greater => {
                    error!("Actual DVC message size is grater than expected total DVC message size");
                    self.total_length = 0;
                    self.data.clear();

                    None
                }
            }
        }
    }
}
