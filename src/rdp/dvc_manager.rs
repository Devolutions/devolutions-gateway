#[cfg(test)]
mod tests;

use std::{cmp::Ordering, collections::HashMap};

use ironrdp::{
    rdp::vc::{self, dvc},
    PduParsing,
};
use slog_scope::{error, info};

use crate::interceptor::PduSource;

pub struct DvcManager {
    dynamic_channels: HashMap<u32, DynamicChannel>,
    pending_dynamic_channels: HashMap<u32, DynamicChannel>,
}

impl DvcManager {
    pub fn new() -> Self {
        Self {
            dynamic_channels: HashMap::new(),
            pending_dynamic_channels: HashMap::new(),
        }
    }

    pub fn process(&mut self, pdu_souce: PduSource, svc_data: &[u8]) -> Result<Option<Vec<u8>>, vc::ChannelError> {
        let svc_header = vc::ChannelPduHeader::from_buffer(svc_data)?;
        let dvc_data = &svc_data[svc_header.buffer_length()..];

        if svc_header.total_length as usize != dvc_data.len() {
            return Err(vc::ChannelError::InvalidChannelTotalDataLength);
        }

        let dvc_pdu = match pdu_souce {
            PduSource::Client => {
                let client_dvc_pdu = dvc::ClientPdu::from_buffer(dvc_data)?;
                match client_dvc_pdu {
                    dvc::ClientPdu::CapabilitiesResponse(caps_response) => {
                        info!("DVC version client response - {:?}", caps_response.version);
                        None
                    }
                    dvc::ClientPdu::CreateResponse(create_request) => {
                        if dvc::DVC_CREATION_STATUS_OK == create_request.creation_status {
                            if let Some((id, channel)) =
                                self.pending_dynamic_channels.remove_entry(&create_request.channel_id)
                            {
                                // add created DVC only if client was able to create it
                                info!("Creating of {} DVC with {} ID", channel.name, id);
                                self.dynamic_channels.insert(id, channel);
                            }
                        } else {
                            let channel_name = self
                                .pending_dynamic_channels
                                .remove(&create_request.channel_id)
                                .map_or("unknown".to_string(), |channel| channel.name);

                            info!(
                                "Client could not create {} DVC with {} ID",
                                channel_name, create_request.channel_id
                            );
                        }

                        None
                    }
                    dvc::ClientPdu::DataFirst(data_first) => {
                        match self.dynamic_channels.get_mut(&data_first.channel_id) {
                            Some(channel) => channel.process_data_first_pdu(pdu_souce, data_first),
                            None => {
                                error!("DVC with {} ID is not created", data_first.channel_id);
                                None
                            }
                        }
                    }
                    dvc::ClientPdu::Data(data) => match self.dynamic_channels.get_mut(&data.channel_id) {
                        Some(channel) => channel.process_data_pdu(pdu_souce, data),
                        None => {
                            error!("DVC with {} ID is not created", data.channel_id);
                            None
                        }
                    },
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
                let server_dvc_pdu = dvc::ServerPdu::from_buffer(dvc_data)?;
                match server_dvc_pdu {
                    dvc::ServerPdu::CapabilitiesRequest(caps_request) => {
                        info!("DVC version server request - {:?}", caps_request);
                        None
                    }
                    dvc::ServerPdu::CreateRequest(create_request) => {
                        self.pending_dynamic_channels.insert(
                            create_request.channel_id,
                            DynamicChannel::new(create_request.channel_name),
                        );
                        None
                    }
                    dvc::ServerPdu::DataFirst(data_first) => {
                        match self.dynamic_channels.get_mut(&data_first.channel_id) {
                            Some(channel) => channel.process_data_first_pdu(pdu_souce, data_first),
                            None => {
                                error!("DVC with {} ID is not created", data_first.channel_id);
                                None
                            }
                        }
                    }
                    dvc::ServerPdu::Data(data) => match self.dynamic_channels.get_mut(&data.channel_id) {
                        Some(channel) => channel.process_data_pdu(pdu_souce, data),
                        None => {
                            error!("DVC with {} ID is not created", data.channel_id);
                            None
                        }
                    },
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

    fn process_data_first_pdu(&mut self, pdu_souce: PduSource, data_first: dvc::DataFirstPdu) -> Option<Vec<u8>> {
        match pdu_souce {
            PduSource::Client => self.client_data.process_data_first_pdu(data_first),
            PduSource::Server => self.server_data.process_data_first_pdu(data_first),
        }
    }

    fn process_data_pdu(&mut self, pdu_souce: PduSource, data: dvc::DataPdu) -> Option<Vec<u8>> {
        match pdu_souce {
            PduSource::Client => self.client_data.process_data_pdu(data),
            PduSource::Server => self.server_data.process_data_pdu(data),
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

    fn process_data_first_pdu(&mut self, data_first: dvc::DataFirstPdu) -> Option<Vec<u8>> {
        if self.total_length != 0 || !self.data.is_empty() {
            error!("Incomplete DVC message, it will be skipped");
            self.data.clear();
        }
        self.total_length = data_first.data_length;
        self.data = data_first.dvc_data;

        None
    }

    fn process_data_pdu(&mut self, mut data: dvc::DataPdu) -> Option<Vec<u8>> {
        if self.total_length == 0 && self.data.is_empty() {
            // message is not fragmented
            Some(data.dvc_data)
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
