mod gfx;
#[cfg(test)]
mod tests;

use std::cmp::Ordering;
use std::collections::HashMap;
use std::io;

use ironrdp::rdp::vc::{self, dvc};
use ironrdp::PduParsing;
use slog_scope::{error, info};

use crate::interceptor::PduSource;

pub const RDP8_GRAPHICS_PIPELINE_NAME: &str = "Microsoft::Windows::RDS::Graphics";

trait DynamicChannelDataHandler: Send + Sync {
    fn process_complete_data(
        &mut self,
        complete_data: CompleteDataResult,
        pdu_source: PduSource,
    ) -> Result<Vec<u8>, io::Error>;
}

pub struct DvcManager {
    dynamic_channels: HashMap<u32, DynamicChannel>,
    pending_dynamic_channels: HashMap<u32, DynamicChannel>,
    allowed_channels: Vec<String>,
}

impl DvcManager {
    pub fn with_allowed_channels(allowed_channels: Vec<String>) -> Self {
        Self {
            dynamic_channels: HashMap::new(),
            pending_dynamic_channels: HashMap::new(),
            allowed_channels,
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
                let client_dvc_pdu = dvc::ClientPdu::from_buffer(dvc_data, svc_header.total_length as usize)?;
                match client_dvc_pdu {
                    dvc::ClientPdu::CapabilitiesResponse(caps_response) => {
                        info!("DVC version client response - {:?}", caps_response.version);

                        None
                    }
                    dvc::ClientPdu::CreateResponse(create_response_pdu) => {
                        self.handle_create_response_pdu(&create_response_pdu);

                        None
                    }
                    dvc::ClientPdu::DataFirst(data_first_pdu) => {
                        self.handle_data_first_pdu(pdu_souce, data_first_pdu, dvc_data)
                    }
                    dvc::ClientPdu::Data(data_pdu) => self.handle_data_pdu(pdu_souce, data_pdu, dvc_data),
                    dvc::ClientPdu::CloseResponse(close_response_pdu) => {
                        self.handle_close_response(&close_response_pdu);

                        None
                    }
                }
            }
            PduSource::Server => {
                let server_dvc_pdu = dvc::ServerPdu::from_buffer(dvc_data, svc_header.total_length as usize)?;
                match server_dvc_pdu {
                    dvc::ServerPdu::CapabilitiesRequest(caps_request) => {
                        info!("DVC version server request - {:?}", caps_request);

                        None
                    }
                    dvc::ServerPdu::CreateRequest(create_request_pdu) => {
                        self.handle_create_request_pdu(&create_request_pdu);

                        None
                    }
                    dvc::ServerPdu::DataFirst(data_first_pdu) => {
                        self.handle_data_first_pdu(pdu_souce, data_first_pdu, dvc_data)
                    }
                    dvc::ServerPdu::Data(data_pdu) => self.handle_data_pdu(pdu_souce, data_pdu, dvc_data),
                    dvc::ServerPdu::CloseRequest(close_request_pdu) => {
                        self.handle_close_request(&close_request_pdu);

                        None
                    }
                }
            }
        };

        Ok(dvc_pdu)
    }

    pub fn handle_create_request_pdu(&mut self, create_request_pdu: &dvc::CreateRequestPdu) {
        if self.allowed_channels.contains(&create_request_pdu.channel_name) {
            let dynamic_channel = match create_request_pdu.channel_name.as_str() {
                RDP8_GRAPHICS_PIPELINE_NAME => {
                    DynamicChannel::with_handler(create_request_pdu.channel_name.clone(), Box::new(gfx::Handler::new()))
                }
                _ => DynamicChannel::new(create_request_pdu.channel_name.clone()),
            };

            self.pending_dynamic_channels
                .insert(create_request_pdu.channel_id, dynamic_channel);
        }
    }

    pub fn handle_create_response_pdu(&mut self, create_response_pdu: &dvc::CreateResponsePdu) {
        if dvc::DVC_CREATION_STATUS_OK == create_response_pdu.creation_status {
            if let Some((id, channel)) = self
                .pending_dynamic_channels
                .remove_entry(&create_response_pdu.channel_id)
            {
                // add created DVC only if client was able to create it
                info!("Creating of {} DVC with {} ID", channel.name, id);
                self.dynamic_channels.insert(id, channel);
            }
        } else {
            let channel_name = self
                .pending_dynamic_channels
                .remove(&create_response_pdu.channel_id)
                .map_or("unknown".to_string(), |channel| channel.name);

            info!(
                "Client could not create {} DVC with {} ID",
                channel_name, create_response_pdu.channel_id
            );
        }
    }

    pub fn handle_data_first_pdu(
        &mut self,
        pdu_source: PduSource,
        data_first_pdu: dvc::DataFirstPdu,
        dvc_data: &[u8],
    ) -> Option<Vec<u8>> {
        match self.dynamic_channels.get_mut(&data_first_pdu.channel_id) {
            Some(channel) => {
                let dvc_data = &dvc_data[data_first_pdu.buffer_length()..];

                channel.process_data_first_pdu(pdu_source, data_first_pdu.total_data_size as usize, dvc_data)
            }
            None => None,
        }
    }

    pub fn handle_data_pdu(
        &mut self,
        pdu_source: PduSource,
        data_pdu: dvc::DataPdu,
        dvc_data: &[u8],
    ) -> Option<Vec<u8>> {
        match self.dynamic_channels.get_mut(&data_pdu.channel_id) {
            Some(channel) => {
                let dvc_data = &dvc_data[data_pdu.buffer_length()..];

                channel.process_data_pdu(pdu_source, dvc_data)
            }
            None => None,
        }
    }

    pub fn handle_close_request(&mut self, _close_request_pdu: &dvc::ClosePdu) {
        // nothing to do because the client must send a response
    }

    pub fn handle_close_response(&mut self, close_response_pdu: &dvc::ClosePdu) {
        // remove DVC only here, because the client also can initiate DVC closing
        let channel_name = self
            .dynamic_channels
            .remove(&close_response_pdu.channel_id)
            .map_or("unknown".to_string(), |channel| channel.name);

        info!(
            "Closing of {} DVC with {} ID",
            channel_name, close_response_pdu.channel_id
        );
    }

    pub fn channel_name(&self, channel_id: u32) -> Option<&str> {
        self.dynamic_channels.get(&channel_id).map(|d| d.name.as_str())
    }
}

struct DynamicChannel {
    name: String,
    client_data: CompleteData,
    server_data: CompleteData,
    handler: Box<dyn DynamicChannelDataHandler>,
}

impl DynamicChannel {
    fn new(name: String) -> Self {
        DynamicChannel::with_handler(name, Box::new(DefaultHandler))
    }

    fn with_handler(name: String, handler: Box<dyn DynamicChannelDataHandler>) -> Self {
        Self {
            name,
            client_data: CompleteData::new(),
            server_data: CompleteData::new(),
            handler,
        }
    }

    fn process_data_first_pdu(
        &mut self,
        pdu_souce: PduSource,
        total_length: usize,
        data_first: &[u8],
    ) -> Option<Vec<u8>> {
        let complete_data = match pdu_souce {
            PduSource::Client => self.client_data.process_data_first_pdu(total_length, data_first),
            PduSource::Server => self.server_data.process_data_first_pdu(total_length, data_first),
        };

        self.process_complete_data(pdu_souce, complete_data)
    }

    fn process_data_pdu(&mut self, pdu_souce: PduSource, data: &[u8]) -> Option<Vec<u8>> {
        let complete_data = match pdu_souce {
            PduSource::Client => self.client_data.process_data_pdu(data),
            PduSource::Server => self.server_data.process_data_pdu(data),
        };

        self.process_complete_data(pdu_souce, complete_data)
    }

    fn process_complete_data(
        &mut self,
        pdu_source: PduSource,
        complete_data: Option<CompleteDataResult>,
    ) -> Option<Vec<u8>> {
        match complete_data {
            Some(complete_data) => match self.handler.process_complete_data(complete_data, pdu_source) {
                Ok(data) => Some(data),
                Err(e) => {
                    error!("Unexpected DVC error: {}", e);

                    None
                }
            },
            None => None,
        }
    }
}

#[derive(Debug, PartialEq)]
struct CompleteData {
    total_length: usize,
    data: Option<Vec<u8>>,
}

impl CompleteData {
    fn new() -> Self {
        Self {
            total_length: 0,
            data: None,
        }
    }

    fn process_data_first_pdu<'a>(
        &mut self,
        total_length: usize,
        data_first: &'a [u8],
    ) -> Option<CompleteDataResult<'a>> {
        if self.total_length != 0 || self.data.is_some() {
            error!("Incomplete DVC message, it will be skipped");

            self.data = None;
        }

        if total_length == data_first.len() {
            Some(CompleteDataResult::Complete(data_first))
        } else {
            self.total_length = total_length;
            self.data = Some(data_first.to_vec());

            None
        }
    }

    fn process_data_pdu<'a>(&mut self, data: &'a [u8]) -> Option<CompleteDataResult<'a>> {
        if self.total_length == 0 && self.data.is_none() {
            // message is not fragmented

            Some(CompleteDataResult::Complete(data))
        } else {
            // message is fragmented so need to reassemble it
            let actual_data_length = self.data.as_ref().unwrap().len() + data.len();

            match actual_data_length.cmp(&(self.total_length)) {
                Ordering::Less => {
                    // this is one of the fragmented messages, just append it
                    self.data.as_mut().unwrap().extend_from_slice(data);

                    None
                }
                Ordering::Equal => {
                    // this is the last fragmented message, need to return the whole reassembled message
                    self.data.as_mut().unwrap().extend_from_slice(data);
                    self.total_length = 0;

                    self.data.take().map(CompleteDataResult::Parted)
                }
                Ordering::Greater => {
                    error!("Actual DVC message size is grater than expected total DVC message size");
                    self.total_length = 0;

                    self.data = None;

                    None
                }
            }
        }
    }
}

enum CompleteDataResult<'a> {
    Parted(Vec<u8>),
    Complete(&'a [u8]),
}

struct DefaultHandler;

impl DynamicChannelDataHandler for DefaultHandler {
    fn process_complete_data(
        &mut self,
        complete_data: CompleteDataResult,
        _pdu_source: PduSource,
    ) -> io::Result<Vec<u8>> {
        match complete_data {
            CompleteDataResult::Parted(v) => Ok(v),
            CompleteDataResult::Complete(v) => Ok(v.to_vec()),
        }
    }
}
