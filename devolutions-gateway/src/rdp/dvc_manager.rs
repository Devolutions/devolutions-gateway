mod gfx;

use crate::interceptor::PeerSide;
use ironrdp::rdp::vc::{self, dvc};
use ironrdp::PduParsing;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::io;

pub const RDP8_GRAPHICS_PIPELINE_NAME: &str = "Microsoft::Windows::RDS::Graphics";

trait DynamicChannelDataHandler: Send + Sync {
    fn process_complete_data(
        &mut self,
        complete_data: CompleteDataResult,
        pdu_source: PeerSide,
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

    pub fn process(&mut self, pdu_source: PeerSide, svc_data: &[u8]) -> Result<Option<Vec<u8>>, vc::ChannelError> {
        let svc_header = vc::ChannelPduHeader::from_buffer(svc_data)?;
        let dvc_data = &svc_data[svc_header.buffer_length()..];

        if svc_header.total_length as usize != dvc_data.len() {
            return Err(vc::ChannelError::InvalidChannelTotalDataLength);
        }

        let dvc_pdu = match pdu_source {
            PeerSide::Client => {
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
                        self.handle_data_first_pdu(pdu_source, data_first_pdu, dvc_data)
                    }
                    dvc::ClientPdu::Data(data_pdu) => self.handle_data_pdu(pdu_source, data_pdu, dvc_data),
                    dvc::ClientPdu::CloseResponse(close_response_pdu) => {
                        self.handle_close_response(&close_response_pdu);

                        None
                    }
                }
            }
            PeerSide::Server => {
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
                        self.handle_data_first_pdu(pdu_source, data_first_pdu, dvc_data)
                    }
                    dvc::ServerPdu::Data(data_pdu) => self.handle_data_pdu(pdu_source, data_pdu, dvc_data),
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
        pdu_source: PeerSide,
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
        pdu_source: PeerSide,
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
        pdu_source: PeerSide,
        total_length: usize,
        data_first: &[u8],
    ) -> Option<Vec<u8>> {
        let complete_data = match pdu_source {
            PeerSide::Client => self.client_data.process_data_first_pdu(total_length, data_first),
            PeerSide::Server => self.server_data.process_data_first_pdu(total_length, data_first),
        };

        self.process_complete_data(pdu_source, complete_data)
    }

    fn process_data_pdu(&mut self, pdu_source: PeerSide, data: &[u8]) -> Option<Vec<u8>> {
        let complete_data = match pdu_source {
            PeerSide::Client => self.client_data.process_data_pdu(data),
            PeerSide::Server => self.server_data.process_data_pdu(data),
        };

        self.process_complete_data(pdu_source, complete_data)
    }

    fn process_complete_data(
        &mut self,
        pdu_source: PeerSide,
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
        _pdu_source: PeerSide,
    ) -> io::Result<Vec<u8>> {
        match complete_data {
            CompleteDataResult::Parted(v) => Ok(v),
            CompleteDataResult::Complete(v) => Ok(v.to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DRDYNVC_WITH_CAPS_REQUEST_PACKET: [u8; 20] = [
        0x0C, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x58, 0x00, 0x02, 0x00, 0x33, 0x33, 0x11, 0x11, 0x3d, 0x0a,
        0xa7, 0x04,
    ];
    const DRDYNVC_WITH_CAPS_RESPONSE_PACKET: [u8; 12] =
        [0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x50, 0x00, 0x02, 0x00];

    const DRDYNVC_WITH_CREATE_RESPONSE_PACKET: [u8; 14] = [
        0x06, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00,
    ];
    const DRDYNVC_WITH_CREATE_REQUEST_PACKET: [u8; 19] = [
        0x0B, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x31,
        0x00,
    ];
    const DRDYNVC_WITH_DATA_FIRST_PACKET: [u8; 57] = [
        0x31, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x03, 0x5C, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
        0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
        0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
        0x71, 0x71, 0x71,
    ];
    const DRDYNVC_WITH_DATA_LAST_PACKET: [u8; 56] = [
        0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x34, 0x03, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
        0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
        0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
        0x71, 0x71,
    ];
    const DRDYNVC_WITH_COMPLETE_DATA_PACKET: [u8; 56] = [
        0x30, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x34, 0x03, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
        0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
        0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
        0x71, 0x71,
    ];
    const DRDYNVC_WITH_CLOSE_PACKET: [u8; 10] = [0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x40, 0x03];
    const RAW_UNFRAGMENTED_DATA_BUFFER: [u8; 46] = [0x71; 46];
    const RAW_FRAGMENTED_DATA_BUFFER: [u8; 92] = [0x71; 92];

    const DRDYNVC_WITH_FAILED_CREATION_STATUS_PACKET: [u8; 14] = [
        0x06, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10, 0x03, 0x01, 0x00, 0x00, 0x00,
    ];
    const VC_PACKET_WITH_INVALID_TOTAL_DATA_LENGTH: [u8; 9] = [0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00];

    const CHANNEL_NAME: &str = "testdvc1";
    const CHANNEL_ID: u32 = 0x03;

    #[test]
    fn dvc_manager_reads_dvc_caps_request_packet_without_error() {
        let mut dvc_manager = DvcManager::with_allowed_channels(Vec::new());
        let result_message = dvc_manager
            .process(PeerSide::Server, DRDYNVC_WITH_CAPS_REQUEST_PACKET.as_ref())
            .unwrap();

        assert_eq!(None, result_message);
    }

    #[test]
    fn dvc_manager_reads_dvc_caps_response_packet_without_error() {
        let mut dvc_manager = DvcManager::with_allowed_channels(Vec::new());
        let result_message = dvc_manager
            .process(PeerSide::Client, DRDYNVC_WITH_CAPS_RESPONSE_PACKET.as_ref())
            .unwrap();

        assert_eq!(None, result_message);
    }

    #[test]
    fn dvc_manager_reads_dvc_create_response_packet_without_error() {
        let mut dvc_manager = DvcManager::with_allowed_channels(Vec::new());
        let result_message = dvc_manager
            .process(PeerSide::Client, DRDYNVC_WITH_CREATE_RESPONSE_PACKET.as_ref())
            .unwrap();

        assert_eq!(None, result_message);
    }

    #[test]
    fn dvc_manager_reads_dvc_close_request_packet_without_error() {
        let mut dvc_manager = DvcManager::with_allowed_channels(Vec::new());
        let result_message = dvc_manager
            .process(PeerSide::Server, DRDYNVC_WITH_CLOSE_PACKET.as_ref())
            .unwrap();

        assert_eq!(None, result_message);
    }

    #[test]
    fn dvc_manager_fails_reading_vc_packet_with_invalid_data_length() {
        let mut dvc_manager = DvcManager::with_allowed_channels(Vec::new());
        match dvc_manager.process(PeerSide::Client, VC_PACKET_WITH_INVALID_TOTAL_DATA_LENGTH.as_ref()) {
            Err(vc::ChannelError::InvalidChannelTotalDataLength) => (),
            res => panic!(
                "Expected ChannelError::InvalidChannelTotalDataLength error, got: {:?}",
                res
            ),
        }
    }

    #[test]
    fn dvc_manager_creates_dv_channel() {
        let mut dvc_manager = get_dvc_manager_with_got_create_request_pdu();
        let result_message = dvc_manager
            .process(PeerSide::Client, DRDYNVC_WITH_CREATE_RESPONSE_PACKET.as_ref())
            .unwrap();

        assert_eq!(None, result_message);

        let channel_name = dvc_manager.dynamic_channels.get(&CHANNEL_ID).unwrap().name.clone();
        assert_eq!(CHANNEL_NAME, channel_name);

        let channel = dvc_manager.pending_dynamic_channels.get(&CHANNEL_ID);
        assert!(channel.is_none());
    }

    #[test]
    fn dvc_manager_removes_channel_during_create_response() {
        let mut dvc_manager = get_dvc_manager_with_got_create_request_pdu();
        let result_message = dvc_manager
            .process(PeerSide::Client, DRDYNVC_WITH_FAILED_CREATION_STATUS_PACKET.as_ref())
            .unwrap();

        assert_eq!(None, result_message);

        let channel = dvc_manager.pending_dynamic_channels.get(&CHANNEL_ID);
        assert!(channel.is_none());

        assert!(dvc_manager.dynamic_channels.is_empty());
    }

    #[test]
    fn dvc_manager_does_not_remove_channel_during_create_response() {
        let mut dvc_manager = get_dvc_manager_with_created_channel();
        let channel = dvc_manager.dynamic_channels.get(&CHANNEL_ID);
        assert!(channel.is_some());

        let result_message = dvc_manager
            .process(PeerSide::Client, DRDYNVC_WITH_CREATE_RESPONSE_PACKET.as_ref())
            .unwrap();

        assert_eq!(None, result_message);

        let channel = dvc_manager.dynamic_channels.get(&CHANNEL_ID);
        assert!(channel.is_some());
    }

    #[test]
    fn dvc_manager_removes_dv_channel() {
        let mut dvc_manager = get_dvc_manager_with_created_channel();
        let channel = dvc_manager.dynamic_channels.get(&CHANNEL_ID);
        assert!(channel.is_some());

        let result_message = dvc_manager
            .process(PeerSide::Client, DRDYNVC_WITH_CLOSE_PACKET.as_ref())
            .unwrap();

        assert_eq!(None, result_message);

        let channel = dvc_manager.dynamic_channels.get(&CHANNEL_ID);
        assert!(channel.is_none());
    }

    #[test]
    fn dvc_manager_reads_complete_message() {
        let mut dvc_manager = get_dvc_manager_with_created_channel();
        let channel = dvc_manager.dynamic_channels.get(&CHANNEL_ID);
        assert!(channel.is_some());

        let result_message = dvc_manager
            .process(PeerSide::Client, DRDYNVC_WITH_COMPLETE_DATA_PACKET.as_ref())
            .unwrap();

        assert_eq!(
            RAW_UNFRAGMENTED_DATA_BUFFER.as_ref(),
            result_message.unwrap().as_slice()
        );
    }

    #[test]
    fn dvc_manager_reads_fragmented_message() {
        let mut dvc_manager = get_dvc_manager_with_created_channel();
        let channel = dvc_manager.dynamic_channels.get(&CHANNEL_ID);
        assert!(channel.is_some());

        let result_message = dvc_manager
            .process(PeerSide::Server, DRDYNVC_WITH_DATA_FIRST_PACKET.as_ref())
            .unwrap();
        assert_eq!(None, result_message);

        let result_message = dvc_manager
            .process(PeerSide::Server, DRDYNVC_WITH_DATA_LAST_PACKET.as_ref())
            .unwrap();

        assert_eq!(RAW_FRAGMENTED_DATA_BUFFER.as_ref(), result_message.unwrap().as_slice());
    }

    fn get_dvc_manager_with_created_channel() -> DvcManager {
        let mut dvc_manager = DvcManager::with_allowed_channels(vec![CHANNEL_NAME.to_string()]);
        dvc_manager
            .process(PeerSide::Server, DRDYNVC_WITH_CREATE_REQUEST_PACKET.as_ref())
            .unwrap();

        dvc_manager
            .process(PeerSide::Client, DRDYNVC_WITH_CREATE_RESPONSE_PACKET.as_ref())
            .unwrap();

        dvc_manager
    }

    fn get_dvc_manager_with_got_create_request_pdu() -> DvcManager {
        let mut dvc_manager = DvcManager::with_allowed_channels(vec![CHANNEL_NAME.to_string()]);
        dvc_manager
            .process(PeerSide::Server, DRDYNVC_WITH_CREATE_REQUEST_PACKET.as_ref())
            .unwrap();

        let channel = dvc_manager.pending_dynamic_channels.get(&CHANNEL_ID).unwrap();
        assert_eq!(CHANNEL_NAME, channel.name);

        assert!(dvc_manager.dynamic_channels.is_empty());

        dvc_manager
    }
}
