use std::{sync::{Arc, Mutex}, net::SocketAddr};
use crate::interceptor::{PeerInfo, MessageReader, PacketInterceptor};
use slog_scope::debug;
use crate::plugin_manager::{PLUGIN_MANAGER, PacketsParser, Recorder};

#[derive(Clone)]
pub struct PcapRecordingInterceptor {
    server_info: Arc<Mutex<PeerInfo>>,
    client_info: Arc<Mutex<PeerInfo>>,
    packets_parser: Arc<Mutex<Option<PacketsParser>>>,
    recorder: Arc<Mutex<Option<Recorder>>>,
}

impl PcapRecordingInterceptor {
    pub fn new(server_addr: SocketAddr, client_addr: SocketAddr, association_id: String, candidate_id: String) -> Self {
        debug!("Recording Interceptor was created");
        let recording_plugin = PLUGIN_MANAGER.lock().unwrap().get_recording_plugin();
        if let Some(recorder) = &recording_plugin {
            let filename = format!(
                "{}-to-{}",
                association_id,
                candidate_id
            );
            recorder.set_filename(filename.as_str());
        }

        let interceptor = PcapRecordingInterceptor {
            server_info: Arc::new(Mutex::new(PeerInfo::new(server_addr))),
            client_info: Arc::new(Mutex::new(PeerInfo::new(client_addr))),
            packets_parser: Arc::new(Mutex::new(PLUGIN_MANAGER.lock().unwrap().get_parsing_packets_plugin())),
            recorder: Arc::new(Mutex::new(recording_plugin)),
        };

        interceptor
    }

    pub fn set_recording_directory(&mut self, directory: &str) {
        let rec = self.recorder.lock().unwrap();
        if let Some(recorder) = rec.as_ref() {
            recorder.set_directory(directory);
        }
    }
}

impl PacketInterceptor for PcapRecordingInterceptor {
    fn on_new_packet(&mut self, source_addr: Option<SocketAddr>, data: &[u8]) {
        debug!("New packet intercepted. Packet size = {}", data.len());

        let mut server_info = self.server_info.lock().unwrap();

        let mut option_parser = self.packets_parser.lock().unwrap();
        let mut option_recorder = self.recorder.lock().unwrap();
        let is_from_server = source_addr.unwrap() == server_info.addr;

        if option_parser.is_some() {
            let mut parser = option_parser.as_ref().unwrap();
            let mut message_id: u32 = 0;

            let parse_res = parser.parse_message(data, data.len(), is_from_server);
            let status = parse_res.0;
            message_id = parse_res.1;

            if !parser.is_message_constructed() {
                return;
            } else if message_id == PacketsParser::NOW_UPDATE_MSG_ID {
                let size = parser.get_size();
                let mut image_data = parser.get_image_data();
                if option_recorder.is_some() {
                    let mut recorder = option_recorder.as_ref().unwrap();
                    recorder.set_size(size.width, size.height);
                    recorder.update_recording(image_data);
                }
            }

            if status < data.len() {
                drop(server_info);
                drop(option_parser);
                drop(option_recorder);
                self.on_new_packet(source_addr, &data[status..]);
            }
        }
    }

    fn get_interceptor_clone(&self) -> Box<dyn PacketInterceptor> {
        Box::new(self.clone())
    }
}
