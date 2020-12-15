use byteorder::{LittleEndian, ReadBytesExt};
use std::net::SocketAddr;

pub mod pcap;
pub mod rdp;

pub trait PacketInterceptor: Send + Sync {
    fn on_new_packet(&mut self, source_addr: Option<SocketAddr>, data: &[u8]);
}

pub trait MessageReader: Send + Sync {
    fn get_messages(&mut self, data: &mut Vec<u8>, source: PduSource) -> Vec<Vec<u8>>;
}

#[derive(Copy, Clone, Debug)]
pub enum PduSource {
    Client,
    Server,
}

pub struct PeerInfo {
    pub addr: SocketAddr,
    pub sequence_number: u32,
    pub data: Vec<u8>,
}

impl PeerInfo {
    pub fn new(addr: SocketAddr) -> Self {
        PeerInfo {
            addr,
            sequence_number: 0,
            data: Vec::new(),
        }
    }
}

pub struct UnknownMessageReader;
impl MessageReader for UnknownMessageReader {
    fn get_messages(&mut self, data: &mut Vec<u8>, _source: PduSource) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        result.push(data.clone());
        data.clear();
        result
    }
}

pub struct WaykMessageReader;
impl MessageReader for WaykMessageReader {
    fn get_messages(&mut self, data: &mut Vec<u8>, _source: PduSource) -> Vec<Vec<u8>> {
        let mut messages = Vec::new();

        loop {
            let msg_size = {
                let mut cursor = std::io::Cursor::new(&data);
                if let Ok(header) = cursor.read_u32::<LittleEndian>() {
                    if header & 0x8000_0000 != 0 {
                        (header & 0x0000_FFFF) as usize + 4
                    } else {
                        (header & 0x07FF_FFFF) as usize + 6
                    }
                } else {
                    break;
                }
            };

            if data.len() >= msg_size {
                let drain = data.drain(..msg_size);
                let mut new_message = Vec::new();
                for x in drain {
                    new_message.push(x);
                }
                messages.push(new_message);
            } else {
                break;
            }
        }

        messages
    }
}
