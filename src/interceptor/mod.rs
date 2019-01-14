use byteorder::{LittleEndian, ReadBytesExt};
use std::net::SocketAddr;

pub mod pcap;

pub struct PeerInfo {
    pub addr: SocketAddr,
    pub sequence_number: u32,
    pub message_reader: Box<MessageReader>,
}

impl PeerInfo {
    pub fn new<T: 'static + MessageReader>(addr: SocketAddr, msg_reader: T) -> Self {
        PeerInfo {
            addr,
            sequence_number: 0,
            message_reader: Box::new(msg_reader),
        }
    }
}

pub trait MessageReader: Send + Sync {
    fn get_next_messages(&mut self, new_data: &Vec<u8>) -> Vec<Vec<u8>>;
}

struct WaykMessageReader {
    data: Vec<u8>,
}

impl WaykMessageReader {
    pub fn new() -> Self {
        WaykMessageReader { data: Vec::new() }
    }
}

impl MessageReader for WaykMessageReader {
    fn get_next_messages(&mut self, new_data: &Vec<u8>) -> Vec<Vec<u8>> {
        let mut messages = Vec::new();

        self.data.append(&mut new_data.clone());

        loop {
            let msg_size = {
                let mut cursor = std::io::Cursor::new(&self.data);
                if let Ok(header) = cursor.read_u32::<LittleEndian>() {
                    if header & 0x8000_0000 != 0 {
                        (header & 0x0000_FFFF) as usize + 4
                    } else {
                        (header & 0x7FFF_FFF) as usize + 6
                    }
                } else {
                    break;
                }
            };

            if self.data.len() >= msg_size {
                let drain = self.data.drain(..msg_size);
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
