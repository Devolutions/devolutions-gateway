use rdp_proto::{parse_fastpath_header, read_tpkt_len};

pub struct RdpMessageReader;
impl RdpMessageReader {
    pub fn get_messages(data: &mut Vec<u8>) -> Vec<Vec<u8>> {
        let mut messages = Vec::new();

        loop {
            let len = match read_tpkt_len(data.as_slice()) {
                Ok(len) => {
                    // tpkt&tpdu
                    len
                }
                _ => {
                    // fastpath
                    if let Ok((_, len)) = parse_fastpath_header(data.as_slice()) {
                        u64::from(len)
                    } else {
                        break;
                    }
                }
            };
            if data.len() >= len as usize {
                let new_message: Vec<u8> = data.drain(..len as usize).collect();
                messages.push(new_message);
            } else {
                break;
            }
        }

        messages
    }
}
