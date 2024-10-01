use ironrdp::core::{Decode, ReadCursor};
use now_proto_pdu::{NowHeader, NowMessage};

enum NowFrameState {
    Header,
    Body(NowHeader),
}

/// Reconstructs Now messages from a stream of bytes.
pub struct NowMessageDissector {
    pdu_body_buffer: Vec<u8>,
    read_state: NowFrameState,
}

impl Default for NowMessageDissector {
    fn default() -> Self {
        Self {
            pdu_body_buffer: Vec::new(),
            read_state: NowFrameState::Header,
        }
    }
}

impl NowMessageDissector {
    pub fn dissect(&mut self, data_chunk: &[u8]) -> Result<Vec<NowMessage>, anyhow::Error> {
        let mut messages = Vec::new();

        self.pdu_body_buffer.extend_from_slice(data_chunk);

        'dissect_messages: loop {
            match &self.read_state {
                NowFrameState::Header if self.pdu_body_buffer.len() < NowHeader::FIXED_PART_SIZE => {
                    // More data needed to read header
                    break 'dissect_messages;
                }
                NowFrameState::Header => {
                    // We have enough data in the buffer to read the header
                    let mut data_chunk = ReadCursor::new(&self.pdu_body_buffer);
                    let header = NowHeader::decode(&mut data_chunk).expect("Failed to read message header");

                    let is_empty_chunk = header.size == 0;
                    self.read_state = NowFrameState::Body(header);

                    if data_chunk.remaining().is_empty() && !is_empty_chunk {
                        // Need more data to read the body
                        break 'dissect_messages;
                    }

                    continue 'dissect_messages;
                }
                NowFrameState::Body(header) => {
                    let expected_message_size = header.size as usize + NowHeader::FIXED_PART_SIZE;

                    if self.pdu_body_buffer.len() < expected_message_size {
                        // More data needed to read the body
                        break 'dissect_messages;
                    }

                    // We have enough data in the buffer to read the body
                    let data_remaining = {
                        let mut cursor = ReadCursor::new(&self.pdu_body_buffer);
                        let message = NowMessage::decode(&mut cursor).expect("Failed to read message");
                        messages.push(message);

                        !cursor.remaining().is_empty()
                    };

                    // Remove the processed message from the buffer.
                    // We need to continue process the chunk in case there are more messages in it.
                    self.pdu_body_buffer.drain(0..expected_message_size);

                    self.read_state = NowFrameState::Header;

                    // No remaining data left
                    if !data_remaining {
                        // No more data to process
                        break 'dissect_messages;
                    }
                }
            }
        }

        Ok(messages)
    }
}
