use now_proto_pdu::ironrdp_core::{Decode, DecodeError, DecodeErrorKind, IntoOwned, ReadCursor};
use now_proto_pdu::NowMessage;

/// Reconstructs Now messages from a stream of bytes.
pub struct NowMessageDissector {
    pdu_body_buffer: Vec<u8>,
}

impl Default for NowMessageDissector {
    fn default() -> Self {
        Self {
            pdu_body_buffer: Vec::new(),
        }
    }
}

impl NowMessageDissector {
    pub fn dissect(&mut self, data_chunk: &[u8]) -> Result<Vec<NowMessage<'static>>, anyhow::Error> {
        let mut messages = Vec::new();

        // TODO: This is not optimized:
        // - if data_chunk enough for a whole message, we can avoid
        //   pushing it to the buffer and directly decode it.
        // - if data_chunk is empty after all messages were decoded, we can avoid `drain` and
        // clear the buffer instead.

        self.pdu_body_buffer.extend_from_slice(data_chunk);

        loop {
            let mut cursor = ReadCursor::new(&self.pdu_body_buffer);
            match NowMessage::decode(&mut cursor) {
                Ok(message) => {
                    messages.push(message.into_owned());
                    let pos = cursor.pos();
                    self.pdu_body_buffer.drain(0..pos);
                }
                Err(DecodeError {
                    kind: DecodeErrorKind::NotEnoughBytes { .. },
                    ..
                }) => {
                    // Need more data to read the message
                    break;
                }
                Err(err) => {
                    return Err(err.into());
                }
            }
        }

        Ok(messages)
    }
}
