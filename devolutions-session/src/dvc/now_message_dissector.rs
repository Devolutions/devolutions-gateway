use now_proto_pdu::ironrdp_core::{Decode, DecodeError, DecodeErrorKind, IntoOwned, ReadCursor};
use now_proto_pdu::NowMessage;

/// Reconstructs Now messages from a stream of bytes.
#[derive(Default)]
pub struct NowMessageDissector {
    pdu_body_buffer: Vec<u8>,
}

impl NowMessageDissector {
    pub fn dissect(&mut self, data_chunk: &[u8]) -> Result<Vec<NowMessage<'static>>, anyhow::Error> {
        let mut messages = Vec::new();

        self.pdu_body_buffer.extend_from_slice(data_chunk);

        loop {
            let mut cursor = ReadCursor::new(&self.pdu_body_buffer);
            match NowMessage::decode(&mut cursor) {
                Ok(message) => {
                    messages.push(message.into_owned());
                    let pos = cursor.pos();

                    if pos == self.pdu_body_buffer.len() {
                        // All messages were read, clear the buffer
                        self.pdu_body_buffer.clear();
                        return Ok(messages);
                    }
                    // Remove the read bytes from the buffer
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
