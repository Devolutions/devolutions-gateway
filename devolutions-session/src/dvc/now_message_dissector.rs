use anyhow::Context;
use now_proto_pdu::NowMessage;
use now_proto_pdu::ironrdp_core::{Decode, DecodeError, DecodeErrorKind, IntoOwned, ReadCursor, WriteBuf};

/// Reconstructs Now messages from a stream of bytes.
#[derive(Default)]
pub struct NowMessageDissector {
    start_pos: usize,
    pdu_body_buffer: WriteBuf,
}

impl NowMessageDissector {
    pub fn dissect(&mut self, data_chunk: &[u8]) -> Result<Vec<NowMessage<'static>>, anyhow::Error> {
        let mut messages = Vec::new();

        self.pdu_body_buffer.write_slice(data_chunk);

        loop {
            let usable_chunk_size = self
                .pdu_body_buffer
                .filled_len()
                .checked_sub(self.start_pos)
                .context("failed to get usable chunk size")?;

            let mut cursor = ReadCursor::new(&self.pdu_body_buffer.filled()[self.start_pos..]);

            match NowMessage::decode(&mut cursor) {
                Ok(message) => {
                    messages.push(message.into_owned());
                    let pos = cursor.pos();

                    if pos == usable_chunk_size {
                        // All messages were read, clear the buffer
                        self.pdu_body_buffer.clear();
                        self.start_pos = 0;
                        return Ok(messages);
                    }
                    // Remove the read bytes from the buffer
                    self.start_pos += pos;
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
