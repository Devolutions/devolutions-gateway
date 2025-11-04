use std::io;

use bytes::BytesMut;
use jmux_proto::{Header, Message};
use tokio_util::codec::{Decoder, Encoder};

pub(crate) struct JmuxCodec;

impl Decoder for JmuxCodec {
    type Item = Message;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        const MAX_RESERVE_CHUNK_IN_BYTES: usize = 8 * 1024; // 8 kiB

        if src.len() < Header::SIZE {
            // Not enough data to read length marker.
            return Ok(None);
        }

        // Read length marker
        let mut length_bytes = [0u8; 2];
        length_bytes.copy_from_slice(&src[1..3]);
        let length = u16::from_be_bytes(length_bytes) as usize;

        if src.len() < length {
            // The full packet has not arrived yet.
            // Reserve more space in the buffer (good performance-wise).
            let additional = core::cmp::min(MAX_RESERVE_CHUNK_IN_BYTES, length - src.len());
            src.reserve(additional);

            // Inform the Framed that more bytes are required to form the next frame.
            return Ok(None);
        }

        // `split_to` is modifying src such that it no longer contains this frame (`advance` could have been used as well)
        let packet_bytes = src.split_to(length).freeze();

        // Parse the JMUX packet contained in this frame
        let packet = Message::decode(packet_bytes).map_err(io::Error::other)?;

        // Hands the frame
        Ok(Some(packet))
    }
}

impl Encoder<Message> for JmuxCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        item.encode(dst).map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code can panic on errors")]

    use super::*;
    use bytes::Bytes;
    use futures_util::StreamExt;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, ReadBuf};
    use tokio_util::codec::FramedRead;

    struct MockAsyncReader {
        raw_msg: Vec<u8>,
    }

    impl AsyncRead for MockAsyncReader {
        fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            if buf.remaining() > 0 {
                let amount = std::cmp::min(buf.remaining(), self.raw_msg.len());
                buf.put_slice(&self.raw_msg[0..amount]);
                self.raw_msg.drain(0..amount);
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    #[tokio::test]
    async fn jmux_decoder() {
        let raw_msg = &[
            100, // msg type
            0, 34, // msg size
            0,  // msg flags
            0, 0, 0, 1, // sender channel id
            0, 0, 4, 0, // initial window size
            4, 0, // maximum packet size
            116, 99, 112, 58, 47, 47, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 58, 52, 52,
            51, // destination url: tcp://google.com:443
        ];

        let expected_message = Message::decode(Bytes::from_static(raw_msg)).unwrap();

        let reader = MockAsyncReader {
            raw_msg: raw_msg.to_vec(),
        };
        let mut framed_reader = FramedRead::new(reader, JmuxCodec);
        let frame = framed_reader.next().await.unwrap().unwrap();

        assert_eq!(expected_message, frame);
    }
}
