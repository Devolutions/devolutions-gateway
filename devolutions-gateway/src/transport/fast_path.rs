use std::io;

use bytes::{Buf, BytesMut};
use ironrdp::fast_path::{FastPathError, FastPathHeader};
use ironrdp::PduParsing;
use tokio_util::codec::{Decoder, Encoder};

// FIXME: this is not a "transport" but a codec to apply above a transport
// (this is also only used as part of the RDP connection sequence)

#[derive(Default)]
pub struct FastPathTransport;

impl Decoder for FastPathTransport {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match FastPathHeader::from_buffer(buf.as_ref()) {
            Ok(header) => {
                let packet_length = header.buffer_length() + header.data_length;

                if buf.len() < packet_length {
                    Ok(None)
                } else {
                    let fast_path = buf.split_to(packet_length);

                    Ok(Some(fast_path))
                }
            }
            Err(FastPathError::NullLength { bytes_read }) => {
                buf.advance(bytes_read);

                Ok(None)
            }
            Err(FastPathError::IOError(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(FastPathError::IOError(e)) => Err(e),
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, format!("{e}"))),
        }
    }
}

impl Encoder<BytesMut> for FastPathTransport {
    type Error = io::Error;

    fn encode(&mut self, item: BytesMut, buf: &mut BytesMut) -> Result<(), Self::Error> {
        buf.extend_from_slice(item.as_ref());

        Ok(())
    }
}
