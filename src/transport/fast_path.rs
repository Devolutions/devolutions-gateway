use std::io;

use bytes::BytesMut;
use ironrdp::{parse_fast_path_header, FastPathError};
use tokio::codec::{Decoder, Encoder};

#[derive(Default)]
pub struct FastPathTransport;

impl Decoder for FastPathTransport {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match parse_fast_path_header(buf.as_ref()) {
            Ok((_, len)) => {
                if buf.len() < usize::from(len) {
                    Ok(None)
                } else {
                    let fast_path = buf.split_to(usize::from(len));

                    Ok(Some(fast_path))
                }
            }
            Err(FastPathError::NullLength { bytes_read }) => {
                buf.split_to(bytes_read);

                Ok(None)
            }
            Err(FastPathError::IOError(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(FastPathError::IOError(e)) => Err(e),
        }
    }
}

impl Encoder for FastPathTransport {
    type Item = BytesMut;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        buf.extend_from_slice(item.as_ref());

        Ok(())
    }
}
