use std::io;

use bytes::BytesMut;
use tokio::codec::{Decoder, Encoder};

use crate::transport::{fast_path, x224};

#[derive(Default)]
pub struct RdpTransport {
    data_transport: x224::DataTransport,
    fast_path_transport: fast_path::FastPathTransport,
}

impl Decoder for RdpTransport {
    type Item = RdpPdu;
    type Error = io::Error;

    fn decode(&mut self, mut buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.data_transport.decode(&mut buf) {
            Ok(Some(data)) => Ok(Some(RdpPdu::Data(data))),
            Ok(None) => Ok(None),
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(_) => {
                if let Some(fast_path) = self.fast_path_transport.decode(&mut buf)? {
                    Ok(Some(RdpPdu::FastPathBytes(fast_path)))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

impl Encoder for RdpTransport {
    type Item = RdpPdu;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, mut buf: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            RdpPdu::Data(data) => self.data_transport.encode(data, &mut buf),
            RdpPdu::FastPathBytes(data) => self.fast_path_transport.encode(data, &mut buf),
        }
    }
}

#[derive(Debug)]
pub enum RdpPdu {
    Data(BytesMut),
    FastPathBytes(BytesMut),
}
