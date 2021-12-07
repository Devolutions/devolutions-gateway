use std::io;

use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use crate::transport::{fast_path, x224};

// FIXME: these are not "transport" but codecs to apply above a transport
// (this is also only used as part of the RDP connection sequence)

#[derive(Default)]
pub struct RdpTransport {
    data_transport: x224::DataTransport,
    fast_path_transport: fast_path::FastPathTransport,
}

impl Decoder for RdpTransport {
    type Item = RdpPdu;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.data_transport.decode(buf) {
            Ok(Some(data)) => Ok(Some(RdpPdu::Data(data))),
            Ok(None) => Ok(None),
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(_) => {
                if let Some(fast_path) = self.fast_path_transport.decode(buf)? {
                    Ok(Some(RdpPdu::FastPathBytes(fast_path)))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

impl Encoder<RdpPdu> for RdpTransport {
    type Error = io::Error;

    fn encode(&mut self, item: RdpPdu, buf: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            RdpPdu::Data(data) => self.data_transport.encode(data, buf),
            RdpPdu::FastPathBytes(data) => self.fast_path_transport.encode(data, buf),
        }
    }
}

#[derive(Debug)]
pub enum RdpPdu {
    Data(BytesMut),
    FastPathBytes(BytesMut),
}
