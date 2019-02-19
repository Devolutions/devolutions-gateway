use std::io;

use bytes::BytesMut;
use tokio::codec::{Decoder, Encoder};

use rdp_proto;

pub struct X224Transport {}

impl X224Transport {
    pub fn new() -> X224Transport {
        X224Transport {}
    }
}

macro_rules! io_try {
    ($e:expr) => (match $e {
        Ok(v) => v,
        Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(e) => return Err(e),
    });
}

impl Decoder for X224Transport {
    type Item = (rdp_proto::X224TPDUType, BytesMut);
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut stream = buf.as_ref();
        let len = io_try!(rdp_proto::read_tpkt_len(&mut stream)) as usize;

        if buf.len() < len {
            return Ok(None);
        }

        let (_, code) = io_try!(rdp_proto::parse_tdpu_header(&mut stream));

        let mut tpdu = buf.split_to(len as usize);
        match code {
            rdp_proto::X224TPDUType::Data => tpdu.advance(rdp_proto::TPDU_DATA_LENGTH),
            _ => tpdu.advance(rdp_proto::TPDU_REQUEST_LENGTH),
        }

        Ok(Some((code, tpdu)))
    }
}

impl Encoder for X224Transport {
    type Item = (rdp_proto::X224TPDUType, BytesMut);
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let (code, data) = item;
        let length = rdp_proto::TPDU_REQUEST_LENGTH as u16 + data.len() as u16;

        buf.reserve(length as usize);
        buf.resize(rdp_proto::TPDU_REQUEST_LENGTH, 0);

        let mut buf_slice = buf.as_mut();
        rdp_proto::write_tpkt_header(&mut buf_slice, length)?;
        rdp_proto::write_tpdu_header(
            &mut buf_slice,
            length as u8 - rdp_proto::TPKT_HEADER_LENGTH as u8,
            code,
            0,
        )?;

        buf.extend_from_slice(&data);

        Ok(())
    }
}
