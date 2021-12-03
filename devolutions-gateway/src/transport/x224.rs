use bytes::{Buf, BytesMut};
use ironrdp::nego::{NegotiationError, Request, Response};
use ironrdp::{Data, PduParsing};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

// FIXME: these are not "transport" but codecs to apply above a transport
// (this is also only used as part of the RDP connection sequence)

macro_rules! negotiation_try {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(ironrdp::nego::NegotiationError::IOError(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(None);
            }
            Err(e) => return Err(map_negotiation_error(e)),
        }
    };
}

pub struct NegotiationWithClientTransport;

impl Decoder for NegotiationWithClientTransport {
    type Item = Request;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let connection_request = negotiation_try!(Request::from_buffer(buf.as_ref()));
        buf.advance(connection_request.buffer_length());

        Ok(Some(connection_request))
    }
}

impl Encoder<Response> for NegotiationWithClientTransport {
    type Error = io::Error;

    fn encode(&mut self, item: Response, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let item_len = item.buffer_length();
        let len = buf.len();
        buf.resize(len + item_len, 0);

        item.to_buffer(&mut buf[len..]).map_err(map_negotiation_error)
    }
}

#[derive(Default)]
pub struct NegotiationWithServerTransport;

impl Decoder for NegotiationWithServerTransport {
    type Item = Response;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let connection_response = negotiation_try!(Response::from_buffer(buf.as_ref()));
        buf.advance(connection_response.buffer_length());

        Ok(Some(connection_response))
    }
}

impl Encoder<Request> for NegotiationWithServerTransport {
    type Error = io::Error;

    fn encode(&mut self, item: Request, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let item_len = item.buffer_length();
        let len = buf.len();
        buf.resize(len + item_len, 0);

        item.to_buffer(&mut buf[len..]).map_err(map_negotiation_error)
    }
}

#[derive(Default)]
pub struct DataTransport;

impl Decoder for DataTransport {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let data_pdu = negotiation_try!(Data::from_buffer(buf.as_ref()));
        if buf.len() < data_pdu.buffer_length() {
            Ok(None)
        } else {
            buf.advance(data_pdu.buffer_length());
            let data = buf.split_to(data_pdu.data_length);

            Ok(Some(data))
        }
    }
}

impl Encoder<BytesMut> for DataTransport {
    type Error = io::Error;

    fn encode(&mut self, item: BytesMut, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let data_pdu = Data::new(item.len());
        let item_len = data_pdu.buffer_length();
        let len = buf.len();
        buf.resize(len + item_len, 0);
        data_pdu.to_buffer(&mut buf[len..]).map_err(map_negotiation_error)?;
        buf.extend_from_slice(item.as_ref());

        Ok(())
    }
}

fn map_negotiation_error(e: NegotiationError) -> io::Error {
    match e {
        NegotiationError::ResponseFailure(e) => io::Error::new(
            io::ErrorKind::Other,
            format!("Negotiation Response error (code: {:?})", e),
        ),
        NegotiationError::TpktVersionError => {
            io::Error::new(io::ErrorKind::InvalidData, "Negotiation invalid tpkt header version")
        }
        NegotiationError::IOError(e) => e,
    }
}
