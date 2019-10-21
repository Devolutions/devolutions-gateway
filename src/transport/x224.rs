use std::io;

use bytes::BytesMut;
use ironrdp::{
    nego::{NegotiationError, Request, Response},
    Data, PduParsing,
};
use tokio::codec::{Decoder, Encoder};

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

#[derive(Default)]
pub struct NegotiationWithClientTransport;

impl Decoder for NegotiationWithClientTransport {
    type Item = Request;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let connection_request = negotiation_try!(Request::from_buffer(buf.as_ref()));
        buf.split_to(connection_request.buffer_length());

        Ok(Some(connection_request))
    }
}

impl Encoder for NegotiationWithClientTransport {
    type Item = Response;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut item_buf = BytesMut::with_capacity(item.buffer_length());
        item_buf.resize(item.buffer_length(), 0x00);
        item.to_buffer(item_buf.as_mut()).map_err(map_negotiation_error)?;

        buf.extend_from_slice(item_buf.as_ref());

        Ok(())
    }
}

#[derive(Default)]
pub struct NegotiationWithServerTransport;

impl Decoder for NegotiationWithServerTransport {
    type Item = Response;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let connection_response = negotiation_try!(Response::from_buffer(buf.as_ref()));
        buf.split_to(connection_response.buffer_length());

        Ok(Some(connection_response))
    }
}

impl Encoder for NegotiationWithServerTransport {
    type Item = Request;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut item_buf = BytesMut::with_capacity(item.buffer_length());
        item_buf.resize(item.buffer_length(), 0x00);
        item.to_buffer(item_buf.as_mut()).map_err(map_negotiation_error)?;

        buf.extend_from_slice(item_buf.as_ref());

        Ok(())
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
            buf.split_to(data_pdu.buffer_length() - data_pdu.data_length);
            let data = buf.split_to(data_pdu.data_length);

            Ok(Some(data))
        }
    }
}

impl Encoder for DataTransport {
    type Item = BytesMut;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let data_pdu = Data::new(item.len());
        let mut data_pdu_buf = BytesMut::with_capacity(data_pdu.buffer_length() - data_pdu.data_length);
        data_pdu_buf.resize(data_pdu.buffer_length() - data_pdu.data_length, 0x00);
        data_pdu
            .to_buffer(data_pdu_buf.as_mut())
            .map_err(map_negotiation_error)?;

        buf.extend_from_slice(data_pdu_buf.as_ref());
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
        NegotiationError::IOError(e) => e,
    }
}
