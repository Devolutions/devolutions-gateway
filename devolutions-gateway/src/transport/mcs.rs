use std::io;

use bytes::{Buf, BytesMut};
use ironrdp::{McsPdu, PduParsing};
use tokio_util::codec::{Decoder, Encoder};

use crate::transport::x224;

// FIXME: these are not "transport" but codecs to apply above a transport
// (this is also only used as part of the RDP connection sequence)

#[derive(Default)]
pub struct McsTransport {
    x224_transport: x224::DataTransport,
}

impl Decoder for McsTransport {
    type Item = ironrdp::McsPdu;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if let Some(data) = self.x224_transport.decode(buf)? {
            Ok(Some(McsPdu::from_buffer(data.as_ref())?))
        } else {
            Ok(None)
        }
    }
}

impl Encoder<ironrdp::McsPdu> for McsTransport {
    type Error = io::Error;

    fn encode(&mut self, item: ironrdp::McsPdu, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut item_buffer = BytesMut::with_capacity(item.buffer_length());
        item_buffer.resize(item.buffer_length(), 0x00);
        item.to_buffer(item_buffer.as_mut())?;

        self.x224_transport.encode(item_buffer, buf)
    }
}

#[derive(Default)]
pub struct SendDataContextTransport {
    x224_transport: x224::DataTransport,
}

impl Decoder for SendDataContextTransport {
    type Item = (ironrdp::McsPdu, BytesMut);
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if let Some(mut data) = self.x224_transport.decode(buf)? {
            let mcs_pdu = McsPdu::from_buffer(data.as_ref())?;
            match mcs_pdu {
                McsPdu::SendDataIndication(ref send_data_context) | McsPdu::SendDataRequest(ref send_data_context) => {
                    data.advance(data.len() - send_data_context.pdu_length);

                    Ok(Some((mcs_pdu, data)))
                }
                McsPdu::DisconnectProviderUltimatum(reason) => Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("Disconnection request has been received: {:?}", reason),
                )),
                _ => panic!("MCS sequence PDUs cannot be received"),
            }
        } else {
            Ok(None)
        }
    }
}

impl Encoder<(ironrdp::McsPdu, Vec<u8>)> for SendDataContextTransport {
    type Error = io::Error;

    fn encode(&mut self, item: (ironrdp::McsPdu, Vec<u8>), buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut item_buffer = BytesMut::with_capacity(item.0.buffer_length() + item.1.len());
        item_buffer.resize(item.0.buffer_length(), 0x00);
        item.0.to_buffer(item_buffer.as_mut())?;
        item_buffer.extend_from_slice(&item.1);

        self.x224_transport.encode(item_buffer, buf)
    }
}
