use std::io;

use bytes::BytesMut;
use ironrdp::{McsPdu, PduParsing};
use tokio::codec::{Decoder, Encoder};

use crate::transport::x224;

#[derive(Default)]
pub struct McsTransport {
    x224_transport: x224::DataTransport,
}

impl Decoder for McsTransport {
    type Item = ironrdp::McsPdu;
    type Error = io::Error;

    fn decode(&mut self, mut buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if let Some(data) = self.x224_transport.decode(&mut buf)? {
            Ok(Some(McsPdu::from_buffer(data.as_ref())?))
        } else {
            Ok(None)
        }
    }
}

impl Encoder for McsTransport {
    type Item = ironrdp::McsPdu;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, mut buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut item_buffer = BytesMut::with_capacity(item.buffer_length());
        item_buffer.resize(item.buffer_length(), 0x00);
        item.to_buffer(item_buffer.as_mut())?;

        self.x224_transport.encode(item_buffer, &mut buf)
    }
}

#[derive(Default)]
pub struct SendDataContextTransport {
    x224_transport: x224::DataTransport,
}

impl Decoder for SendDataContextTransport {
    type Item = (ironrdp::McsPdu, BytesMut);
    type Error = io::Error;

    fn decode(&mut self, mut buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if let Some(mut data) = self.x224_transport.decode(&mut buf)? {
            let mcs_pdu = McsPdu::from_buffer(data.as_ref())?;
            match mcs_pdu {
                McsPdu::SendDataIndication(ref send_data_context) | McsPdu::SendDataRequest(ref send_data_context) => {
                    data.split_to(data.len() - send_data_context.pdu_length);

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

impl Encoder for SendDataContextTransport {
    type Item = (ironrdp::McsPdu, Vec<u8>);
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, mut buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut item_buffer = BytesMut::with_capacity(item.0.buffer_length() + item.1.len());
        item_buffer.resize(item.0.buffer_length(), 0x00);
        item.0.to_buffer(item_buffer.as_mut())?;
        item_buffer.extend_from_slice(&item.1);

        self.x224_transport.encode(item_buffer, &mut buf)
    }
}
