use super::{CompleteDataResult, DynamicChannelDataHandler};
use crate::interceptor::PeerSide;
use ironrdp::dvc::gfx::ServerPdu;
use ironrdp::graphics::zgfx;
use ironrdp::PduParsing;
use std::io;

pub struct Handler {
    decompressor: zgfx::Decompressor,
    decompressed_buffer: Vec<u8>,
}

impl Handler {
    pub fn new() -> Self {
        Self {
            decompressor: zgfx::Decompressor::new(),
            decompressed_buffer: Vec::with_capacity(1024 * 256),
        }
    }
}

impl DynamicChannelDataHandler for Handler {
    fn process_complete_data(
        &mut self,
        complete_data: CompleteDataResult,
        pdu_source: PeerSide,
    ) -> Result<Vec<u8>, io::Error> {
        if let PeerSide::Server = pdu_source {
            let compressed_data = match &complete_data {
                CompleteDataResult::Complete(v) => v,
                CompleteDataResult::Parted(v) => v.as_slice(),
            };

            self.decompressed_buffer.clear();
            self.decompressor
                .decompress(compressed_data, &mut self.decompressed_buffer)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to decompress ZGFX: {e:?}")))?;
            let gfx_pdu = ServerPdu::from_buffer(self.decompressed_buffer.as_slice())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to decode GFX PDU: {e:?}")))?;
            debug!("Got GFX PDU: {:?}", gfx_pdu);

            Ok(self.decompressed_buffer.to_vec())
        } else {
            match complete_data {
                CompleteDataResult::Parted(v) => Ok(v),
                CompleteDataResult::Complete(v) => Ok(v.to_vec()),
            }
        }
    }
}
