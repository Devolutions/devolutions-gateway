use std::io;

use ironrdp::{
    dvc::gfx::{zgfx, ServerPdu},
    PduParsing,
};
use slog_scope::trace;

use super::DynamicChannelDataHandler;
use crate::interceptor::PduSource;

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
        mut complete_data: Vec<u8>,
        pdu_source: PduSource,
    ) -> Result<Vec<u8>, io::Error> {
        if let PduSource::Server = pdu_source {
            self.decompressed_buffer.clear();
            self.decompressor
                .decompress(complete_data.as_slice(), &mut self.decompressed_buffer)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to decompress ZGFX: {:?}", e)))?;
            let gfx_pdu = ServerPdu::from_buffer(self.decompressed_buffer.as_slice())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to decode GFX PDU: {:?}", e)))?;
            trace!("Got GFX PDU: {:x?}", gfx_pdu);

            complete_data.resize(self.decompressed_buffer.len(), 0);
            complete_data.clone_from_slice(self.decompressed_buffer.as_slice());
        }

        Ok(complete_data)
    }
}
