use anyhow::Context as _;
use cadeau::xmf::vpx::{VpxCodec, VpxDecoder, VpxImage};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Dimensions {
    pub width: u32,
    pub height: u32,
}

pub(crate) struct DecodedFrame<'decoder> {
    pub image: VpxImage<'decoder>,
    pub dimensions: Dimensions,
}

pub(crate) struct InputDecoder {
    codec: VpxCodec,
    threads: u32,
    decoder: Option<VpxDecoder>,
}

impl InputDecoder {
    pub(crate) fn new(codec: VpxCodec, threads: u32) -> Self {
        Self {
            codec,
            threads,
            decoder: None,
        }
    }

    pub(crate) fn decode<'decoder>(&'decoder mut self, data: &[u8]) -> anyhow::Result<DecodedFrame<'decoder>> {
        if self.decoder.is_none() {
            self.decoder = Some(
                VpxDecoder::builder()
                    .threads(self.threads)
                    .width(0)
                    .height(0)
                    .codec(self.codec)
                    .build()?,
            );
        }

        let decoder = self.decoder.as_mut().context("input decoder is missing")?;
        decoder.decode(data)?;
        let image = decoder.next_frame()?;
        let dimensions = Dimensions {
            width: image.width(),
            height: image.height(),
        };
        anyhow::ensure!(
            dimensions.width > 0 && dimensions.height > 0,
            "decoder returned invalid frame dimensions"
        );
        Ok(DecodedFrame { image, dimensions })
    }
}
