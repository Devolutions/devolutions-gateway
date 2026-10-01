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
        let decoder = match &mut self.decoder {
            Some(decoder) => decoder,
            decoder @ None => decoder.insert(
                VpxDecoder::builder()
                    .threads(self.threads)
                    .width(0)
                    .height(0)
                    .codec(self.codec)
                    .build()?,
            ),
        };

        decoder.decode(data)?;
        let image = decoder.next_frame()?;
        let dimensions = Dimensions {
            width: image.width(),
            height: image.height(),
        };
        anyhow::ensure!(
            0 < dimensions.width && 0 < dimensions.height,
            "decoder returned invalid frame dimensions"
        );
        Ok(DecodedFrame { image, dimensions })
    }
}
