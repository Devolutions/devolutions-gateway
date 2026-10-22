use anyhow::Context as _;
use cadeau::xmf::vpx::{VpxCodec, VpxDecoder, VpxImage};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Dimensions {
    pub width: u32,
    pub height: u32,
}

pub(crate) struct InputDecoder {
    codec: VpxCodec,
    threads: u32,
    // INVARIANT: `picture` points into a frame buffer owned by `decoder`, which stays valid until the next decode.
    // It is cleared before every decode, and it is declared before `decoder` so that it is dropped first.
    picture: Option<VpxImage<'static>>,
    decoder: Option<VpxDecoder>,
}

impl InputDecoder {
    pub(crate) fn new(codec: VpxCodec, threads: u32) -> Self {
        Self {
            codec,
            threads,
            picture: None,
            decoder: None,
        }
    }

    /// Decodes one frame and keeps its picture until the next call.
    pub(crate) fn decode(&mut self, data: &[u8]) -> anyhow::Result<Dimensions> {
        self.picture = None;

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

        // SAFETY: Only the lifetime changes. Per the field invariant, the picture is dropped before the decoder
        // decodes again or is dropped, so it never outlives the frame buffer it points into.
        let image = unsafe { core::mem::transmute::<VpxImage<'_>, VpxImage<'static>>(image) };
        self.picture = Some(image);

        Ok(dimensions)
    }

    /// The picture of the last decoded frame.
    pub(crate) fn picture(&self) -> Option<&VpxImage<'_>> {
        self.picture.as_ref()
    }
}
