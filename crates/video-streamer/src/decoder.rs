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
    dimensions: Option<Dimensions>,
}

impl InputDecoder {
    pub(crate) fn new(codec: VpxCodec, threads: u32) -> Self {
        Self {
            codec,
            threads,
            decoder: None,
            dimensions: None,
        }
    }

    pub(crate) fn decode<'decoder>(
        &'decoder mut self,
        data: &[u8],
        key_frame: bool,
    ) -> anyhow::Result<Option<DecodedFrame<'decoder>>> {
        if key_frame {
            self.dimensions = Some(frame_dimensions(data, self.codec)?);
        }

        if self.decoder.is_none() {
            if self.dimensions.is_none() {
                return Ok(None);
            }
            self.decoder = Some(
                VpxDecoder::builder()
                    .threads(self.threads)
                    .width(0)
                    .height(0)
                    .codec(self.codec)
                    .build()?,
            );
        }

        let dimensions = self.dimensions.context("decoded frame dimensions are missing")?;
        let decoder = self.decoder.as_mut().context("input decoder is missing")?;
        decoder.decode(data)?;
        let image = decoder.next_frame()?;
        Ok(Some(DecodedFrame { image, dimensions }))
    }
}

fn frame_dimensions(frame: &[u8], codec: VpxCodec) -> anyhow::Result<Dimensions> {
    match codec {
        VpxCodec::VP8 => vp8_dimensions(frame),
        VpxCodec::VP9 => vp9_dimensions(frame),
    }
}

fn vp8_dimensions(frame: &[u8]) -> anyhow::Result<Dimensions> {
    anyhow::ensure!(frame.len() >= 10, "VP8 key frame is too short");
    anyhow::ensure!(frame[0] & 1 == 0, "VP8 frame is not a key frame");
    anyhow::ensure!(frame[3..6] == [0x9d, 0x01, 0x2a], "VP8 key frame sync code is invalid");

    let width = u16::from_le_bytes([frame[6], frame[7]]) & 0x3fff;
    let height = u16::from_le_bytes([frame[8], frame[9]]) & 0x3fff;
    anyhow::ensure!(width > 0 && height > 0, "VP8 key frame dimensions are invalid");

    Ok(Dimensions {
        width: u32::from(width),
        height: u32::from(height),
    })
}

fn vp9_dimensions(frame: &[u8]) -> anyhow::Result<Dimensions> {
    let mut bits = BitReader::new(frame);
    anyhow::ensure!(bits.read(2)? == 0b10, "VP9 frame marker is invalid");

    let profile_low = bits.read(1)?;
    let profile_high = bits.read(1)?;
    let profile = profile_low | (profile_high << 1);
    if profile == 3 {
        anyhow::ensure!(bits.read(1)? == 0, "VP9 reserved profile bit is invalid");
    }

    anyhow::ensure!(bits.read(1)? == 0, "VP9 frame references an existing frame");
    anyhow::ensure!(bits.read(1)? == 0, "VP9 frame is not a key frame");
    bits.skip(2)?;
    anyhow::ensure!(bits.read(24)? == 0x49_83_42, "VP9 key frame sync code is invalid");

    if profile >= 2 {
        bits.skip(1)?;
    }
    let color_space = bits.read(3)?;
    if color_space != 7 {
        bits.skip(1)?;
        if profile == 1 || profile == 3 {
            bits.skip(3)?;
        }
    } else if profile == 1 || profile == 3 {
        bits.skip(1)?;
    }

    let width = bits.read(16)?.checked_add(1).context("VP9 width overflow")?;
    let height = bits.read(16)?.checked_add(1).context("VP9 height overflow")?;

    Ok(Dimensions { width, height })
}

struct BitReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read(&mut self, count: usize) -> anyhow::Result<u32> {
        anyhow::ensure!(count <= 32, "bit read is too wide");
        let end = self.position.checked_add(count).context("bit position overflow")?;
        anyhow::ensure!(end <= self.bytes.len() * 8, "VP9 key frame header is truncated");

        let mut value = 0;
        while self.position < end {
            let byte = self.bytes[self.position / 8];
            let shift = 7 - (self.position % 8);
            value = (value << 1) | u32::from((byte >> shift) & 1);
            self.position += 1;
        }
        Ok(value)
    }

    fn skip(&mut self, count: usize) -> anyhow::Result<()> {
        self.read(count).map(|_| ())
    }
}
