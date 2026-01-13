use std::num::{NonZeroU16, NonZeroUsize};
use std::time::Duration;

use bytes::Bytes;
use ironrdp::server::{
    BitmapUpdate, DesktopSize, DisplayUpdate, PixelFormat, RdpServerDisplay, RdpServerDisplayUpdates,
};

const WIDTH: u16 = 1024;
const HEIGHT: u16 = 1024;

pub(crate) struct DisplayHandler;

impl DisplayHandler {
    pub(crate) fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for DisplayHandler {
    async fn size(&mut self) -> DesktopSize {
        DesktopSize {
            width: WIDTH,
            height: HEIGHT,
        }
    }

    async fn updates(&mut self) -> anyhow::Result<Box<dyn RdpServerDisplayUpdates>> {
        Ok(Box::new(DisplayUpdates))
    }
}

struct DisplayUpdates;

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for DisplayUpdates {
    async fn next_update(&mut self) -> anyhow::Result<Option<DisplayUpdate>> {
        use rand::Rng as _;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut rng = rand::rngs::OsRng;

        let top: u16 = rng.gen_range(0..HEIGHT);
        let height = NonZeroU16::new(rng.gen_range(1..=HEIGHT - top)).expect("never zero");
        let left: u16 = rng.gen_range(0..WIDTH);
        let width = NonZeroU16::new(rng.gen_range(1..=WIDTH - left)).expect("never zero");

        let data: Vec<u8> = std::iter::repeat_n(
            [rng.r#gen(), rng.r#gen(), rng.r#gen(), 255],
            usize::from(width.get()) * usize::from(height.get()),
        )
        .flatten()
        .collect();

        trace!(left, top, width, height, "BitmapUpdate");

        let bitmap = BitmapUpdate {
            x: left,
            y: top,
            width,
            height,
            format: PixelFormat::BgrA32,
            stride: NonZeroUsize::new(usize::from(width.get()) * 4).expect("stride is never zero"), // 4 bytes per pixel for BgrA32
            data: Bytes::from(data),
        };

        Ok(Some(DisplayUpdate::Bitmap(bitmap)))
    }
}
