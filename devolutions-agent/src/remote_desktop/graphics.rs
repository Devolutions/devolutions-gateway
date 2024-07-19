use std::num::NonZeroU16;
use std::time::Duration;

use ironrdp::server::{
    BitmapUpdate, DesktopSize, DisplayUpdate, PixelFormat, PixelOrder, RdpServerDisplay, RdpServerDisplayUpdates,
};

const WIDTH: u16 = 1024;
const HEIGHT: u16 = 1024;

pub struct DisplayHandler;

impl DisplayHandler {
    pub fn new() -> Self {
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
    async fn next_update(&mut self) -> Option<DisplayUpdate> {
        use rand::Rng as _;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut rng = rand::rngs::OsRng;

        let top: u16 = rng.gen_range(0..HEIGHT);
        let height = NonZeroU16::new(rng.gen_range(1..=HEIGHT - top)).unwrap();
        let left: u16 = rng.gen_range(0..WIDTH);
        let width = NonZeroU16::new(rng.gen_range(1..=WIDTH - left)).unwrap();

        let data: Vec<u8> = std::iter::repeat([rng.gen(), rng.gen(), rng.gen(), 255])
            .take(usize::from(width.get()) * usize::from(height.get()))
            .flatten()
            .collect();

        trace!(left, top, width, height, "BitmapUpdate");

        let bitmap = BitmapUpdate {
            top,
            left,
            width,
            height,
            format: PixelFormat::BgrA32,
            order: PixelOrder::TopToBottom,
            data,
        };

        Some(DisplayUpdate::Bitmap(bitmap))
    }
}
