#[derive(Debug, Clone)]
pub struct CpuCount {
    pub(crate) value: usize,
}

impl CpuCount {
    pub fn new(number: usize) -> Self {
        Self { value: number }
    }

    pub fn system_cpus() -> Self {
        Self::default()
    }

    pub fn physical_cpus() -> Self {
        Self {
            value: num_cpus::get_physical(),
        }
    }
}

impl Default for CpuCount {
    fn default() -> Self {
        Self { value: num_cpus::get() }
    }
}

pub struct StreamingConfig {
    pub encoder_threads: CpuCount,
    /// When `true`, the encoder adaptively skips frames when falling behind
    /// real-time, reducing CPU pressure at the cost of lower output frame rate.
    pub adaptive_frame_skip: bool,
}
