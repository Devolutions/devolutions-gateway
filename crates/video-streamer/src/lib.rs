// Compile-time gated diagnostics to keep production logs clean.
#[cfg(feature = "perf-diagnostics")]
macro_rules! perf_trace {
    ($($tt:tt)*) => {
        tracing::trace!($($tt)*)
    };
}

#[cfg(not(feature = "perf-diagnostics"))]
macro_rules! perf_trace {
    ($($tt:tt)*) => {};
}

#[cfg(feature = "perf-diagnostics")]
macro_rules! perf_debug {
    ($($tt:tt)*) => {
        tracing::debug!($($tt)*)
    };
}

#[cfg(not(feature = "perf-diagnostics"))]
macro_rules! perf_debug {
    ($($tt:tt)*) => {};
}

pub mod config;
pub mod debug;
mod decoder;
mod normalizer;
mod protocol;
pub mod reopenable;
mod session;
pub(crate) mod streamer;

#[macro_use]
extern crate tracing;

#[rustfmt::skip]
pub use config::StreamingConfig;
#[rustfmt::skip]
pub use streamer::reopenable_file::ReOpenableFile;
#[rustfmt::skip]
pub use streamer::signal_writer::SignalWriter;
#[rustfmt::skip]
pub use streamer::webm_stream;
#[rustfmt::skip]
pub use session::{RecordingEvent, SessionConfig, StartAt, stream_session};

#[cfg(feature = "bench")]
pub mod bench_support;
