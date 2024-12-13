pub mod config;
pub mod debug;
pub mod reopenable;
pub(crate) mod streamer;

pub use config::StreamingConfig;
pub use streamer::reopenable_file::ReOpenableFile;
pub use streamer::signal_writer::SignalWriter;
pub use streamer::{webm_stream, Signal};
// We need ebml_iterable for TagIterator::emit_master_end_when_eof method
use ebml_iterable as _;
