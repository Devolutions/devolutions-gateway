pub mod runtime;
pub mod socket;

#[derive(Debug, thiserror::Error)]
pub enum ScannnerNetError {
    #[error("std::io::Error")]
    StdIoError(#[from] std::io::Error),

    #[error("async run time has failed with error: {0}")]
    AsyncRuntimeError(String),
}
