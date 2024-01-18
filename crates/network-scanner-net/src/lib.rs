pub mod async_io;
pub mod async_raw_socket;

#[derive(Debug, thiserror::Error)]
pub enum ScannnerNetError {
    #[error("std::io::Error")]
    StdIoError(#[from] std::io::Error),

    #[error("async run time has failed")]
    AsyncRuntimeError(#[from] anyhow::Error),
}
