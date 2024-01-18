pub mod tokio_raw_socket;
pub mod async_io;

#[derive(Debug,thiserror::Error)]
pub enum ScannnerNetError{

    #[error("std::io::Error")]
    StdIoError(std::io::Error),
    
    #[error("async run time has failed")]
    AsyncRuntimeError(anyhow::Error),
}