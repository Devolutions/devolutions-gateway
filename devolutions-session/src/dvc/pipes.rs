//! IO redirection pipe setup and overlapped-IO helpers used by the process launcher.

use win_api_wrappers::utils::Pipe;
use windows::Win32::Foundation::{ERROR_IO_PENDING, GetLastError};

pub fn ensure_overlapped_io_result(result: windows::core::Result<()>) -> Result<(), windows::core::Error> {
    if let Err(error) = result {
        // SAFETY: GetLastError is alwayі safe to call
        if unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(error);
        }
    }

    Ok(())
}

pub struct IoRedirectionPipes {
    pub stdout_read_pipe: Pipe,
    pub stdout_write_pipe: Pipe,

    pub stderr_read_pipe: Pipe,
    pub stderr_write_pipe: Pipe,

    pub stdin_read_pipe: Pipe,
    pub stdin_write_pipe: Pipe,
}

impl IoRedirectionPipes {
    pub fn new() -> anyhow::Result<Self> {
        let (stdout_read_pipe, stdout_write_pipe) = Pipe::new_async_stdout_redirection_pipe()?;
        let (stderr_read_pipe, stderr_write_pipe) = Pipe::new_async_stdout_redirection_pipe()?;
        let (stdin_read_pipe, stdin_write_pipe) = Pipe::new_sync_stdin_redirection_pipe()?;

        Ok(IoRedirectionPipes {
            stdout_read_pipe,
            stdout_write_pipe,
            stderr_read_pipe,
            stderr_write_pipe,
            stdin_read_pipe,
            stdin_write_pipe,
        })
    }
}
