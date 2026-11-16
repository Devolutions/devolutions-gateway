//! The security context of the connected named-pipe client.
//!
//! The process that connected is not necessarily the one writing: a handle can be inherited or duplicated.
//! The grant route checks the pipe's impersonation token, which Windows associates with the last message read.

use std::os::windows::io::AsRawHandle as _;

use anyhow::{Context as _, bail};
use tokio::net::windows::named_pipe::NamedPipeServer;
use win_api_wrappers::handle::HandleWrapper as _;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::thread::Thread;
use win_api_wrappers::token::Token;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    SECURITY_IMPERSONATION_LEVEL, SecurityIdentification, TOKEN_QUERY, TokenImpersonationLevel,
};

use crate::impersonation::ThreadImpersonation;

#[derive(Clone)]
pub(crate) struct PipeIdentity(Source);

#[derive(Clone)]
enum Source {
    // UNTESTED: The route cannot outlive the pipe that owns this handle; a reused handle could identify another client.
    // Check cancellation and handle reuse when changing connection serving.
    Pipe(usize),
    #[cfg(test)]
    Fixed(Sid),
}

impl PipeIdentity {
    pub(crate) fn of(server: &NamedPipeServer) -> Self {
        Self(Source::Pipe(server.as_raw_handle() as usize))
    }

    #[cfg(test)]
    pub(crate) fn fixed(sid: Sid) -> Self {
        Self(Source::Fixed(sid))
    }

    /// The user of the client security context associated with the last message read from the pipe.
    ///
    /// The thread reverts to its own identity before this returns.
    ///
    /// UNTESTED: A delegated handle is checked against the client security context Windows presents.
    /// The check does not identify the writing process; exercise cross-user delegation when changing it.
    pub(crate) fn current_user_sid(&self) -> anyhow::Result<Sid> {
        match &self.0 {
            Source::Pipe(handle) => {
                let _impersonation = ThreadImpersonation::enter_named_pipe_client(HANDLE(*handle as *mut _))?;
                let token = Thread::current()
                    .token(TOKEN_QUERY, true)
                    .context("failed to open the pipe client impersonation token")?;
                if impersonation_level(&token)?.0 < SecurityIdentification.0 {
                    bail!("pipe client does not allow identification");
                }
                Ok(token
                    .sid_and_attributes()
                    .context("failed to query the pipe client user")?
                    .sid)
            }
            #[cfg(test)]
            Source::Fixed(sid) => Ok(sid.clone()),
        }
    }
}

fn impersonation_level(token: &Token) -> anyhow::Result<SECURITY_IMPERSONATION_LEVEL> {
    let mut level = SECURITY_IMPERSONATION_LEVEL::default();
    let mut returned = 0;

    // SAFETY: The token is open for query and the buffer has the size of the requested information.
    unsafe {
        windows::Win32::Security::GetTokenInformation(
            token.handle().raw(),
            TokenImpersonationLevel,
            Some((&raw mut level).cast()),
            u32::try_from(size_of::<SECURITY_IMPERSONATION_LEVEL>()).expect("impersonation level size fits in u32"),
            &mut returned,
        )
    }
    .context("failed to query the pipe client impersonation level")?;

    Ok(level)
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

    use super::*;

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn a_connected_pipe_reports_the_client_security_context() {
        let name = format!(r"\\.\pipe\now-broker-identity-test-{}", std::process::id());
        let server = ServerOptions::new().create(&name).expect("create pipe");
        let mut client = ClientOptions::new().open(&name).expect("open pipe");
        server.connect().await.expect("connect");
        client.write_all(b"x").await.expect("write");
        server.readable().await.expect("readable");
        let mut byte = [0u8; 1];
        server.try_read(&mut byte).expect("read");

        let sid = PipeIdentity::of(&server).current_user_sid().expect("pipe identity");

        let expected = crate::auth::PipeClient::from_current_process().expect("current process");
        assert_eq!(&sid, expected.user_sid());
        crate::impersonation::tests::assert_thread_not_impersonating();
    }
}
