//! Thread impersonation helpers.

use std::marker::PhantomData;

use anyhow::Context as _;
use tracing::error;
use win_api_wrappers::handle::HandleWrapper as _;
use win_api_wrappers::token::Token;
use windows::Win32::Security::{
    ImpersonateLoggedOnUser, RevertToSelf, SecurityImpersonation, TOKEN_IMPERSONATE, TOKEN_QUERY, TokenImpersonation,
};

/// Duplicate `token` into an impersonation token usable with [`ThreadImpersonation`].
///
/// `token` must have been opened with `TOKEN_DUPLICATE`.
pub(crate) fn impersonation_token(token: &Token) -> anyhow::Result<Token> {
    token
        .duplicate(
            TOKEN_QUERY | TOKEN_IMPERSONATE,
            None,
            SecurityImpersonation,
            TokenImpersonation,
        )
        .context("failed to duplicate the token for impersonation")
}

/// Impersonates a token on the current thread until dropped.
///
/// Thread-pool threads are reused, so a failed revert aborts the process
/// instead of letting the thread keep running under the impersonated identity.
pub(crate) struct ThreadImpersonation {
    // Impersonation is per thread, so the guard must not move to another thread.
    _not_send: PhantomData<*const ()>,
}

impl ThreadImpersonation {
    /// Impersonate `token`, an impersonation token opened with `TOKEN_QUERY | TOKEN_IMPERSONATE`.
    pub(crate) fn enter(token: &Token) -> anyhow::Result<Self> {
        // SAFETY: `token` is a live token handle; the call fails if it lacks the required access.
        unsafe { ImpersonateLoggedOnUser(token.handle().raw()) }.context("ImpersonateLoggedOnUser failed")?;

        Ok(Self { _not_send: PhantomData })
    }
}

impl Drop for ThreadImpersonation {
    fn drop(&mut self) {
        // SAFETY: RevertToSelf has no preconditions.
        if let Err(error) = unsafe { RevertToSelf() } {
            error!(%error, "Failed to revert thread impersonation");
            std::process::abort();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use win_api_wrappers::process::Process;
    use win_api_wrappers::thread::Thread;
    use windows::Win32::Foundation::ERROR_NO_TOKEN;
    use windows::Win32::Security::TOKEN_ALL_ACCESS;

    use super::*;

    pub(crate) fn current_process_token() -> Token {
        Process::current_process()
            .token(TOKEN_ALL_ACCESS)
            .expect("open current process token")
    }

    pub(crate) fn assert_thread_not_impersonating() {
        let Err(error) = Thread::current().token(TOKEN_QUERY, true) else {
            panic!("the thread must not keep an impersonation token");
        };
        let code = error
            .downcast_ref::<windows::core::Error>()
            .map(windows::core::Error::code);
        assert_eq!(code, Some(ERROR_NO_TOKEN.to_hresult()), "{error:#}");
    }

    #[test]
    fn impersonation_guard_reverts_on_panic() {
        let token = impersonation_token(&current_process_token()).expect("duplicate impersonation token");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _impersonation = ThreadImpersonation::enter(&token).expect("impersonate");
            Thread::current()
                .token(TOKEN_QUERY, true)
                .expect("the thread is impersonating inside the guard");
            panic!("lookup panicked");
        }));

        assert!(result.is_err());
        assert_thread_not_impersonating();
    }
}
