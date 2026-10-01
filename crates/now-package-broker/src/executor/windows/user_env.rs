//! Target user environment used to resolve package manager executables.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::marker::PhantomData;
use std::path::Path;

use anyhow::Context as _;
use tracing::{debug, error, warn};
use win_api_wrappers::handle::HandleWrapper as _;
use win_api_wrappers::token::Token;
use windows::Win32::Security::{
    ImpersonateLoggedOnUser, RevertToSelf, SecurityImpersonation, TOKEN_IMPERSONATE, TOKEN_QUERY, TokenImpersonation,
};

use crate::policy_security::{PathOpener, is_plain_local_drive_path};

/// Environment variables of the target user, with filesystem lookups performed as that user.
///
/// Paths derived from the environment are only looked up when they are plain local drive paths,
/// and lookups run while impersonating the target user instead of the broker service account.
pub(super) struct UserEnv<'a> {
    vars: &'a HashMap<String, String>,
    lookup_token: Option<Token>,
}

impl<'a> UserEnv<'a> {
    /// Use `token`, a token of the target user, for filesystem lookups.
    pub(super) fn for_user(vars: &'a HashMap<String, String>, token: &Token) -> anyhow::Result<Self> {
        let lookup_token = token
            .duplicate(
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                None,
                SecurityImpersonation,
                TokenImpersonation,
            )
            .context("failed to duplicate the target user token for impersonation")?;

        Ok(Self {
            vars,
            lookup_token: Some(lookup_token),
        })
    }

    #[cfg(test)]
    pub(super) fn without_impersonation(vars: &'a HashMap<String, String>) -> Self {
        Self {
            vars,
            lookup_token: None,
        }
    }

    pub(super) fn var(&self, key: &str) -> Option<&'a str> {
        self.vars
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.as_str())
    }

    /// Trimmed, non-empty `PATH` entries.
    pub(super) fn path_dirs(&self) -> impl Iterator<Item = &'a str> {
        self.var("PATH")
            .unwrap_or_default()
            .split(';')
            .map(str::trim)
            .filter(|dir| !dir.is_empty())
    }

    pub(super) fn exists(&self, path: &Path) -> bool {
        self.lookup(path, Path::exists)
    }

    pub(super) fn is_file(&self, path: &Path) -> bool {
        self.lookup(path, Path::is_file)
    }

    fn lookup(&self, path: &Path, check: fn(&Path) -> bool) -> bool {
        if !path.to_str().is_some_and(is_plain_local_drive_path) {
            debug!(path = %path.display(), "Skipped non-local environment-derived path");
            return false;
        }

        match self.as_user(|| check(path)) {
            Ok(found) => found,
            Err(error) => {
                warn!(
                    error = format!("{error:#}"),
                    "Failed to impersonate the target user for a path lookup"
                );
                false
            }
        }
    }

    /// Run `f` while impersonating the target user, when a lookup token is configured.
    fn as_user<T>(&self, f: impl FnOnce() -> T) -> anyhow::Result<T> {
        let Some(token) = &self.lookup_token else {
            return Ok(f());
        };

        let _impersonation = ThreadImpersonation::enter(token)?;
        Ok(f())
    }
}

impl PathOpener for UserEnv<'_> {
    fn open(&self, options: &OpenOptions, path: &Path) -> std::io::Result<File> {
        if !path.to_str().is_some_and(is_plain_local_drive_path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("'{}' is not a plain local drive path", path.display()),
            ));
        }

        self.as_user(|| options.open(path)).map_err(std::io::Error::other)?
    }
}

/// Impersonates a token on the current thread until dropped.
///
/// Blocking-pool threads are reused, so a failed revert aborts the process
/// instead of letting the thread keep running under the impersonated identity.
struct ThreadImpersonation {
    // Impersonation is per thread, so the guard must not move to another thread.
    _not_send: PhantomData<*const ()>,
}

impl ThreadImpersonation {
    fn enter(token: &Token) -> anyhow::Result<Self> {
        // SAFETY: `token` is a live impersonation token opened with TOKEN_QUERY | TOKEN_IMPERSONATE.
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
mod tests {
    use std::path::PathBuf;

    use win_api_wrappers::process::Process;
    use win_api_wrappers::thread::Thread;
    use windows::Win32::Foundation::ERROR_NO_TOKEN;
    use windows::Win32::Security::TOKEN_ALL_ACCESS;

    use super::*;

    fn current_process_token() -> Token {
        Process::current_process()
            .token(TOKEN_ALL_ACCESS)
            .expect("open current process token")
    }

    fn assert_thread_not_impersonating() {
        let Err(error) = Thread::current().token(TOKEN_QUERY, true) else {
            panic!("the thread must not keep an impersonation token");
        };
        let code = error
            .downcast_ref::<windows::core::Error>()
            .map(windows::core::Error::code);
        assert_eq!(code, Some(ERROR_NO_TOKEN.to_hresult()), "{error:#}");
    }

    #[test]
    fn lookups_impersonate_and_always_revert() {
        let vars = HashMap::new();
        let token = current_process_token();
        let env = UserEnv::for_user(&vars, &token).expect("prepare user lookups");
        let exe = std::env::current_exe().expect("current exe");

        assert!(env.is_file(&exe));
        assert!(env.exists(exe.parent().expect("exe parent")));
        assert!(!env.is_file(&exe.with_file_name("missing-broker-test.exe")));
        assert_thread_not_impersonating();
    }

    #[test]
    fn impersonation_guard_reverts_on_panic() {
        let token = current_process_token()
            .duplicate(
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                None,
                SecurityImpersonation,
                TokenImpersonation,
            )
            .expect("duplicate impersonation token");

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

    #[test]
    fn non_local_paths_are_skipped_without_lookup() {
        let vars = HashMap::new();
        let token = current_process_token();
        let env = UserEnv::for_user(&vars, &token).expect("prepare user lookups");

        for path in [
            r"\\server\share\tool.exe",
            r"\\server@80\share\tool.exe",
            r"\\?\C:\Windows\System32\cmd.exe",
            r"\\.\C:\Windows\System32\cmd.exe",
            r"\??\C:\Windows\System32\cmd.exe",
            r"//server/share/tool.exe",
            r"C:Windows\System32\cmd.exe",
            r"tool.exe",
            r"C:\Windows\System32\cmd.exe:stream",
        ] {
            assert!(!env.exists(&PathBuf::from(path)), "{path}");
        }
        assert_thread_not_impersonating();
    }

    #[test]
    fn pinned_executables_are_opened_as_the_user_and_resolve_to_a_local_final_path() {
        let vars = HashMap::new();
        let token = current_process_token();
        let env = UserEnv::for_user(&vars, &token).expect("prepare user lookups");
        let exe = std::env::current_exe().expect("current exe");

        let root = tempfile::tempdir().expect("create pin test directory");
        let junction = root.path().join("bin-link");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(exe.parent().expect("exe parent"))
            .stdout(std::process::Stdio::null())
            .status()
            .expect("spawn mklink");
        assert!(status.success(), "create junction");

        let pinned = crate::policy_security::pin_executable(
            &env,
            &junction.join(exe.file_name().expect("exe file name")),
            "test executable",
        )
        .expect("pin through a local junction");
        assert_thread_not_impersonating();
        let expected = crate::policy_security::final_path_from_handle(&File::open(&exe).expect("open exe"))
            .expect("exe final path");
        assert!(
            crate::policy_security::windows_paths_equal(pinned.path(), &expected),
            "pinned path {} must be the final path of the target",
            pinned.path().display()
        );
        let error = OpenOptions::new()
            .write(true)
            .open(&exe)
            .expect_err("a pinned executable cannot be opened for writing");
        assert_eq!(error.raw_os_error(), Some(32), "{error}");

        drop(pinned);
        std::fs::remove_dir(&junction).expect("remove junction");
    }

    #[test]
    fn pinning_rejects_non_local_paths_without_opening_them() {
        let vars = HashMap::new();
        let token = current_process_token();
        let env = UserEnv::for_user(&vars, &token).expect("prepare user lookups");

        for path in [
            r"\\server\share\tool.exe",
            r"\\?\UNC\server\share\tool.exe",
            r"\\.\C:\Windows\System32\cmd.exe",
        ] {
            let error = crate::policy_security::pin_executable(&env, Path::new(path), "test executable")
                .expect_err("non-local paths must be rejected");
            assert!(
                format!("{error:#}").contains("not a plain local drive path"),
                "{path}: {error:#}"
            );
        }
        assert_thread_not_impersonating();
    }

    #[test]
    fn path_dirs_are_trimmed_and_skip_empty_entries() {
        let vars = HashMap::from([("Path".to_owned(), r" C:\a ;;C:\b;  ;".to_owned())]);
        let env = UserEnv::without_impersonation(&vars);

        assert_eq!(env.path_dirs().collect::<Vec<_>>(), [r"C:\a", r"C:\b"]);
    }
}
