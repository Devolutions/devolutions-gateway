use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{BorrowedHandle, OwnedHandle};
use std::os::windows::process::ExitStatusExt as _;
use std::process::{Command, ExitStatus};

use anyhow::{Context as _, ensure};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout};
use tokio::task::JoinHandle;
use win_api_wrappers::handle::{Handle, HandleWrapper as _};
use win_api_wrappers::process::Process;
use win_api_wrappers::thread::{Thread, ThreadAttributeList, ThreadAttributeType};
use win_api_wrappers::token::Token;
use win_api_wrappers::utils::{Pipe, WideString, environment_block};
use windows::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
use windows::Win32::Globalization::{CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN, CompareStringOrdinal};
use windows::Win32::Security::{LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, LogonUserW};
use windows::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, CreateProcessW,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
};
use windows::core::{PCWSTR, PWSTR};
use zeroize::Zeroizing;

use super::super::process_tree::ProcessTree;
use super::super::protocol::ProcessCredential;

pub(in crate::psu_agent) struct Child {
    process: Process,
    thread: Option<Thread>,
    pub(super) id: u32,
    pub(super) stdin: Option<ChildStdin>,
    pub(super) stdout: Option<ChildStdout>,
    pub(super) stderr: Option<ChildStderr>,
    wait: Option<JoinHandle<std::io::Result<ExitStatus>>>,
    status: Option<ExitStatus>,
}

impl Child {
    pub(super) fn spawn(command: &Command, credential: ProcessCredential) -> anyhow::Result<Self> {
        let username = WideString::from(&credential.username);
        let domain = if !credential.domain.is_empty() {
            Some(credential.domain.as_str())
        } else if credential.username.contains('@') {
            None
        } else {
            Some(".")
        };
        let domain = domain.map(WideString::from).unwrap_or_default();
        let mut password = Zeroizing::new(credential.password.encode_utf16().collect::<Vec<_>>());
        password.push(0);
        let mut token = HANDLE::default();
        // UNTESTED: successful batch logon must select the requested local, domain, or UPN account.
        // Token-spawn tests use the current user; check alternate-account identity on a provisioned Windows host
        // when changing logon.
        // SAFETY: Strings are NUL-terminated, contain no interior NUL, and remain alive for the call.
        unsafe {
            LogonUserW(
                username.as_pcwstr(),
                domain.as_pcwstr(),
                PCWSTR(password.as_ptr()),
                LOGON32_LOGON_BATCH,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        }
        .context("Windows batch logon failed")?;
        drop(password);
        drop(credential);
        // SAFETY: Successful LogonUserW returned a token owned by this function.
        let token = Token::from(unsafe { Handle::new_owned(token) }?);
        Self::spawn_with_token(&token, command)
    }

    fn spawn_with_token(token: &Token, command: &Command) -> anyhow::Result<Self> {
        let mut command_line = command_line(command)?;
        if let Some(directory) = command.get_current_dir() {
            ensure!(
                !directory.as_os_str().encode_wide().any(|character| character == 0),
                "working directory contains a NUL character"
            );
        }
        let current_directory = command.get_current_dir().map(WideString::from).unwrap_or_default();
        let mut environment = environment(token, command)?;

        let (stdin_read, stdin_write) = Pipe::new_anonymous(None, 0)?;
        let (stdout_read, stdout_write) = Pipe::new_anonymous(None, 0)?;
        let (stderr_read, stderr_write) = Pipe::new_anonymous(None, 0)?;
        let parent = HandleParent::new()?;
        let stdin = parent.inherit(stdin_read.handle.raw())?;
        let stdout = parent.inherit(stdout_write.handle.raw())?;
        let stderr = parent.inherit(stderr_write.handle.raw())?;
        let inherited = ThreadAttributeType::HandleList(vec![stdin, stdout, stderr]);
        let parent_attribute = ThreadAttributeType::ParentProcess(&parent.process);
        let mut attributes = ThreadAttributeList::with_count(2)?;
        attributes.update(&inherited)?;
        attributes.update(&parent_attribute)?;
        let mut startup = STARTUPINFOEXW::default();
        let mut desktop = WideString::from("");
        startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).expect("STARTUPINFOEXW size fits in u32");
        // An empty desktop selects the target logon's window station instead of inheriting the service's desktop.
        startup.StartupInfo.lpDesktop = desktop.as_pwstr();
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = stdin;
        startup.StartupInfo.hStdOutput = stdout;
        startup.StartupInfo.hStdError = stderr;
        startup.lpAttributeList = attributes.raw();
        let mut information = PROCESS_INFORMATION::default();

        #[cfg(test)]
        tests::BEFORE_CREATE.with(|callback| {
            if let Some(callback) = callback.take() {
                callback(&parent.process);
            }
        });

        // SAFETY: All buffers, pipe handles, the token and the attribute list remain valid for the call.
        // The handle list restricts inheritance to the three child pipe ends.
        unsafe {
            CreateProcessAsUserW(
                Some(token.handle().raw()),
                PCWSTR::null(),
                Some(PWSTR(command_line.as_mut_ptr())),
                None,
                None,
                true,
                CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                Some(environment.as_mut_ptr().cast()),
                current_directory.as_pcwstr(),
                &startup.StartupInfo,
                &mut information,
            )
        }
        .context("CreateProcessAsUserW failed")?;

        // SAFETY: Successful CreateProcessAsUserW returned two handles owned by this function.
        let process = Process::from(unsafe { Handle::new_owned(information.hProcess) }?);
        // SAFETY: The thread handle is distinct from the process handle and is owned here.
        let thread = Thread::from(unsafe { Handle::new_owned(information.hThread) }?);
        let mut child = Self {
            process,
            thread: Some(thread),
            id: information.dwProcessId,
            stdin: None,
            stdout: None,
            stderr: None,
            wait: None,
            status: None,
        };
        // Child owns the process before any fallible pipe conversion, so failure kills the suspended process.
        child.stdin = Some(ChildStdin::from_std(std::process::ChildStdin::from(owned_pipe(
            &stdin_write,
        )?))?);
        child.stdout = Some(ChildStdout::from_std(std::process::ChildStdout::from(owned_pipe(
            &stdout_read,
        )?))?);
        child.stderr = Some(ChildStderr::from_std(std::process::ChildStderr::from(owned_pipe(
            &stderr_read,
        )?))?);
        Ok(child)
    }

    pub(super) fn attach_tree(&mut self) -> anyhow::Result<ProcessTree> {
        let tree = ProcessTree::attach_native(self.process.handle.raw().0)?;
        self.thread
            .take()
            .context("credentialed process already resumed")?
            .resume()
            .context("failed to resume credentialed process")?;
        Ok(tree)
    }

    pub(super) fn start_kill(&mut self) -> std::io::Result<()> {
        self.process.terminate(1).map_err(std::io::Error::other)
    }

    pub(super) async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        if self.wait.is_none() {
            let process = Process::from(self.process.handle.try_clone().map_err(std::io::Error::other)?);
            self.wait = Some(tokio::task::spawn_blocking(move || {
                process.wait(None).map_err(std::io::Error::other)?;
                process
                    .exit_code()
                    .map(ExitStatus::from_raw)
                    .map_err(std::io::Error::other)
            }));
        }
        // A canceled wait leaves the same waiter in place rather than starting another blocking task.
        let status = self.wait.as_mut().expect("waiter initialized").await??;
        self.status = Some(status);
        Ok(status)
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.status.is_none()
            && let Err(error) = self.start_kill()
        {
            debug!(%error, "Failed to kill credentialed PSU child process on drop");
        }
    }
}

// An explicit handle list alone cannot stop unrelated std::process launches from inheriting our handles.
// Keep all inheritable handles in an always-suspended process instead.
// https://devblogs.microsoft.com/oldnewthing/20200306-00/?p=103538
struct HandleParent {
    process: Process,
    job: Option<Handle>,
}

impl HandleParent {
    fn new() -> anyhow::Result<Self> {
        // SAFETY: An unnamed job with default security attributes has no preconditions.
        let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }.context("failed to create handle-donor job")?;
        // SAFETY: This function owns the handle returned by CreateJobObjectW.
        let job = unsafe { Handle::new_owned(job) }?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // The donor dies with the Agent, but the real child must outlive the donor.
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
        // SAFETY: The job is valid and the buffer matches the information class and size.
        unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                u32::try_from(size_of_val(&limits)).expect("job limit information size fits in u32"),
            )
        }
        .context("failed to configure handle-donor job")?;
        let mut attributes = ThreadAttributeList::with_count(1)?;
        let jobs = [job.raw()];
        // SAFETY: The list is initialized, and the job handle array remains alive through CreateProcessW.
        unsafe {
            UpdateProcThreadAttribute(
                attributes.raw(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                Some(jobs.as_ptr().cast()),
                size_of_val(&jobs),
                None,
                None,
            )
        }
        .context("failed to assign handle-donor job at creation")?;
        let executable = WideString::from(&std::env::current_exe().context("failed to locate Agent executable")?);
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).expect("STARTUPINFOEXW size fits in u32");
        startup.lpAttributeList = attributes.raw();
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: All buffers and the job attribute remain valid for the call.
        // No handles are inherited, and the initial thread is never resumed.
        unsafe {
            CreateProcessW(
                executable.as_pcwstr(),
                None,
                None,
                None,
                false,
                CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                None,
                PCWSTR::null(),
                &startup.StartupInfo,
                &mut information,
            )
        }
        .context("failed to create suspended handle donor")?;
        // SAFETY: Successful CreateProcessW returned owned process and thread handles.
        let process = Process::from(unsafe { Handle::new_owned(information.hProcess) }?);
        // SAFETY: This function owns the distinct initial-thread handle returned above.
        let _thread = unsafe { Handle::new_owned(information.hThread) }?;
        Ok(Self {
            process,
            job: Some(job),
        })
    }

    fn inherit(&self, handle: HANDLE) -> anyhow::Result<HANDLE> {
        // SAFETY: Retrieving the current process pseudo handle has no preconditions.
        let current_process = unsafe { GetCurrentProcess() };
        let mut remote = HANDLE::default();
        // SAFETY: Both process handles are valid; DuplicateHandle validates the source handle.
        // The returned handle belongs to the donor, which closes it when terminated.
        unsafe {
            DuplicateHandle(
                current_process,
                handle,
                self.process.handle.raw(),
                &mut remote,
                0,
                true,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .context("failed to duplicate pipe into handle donor")?;
        Ok(remote)
    }
}

impl Drop for HandleParent {
    fn drop(&mut self) {
        drop(self.job.take());
        if let Err(error) = self.process.wait(None) {
            warn!(%error, "Failed to wait for PSU handle donor");
        }
    }
}

fn owned_pipe(pipe: &Pipe) -> std::io::Result<OwnedHandle> {
    // SAFETY: The pipe owns the handle for the duration of this borrow.
    unsafe { BorrowedHandle::borrow_raw(pipe.handle.raw().0) }.try_clone_to_owned()
}

fn command_line(command: &Command) -> anyhow::Result<Vec<u16>> {
    let mut result = Vec::new();
    for argument in std::iter::once(command.get_program()).chain(command.get_args()) {
        let argument = argument.encode_wide().collect::<Vec<_>>();
        ensure!(!argument.contains(&0), "process argument contains a NUL character");
        if !result.is_empty() {
            result.push(u16::from(b' '));
        }
        result.push(u16::from(b'"'));
        let mut backslashes = 0;
        for character in argument {
            if character == u16::from(b'\\') {
                backslashes += 1;
                continue;
            }
            if character == u16::from(b'"') {
                result.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2 + 1));
            } else {
                result.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
            }
            backslashes = 0;
            result.push(character);
        }
        result.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
        result.push(u16::from(b'"'));
    }
    result.push(0);
    Ok(result)
}

fn environment(token: &Token, command: &Command) -> anyhow::Result<Vec<u16>> {
    let mut variables = Vec::new();
    for (name, value) in environment_block(Some(token), false)? {
        set_environment_variable(&mut variables, &name, Some(&value))?;
    }
    for (name, value) in command.get_envs() {
        let name = name.to_str().context("process environment name is not UTF-8")?;
        let value = value
            .map(|value| value.to_str().context("process environment value is not UTF-8"))
            .transpose()?;
        set_environment_variable(&mut variables, name, value)?;
    }
    let mut result = Vec::new();
    for (name, value) in variables {
        result.extend(name);
        result.push(u16::from(b'='));
        result.extend(value);
        result.push(0);
    }
    if result.is_empty() {
        result.push(0);
    }
    result.push(0);
    Ok(result)
}

fn set_environment_variable(
    variables: &mut Vec<(Vec<u16>, Vec<u16>)>,
    name: &str,
    value: Option<&str>,
) -> anyhow::Result<()> {
    ensure!(
        !name.is_empty() && !name.contains(['=', '\0']),
        "invalid process environment name"
    );
    let name = name.encode_utf16().collect::<Vec<_>>();
    ensure!(name.len() <= 32767, "process environment name exceeds Windows limit");
    let mut index = 0;
    // Windows environment names use case-insensitive UTF-16 ordinal order, not Rust's Unicode case folding.
    while index < variables.len() {
        // SAFETY: Both slices are valid and their lengths fit in i32.
        match unsafe { CompareStringOrdinal(&variables[index].0, &name, true) } {
            CSTR_LESS_THAN => index += 1,
            CSTR_EQUAL => {
                variables.remove(index);
                break;
            }
            CSTR_GREATER_THAN => break,
            _ => return Err(windows::core::Error::from_win32()).context("CompareStringOrdinal failed"),
        }
    }
    if let Some(value) = value {
        ensure!(
            !value.contains('\0'),
            "process environment value contains a NUL character"
        );
        variables.insert(index, (name, value.encode_utf16().collect()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use windows::Win32::Security::{SecurityImpersonation, TOKEN_ALL_ACCESS, TokenPrimary};

    use super::*;

    type BeforeCreate = Box<dyn FnOnce(&Process)>;

    thread_local! {
        pub(super) static BEFORE_CREATE: RefCell<Option<BeforeCreate>> = RefCell::new(None);
    }

    fn current_token() -> Token {
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut handle = HANDLE::default();
        // SAFETY: Getting the current process pseudo handle has no preconditions.
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: `process` is valid and `handle` is writable.
        unsafe { OpenProcessToken(process, TOKEN_ALL_ACCESS, &mut handle) }.expect("open current process token");
        // SAFETY: OpenProcessToken returned a token owned by this function.
        let token = Token::from(unsafe { Handle::new_owned(handle) }.expect("valid token handle"));
        token
            .duplicate(TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary)
            .expect("duplicate current primary token")
    }

    #[test]
    fn command_line_preserves_quotes_empty_arguments_and_trailing_backslashes() {
        let mut command = Command::new("pwsh.exe");
        command.args(["", r#"a"b"#, r"C:\path with spaces\", "\u{96ea}"]);
        let encoded = command_line(&command).expect("encode command line");
        let decoded = win_api_wrappers::utils::CommandLine::from_command_line(
            &String::from_utf16(&encoded[..encoded.len() - 1]).expect("UTF-16 command line"),
        );
        assert_eq!(
            decoded.0,
            ["pwsh.exe", "", r#"a"b"#, r"C:\path with spaces\", "\u{96ea}"]
        );
    }

    #[test]
    fn environment_names_follow_windows_utf16_ordinal_order() {
        let mut variables = Vec::new();
        set_environment_variable(&mut variables, "\u{e000}", Some("bmp")).expect("insert BMP name");
        set_environment_variable(&mut variables, "\u{10000}", Some("supplementary")).expect("insert surrogate pair");
        set_environment_variable(&mut variables, "PATH", Some("old")).expect("insert PATH");
        set_environment_variable(&mut variables, "path", Some("new")).expect("replace PATH");
        let names = variables
            .iter()
            .map(|(name, _)| String::from_utf16(name).expect("UTF-16 name"))
            .collect::<Vec<_>>();
        assert_eq!(names, ["path", "\u{10000}", "\u{e000}"]);
        assert_eq!(String::from_utf16(&variables[0].1).expect("UTF-16 value"), "new");
    }

    #[test]
    fn user_environment_overrides_are_case_insensitive_and_nul_terminated() {
        let token = current_token();
        let mut command = Command::new("powershell.exe");
        command.env("psu_run_as_test", "first").env("PSU_RUN_AS_TEST", "second");
        let block = environment(&token, &command).expect("build user environment");
        assert!(block.ends_with(&[0, 0]));
        let variables = block
            .split(|&character| character == 0)
            .filter(|value| !value.is_empty())
            .map(|value| String::from_utf16(value).expect("environment UTF-16"))
            .filter(|value| value.to_uppercase().starts_with("PSU_RUN_AS_TEST="))
            .map(|value| value.split_once('=').expect("environment assignment").1.to_owned())
            .collect::<Vec<_>>();
        assert_eq!(variables, ["second"]);
    }

    #[tokio::test]
    async fn token_process_preserves_identity_pipes_environment_and_exit_code() {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            let token = current_token();
            let directory = tempfile::tempdir().expect("create working directory");
            let expected_identity = token.sid_and_attributes().expect("read current SID").sid.to_string();
            let mut command = Command::new("powershell.exe");
            command.args(["-NoLogo", "-NoProfile", "-Command"]);
            command.arg(concat!(
                "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); ",
                "$line = [Console]::ReadLine(); [Console]::WriteLine($line); ",
                "[Console]::WriteLine($env:PSU_RUN_AS_TEST); [Console]::WriteLine([Environment]::CurrentDirectory); ",
                "[Console]::WriteLine([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value); ",
                "[Console]::Error.WriteLine('stderr-marker'); exit 7",
            ));
            command.env("PSU_RUN_AS_TEST", "env-marker");
            command.current_dir(directory.path());
            let mut child = Child::spawn_with_token(&token, &command).expect("spawn process with current token");
            let tree = child.attach_tree().expect("track and resume token process");
            let mut stdin = child.stdin.take().expect("stdin");
            stdin.write_all(b"stdin-marker\n").await.expect("write stdin");
            drop(stdin);
            let mut stdout = Vec::new();
            child
                .stdout
                .take()
                .expect("stdout")
                .read_to_end(&mut stdout)
                .await
                .expect("read stdout");
            let mut stderr = Vec::new();
            child
                .stderr
                .take()
                .expect("stderr")
                .read_to_end(&mut stderr)
                .await
                .expect("read stderr");
            let status = child.wait().await.expect("wait for token process");
            tree.release();

            assert_eq!(status.code(), Some(7));
            let stdout = String::from_utf8(stdout).expect("stdout UTF-8");
            let lines = stdout.lines().collect::<Vec<_>>();
            let [input, environment, working_directory, identity] = lines.as_slice() else {
                panic!("unexpected stdout: {stdout:?}");
            };
            assert_eq!(*input, "stdin-marker");
            assert_eq!(*environment, "env-marker");
            assert_eq!(
                std::fs::canonicalize(working_directory).expect("canonical working directory"),
                directory.path().canonicalize().expect("canonical requested directory")
            );
            assert_eq!(*identity, expected_identity);
            assert_eq!(String::from_utf8(stderr).expect("stderr UTF-8").trim(), "stderr-marker");
        })
        .await
        .expect("token process did not finish");
    }

    #[tokio::test]
    async fn unrelated_process_does_not_inherit_token_process_output_pipes() {
        let unrelated = Rc::new(RefCell::new(None));
        let donor = Rc::new(RefCell::new(None));
        BEFORE_CREATE.with(|callback| {
            let unrelated = Rc::clone(&unrelated);
            let donor = Rc::clone(&donor);
            callback.replace(Some(Box::new(move |process| {
                *donor.borrow_mut() = Some(Process::from(process.handle.try_clone().expect("retain donor process")));
                *unrelated.borrow_mut() = Some(
                    tokio::process::Command::new("ping.exe")
                        .args(["-n", "60", "127.0.0.1"])
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .kill_on_drop(true)
                        .spawn()
                        .expect("spawn unrelated process while native handles exist"),
                );
            })));
        });
        let token = current_token();
        let mut command = Command::new("powershell.exe");
        command.args([
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "[Console]::WriteLine('token-output')",
        ]);
        let mut child = Child::spawn_with_token(&token, &command).expect("spawn token process");
        assert_eq!(
            donor
                .borrow()
                .as_ref()
                .expect("donor process")
                .wait(Some(0))
                .expect("donor terminated"),
            windows::Win32::Foundation::WAIT_OBJECT_0
        );
        let tree = child.attach_tree().expect("track and resume token process");
        assert!(child.wait().await.expect("wait for token process").success());
        let mut stdout = Vec::new();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            child.stdout.take().expect("stdout").read_to_end(&mut stdout),
        )
        .await;
        let mut unrelated = unrelated.borrow_mut().take().expect("unrelated process");
        assert!(unrelated.try_wait().expect("check unrelated process").is_none());
        unrelated.kill().await.expect("kill unrelated process");
        tree.release();
        result
            .expect("unrelated process retained token stdout")
            .expect("read stdout");
        assert_eq!(String::from_utf8(stdout).expect("stdout UTF-8").trim(), "token-output");
    }

    #[tokio::test]
    async fn token_process_rejects_missing_working_directory() {
        let donor = Rc::new(RefCell::new(None));
        BEFORE_CREATE.with(|callback| {
            let donor = Rc::clone(&donor);
            callback.replace(Some(Box::new(move |process| {
                *donor.borrow_mut() = Some(Process::from(process.handle.try_clone().expect("retain donor process")));
            })));
        });
        let token = current_token();
        let directory = tempfile::tempdir().expect("create parent directory");
        let mut command = Command::new("powershell.exe");
        command.current_dir(directory.path().join("missing"));
        let error = Child::spawn_with_token(&token, &command)
            .err()
            .expect("missing directory must fail");
        assert!(format!("{error:#}").contains("CreateProcessAsUserW failed"));
        assert_eq!(
            donor
                .borrow()
                .as_ref()
                .expect("donor process")
                .wait(Some(0))
                .expect("donor terminated"),
            windows::Win32::Foundation::WAIT_OBJECT_0
        );
    }

    #[test]
    fn failed_handle_duplication_closes_the_donor_and_its_copied_handles() {
        let process;
        {
            let donor = HandleParent::new().expect("create donor");
            process = Process::from(donor.process.handle.try_clone().expect("retain donor process"));
            let (read, _) = Pipe::new_anonymous(None, 0).expect("create pipe");
            donor.inherit(read.handle.raw()).expect("copy first pipe handle");
            let error = donor
                .inherit(HANDLE::default())
                .expect_err("copying invalid handle must fail");
            assert!(format!("{error:#}").contains("failed to duplicate pipe into handle donor"));
        }
        assert_eq!(
            process.wait(Some(0)).expect("donor terminated"),
            windows::Win32::Foundation::WAIT_OBJECT_0
        );
    }

    #[test]
    fn closing_donor_job_terminates_the_suspended_process() {
        let mut donor = HandleParent::new().expect("create donor");
        let process = Process::from(donor.process.handle.try_clone().expect("retain donor process"));
        // Closing the only job handle models Agent exit without relying on HandleParent::drop.
        drop(donor.job.take());
        assert_eq!(
            process.wait(Some(5000)).expect("wait for donor"),
            windows::Win32::Foundation::WAIT_OBJECT_0
        );
    }

    #[tokio::test]
    async fn dropping_token_process_kills_it() {
        let token = current_token();
        let mut command = Command::new("powershell.exe");
        command.args(["-NoLogo", "-NoProfile", "-Command", "Start-Sleep -Seconds 60"]);
        let mut child = Child::spawn_with_token(&token, &command).expect("spawn token process");
        let tree = child.attach_tree().expect("track and resume token process");
        let process = Process::from(child.process.handle.try_clone().expect("duplicate process handle"));
        drop(child);
        drop(tree);
        assert_eq!(
            process.wait(Some(5000)).expect("wait for killed process"),
            windows::Win32::Foundation::WAIT_OBJECT_0
        );
    }
}
