//! Termination of a child process together with the processes it started.
//!
//! Killing only the direct child leaves its descendants running, for example installers or vault clients started by
//! a PowerShell script. On Windows, the child process is created suspended, assigned to a dedicated job object, and
//! only then resumed, so every process it starts joins the job. On Unix, the child process leads a new process
//! group that its descendants inherit.
//!
//! The tree is terminated when the job is stopped, including when the guard is dropped without being released. When
//! the direct child exits on its own, processes it deliberately left running in the background are kept, as they
//! would be when the script runs outside the agent.

use tokio::process::{Child, Command};

pub(super) struct ProcessTree {
    #[cfg(windows)]
    job: Option<std::os::windows::io::OwnedHandle>,
    #[cfg(unix)]
    process_group: Option<libc::pid_t>,
    armed: bool,
}

impl ProcessTree {
    /// Configures the command so that its descendants can be terminated with it.
    ///
    /// Must be called before the command is spawned, and the spawned child must be passed to
    /// [`attach`](Self::attach). On Windows, the child process is created suspended so that it cannot start
    /// processes before it joins its job object.
    pub(super) fn prepare(command: &mut Command) {
        #[cfg(windows)]
        command.creation_flags(windows::Win32::System::Threading::CREATE_SUSPENDED.0);
        #[cfg(unix)]
        command.process_group(0);
    }

    /// Starts tracking the descendants of a child process spawned from a [`prepared`](Self::prepare) command, then
    /// lets it run.
    ///
    /// If tracking cannot be set up, only the direct child can be killed, which is logged.
    pub(super) fn attach(child: &mut Child) -> Self {
        let tree = Self::try_attach(child);

        if let Err(error) = &tree {
            warn!(
                error = format!("{error:#}"),
                "Failed to track PSU child process tree; only the direct child process can be killed"
            );
        }

        #[cfg(windows)]
        if let Err(error) = resume_process(child) {
            error!(
                error = format!("{error:#}"),
                "Failed to resume PSU child process; killing it"
            );
            let _ = child.start_kill();
        }

        tree.unwrap_or(Self {
            #[cfg(windows)]
            job: None,
            #[cfg(unix)]
            process_group: None,
            armed: false,
        })
    }

    #[cfg(windows)]
    fn try_attach(child: &Child) -> anyhow::Result<Self> {
        use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};

        use anyhow::Context as _;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW};

        let process = child.raw_handle().context("child process already exited")?;

        // SAFETY: Creating an unnamed job object with default security attributes has no preconditions.
        let job =
            unsafe { CreateJobObjectW(None, windows::core::PCWSTR::null()) }.context("CreateJobObjectW failed")?;

        // SAFETY: `job` is a valid handle owned by this function and not closed anywhere else.
        let job = unsafe { OwnedHandle::from_raw_handle(job.0) };

        // SAFETY: Both handles are valid for the duration of the call.
        unsafe { AssignProcessToJobObject(HANDLE(job.as_raw_handle()), HANDLE(process)) }
            .context("AssignProcessToJobObject failed")?;

        Ok(Self {
            job: Some(job),
            armed: true,
        })
    }

    #[cfg(unix)]
    fn try_attach(child: &Child) -> anyhow::Result<Self> {
        use anyhow::Context as _;

        // The child process leads its own process group, so the group ID is its process ID.
        let process_group = child.id().context("child process already exited")?;
        let process_group = libc::pid_t::try_from(process_group).context("process ID out of range")?;

        Ok(Self {
            process_group: Some(process_group),
            armed: true,
        })
    }

    #[cfg(not(any(windows, unix)))]
    fn try_attach(_: &Child) -> anyhow::Result<Self> {
        anyhow::bail!("process tree tracking is not supported on this platform")
    }

    /// Kills the direct child process and every process in its tree.
    pub(super) fn terminate(&mut self) {
        if !std::mem::take(&mut self.armed) {
            return;
        }

        #[cfg(windows)]
        if let Some(job) = &self.job {
            use std::os::windows::io::AsRawHandle as _;

            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::System::JobObjects::TerminateJobObject;

            // SAFETY: `job` is a valid job object handle owned by `self`.
            if let Err(error) = unsafe { TerminateJobObject(HANDLE(job.as_raw_handle()), 1) } {
                warn!(%error, "Failed to terminate PSU child process tree");
            }
        }

        #[cfg(unix)]
        if let Some(process_group) = self.process_group {
            // SAFETY: `killpg` has no memory safety preconditions.
            if unsafe { libc::killpg(process_group, libc::SIGKILL) } != 0 {
                let error = std::io::Error::last_os_error();

                // The whole group already exited.
                if error.raw_os_error() != Some(libc::ESRCH) {
                    warn!(%error, "Failed to terminate PSU child process tree");
                }
            }
        }
    }

    /// Leaves the processes started by the direct child running after it exits on its own.
    pub(super) fn release(mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessTree {
    fn drop(&mut self) {
        self.terminate();
    }
}

/// Resumes the initial thread of a child process created with `CREATE_SUSPENDED`.
#[cfg(windows)]
fn resume_process(child: &Child) -> anyhow::Result<()> {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};

    use anyhow::Context as _;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    let process_id = child.id().context("child process already exited")?;

    // SAFETY: Taking a thread snapshot has no preconditions.
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }.context("CreateToolhelp32Snapshot failed")?;
    // SAFETY: `snapshot` is a valid handle owned by this function and not closed anywhere else.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot.0) };
    let snapshot = HANDLE(snapshot.as_raw_handle());

    let mut entry = THREADENTRY32 {
        dwSize: u32::try_from(size_of::<THREADENTRY32>()).expect("THREADENTRY32 size fits in u32"),
        ..THREADENTRY32::default()
    };
    let mut resumed_threads = 0;

    // SAFETY: `snapshot` is valid, and `entry` is a properly sized and writable THREADENTRY32.
    let mut next = unsafe { Thread32First(snapshot, &mut entry) };
    while next.is_ok() {
        if entry.th32OwnerProcessID == process_id {
            // SAFETY: Opening a thread by ID has no memory safety preconditions.
            let thread =
                unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) }.context("OpenThread failed")?;
            // SAFETY: `thread` is a valid handle owned by this function and not closed anywhere else.
            let thread = unsafe { OwnedHandle::from_raw_handle(thread.0) };

            // SAFETY: `thread` is a valid thread handle with THREAD_SUSPEND_RESUME access.
            if unsafe { ResumeThread(HANDLE(thread.as_raw_handle())) } == u32::MAX {
                return Err(std::io::Error::last_os_error()).context("ResumeThread failed");
            }
            resumed_threads += 1;
        }

        // SAFETY: Same as for `Thread32First`.
        next = unsafe { Thread32Next(snapshot, &mut entry) };
    }

    anyhow::ensure!(resumed_threads > 0, "no thread found for process {process_id}");

    Ok(())
}
