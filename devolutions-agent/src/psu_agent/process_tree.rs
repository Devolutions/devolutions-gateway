//! Termination of a child process together with the processes it started.
//!
//! Killing only the direct child leaves its descendants running, for example installers or vault clients started by
//! a PowerShell script. On Windows, the child process is assigned to a dedicated job object, which processes it
//! starts afterwards join automatically. On Unix, the child process leads a new process group that its descendants
//! inherit.
//!
//! The tree is terminated only on kill paths, including when the guard is dropped without being released. When the
//! direct child exits on its own, processes it deliberately left running in the background are kept, as they would
//! be when the script runs outside the agent.

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
    /// Must be called before the command is spawned.
    pub(super) fn prepare(command: &mut Command) {
        #[cfg(unix)]
        command.process_group(0);
        #[cfg(not(unix))]
        let _ = command;
    }

    /// Starts tracking the descendants of a child process spawned from a [`prepared`](Self::prepare) command.
    ///
    /// If tracking cannot be set up, only the direct child can be killed, which is logged.
    pub(super) fn attach(child: &Child) -> Self {
        let tree = Self::try_attach(child);

        if let Err(error) = &tree {
            warn!(
                error = format!("{error:#}"),
                "Failed to track PSU child process tree; only the direct child process can be killed"
            );
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
