use std::process::ExitStatus;

use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::task;

pub(crate) async fn watch_process(pid: Pid) -> Option<ExitStatus> {
    task::spawn_blocking(move || {
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), false);
        sys.process(pid).and_then(|p| p.wait())
    })
    .await
    .expect("blocking task panicked")
}
