use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System, SystemExt as _};
use tokio::time::{sleep, Duration};

pub async fn watch_process(pid: Pid) {
    let mut system = System::new_with_specifics(RefreshKind::new());
    let process_refresh_kind = ProcessRefreshKind::new();

    loop {
        if !system.refresh_process_specifics(pid, process_refresh_kind) {
            return;
        }

        sleep(Duration::from_secs(60)).await;
    }
}
