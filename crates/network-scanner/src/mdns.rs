use mdns_sd::ServiceEvent;

use crate::{
    task_utils::{PortReceiver, TaskManager},
    ScannerError,
};

const META_QUERY: &str = "_services._dns-sd._udp.local.";

#[derive(Clone)]
pub struct MdnsDaemon {
    service_daemon: mdns_sd::ServiceDaemon,
}

impl MdnsDaemon {
    pub fn new() -> Result<Self, ScannerError> {
        let service_daemon = mdns_sd::ServiceDaemon::new()?;
        Ok(Self { service_daemon })
    }

    pub fn get_service_daemon(&self) -> mdns_sd::ServiceDaemon {
        self.service_daemon.clone()
    }
}

pub fn mdns_query_scan(
    service_daemon: MdnsDaemon,
    task_manager: TaskManager,
    entire_duration: std::time::Duration,
    single_query_duration: std::time::Duration,
) -> Result<PortReceiver, ScannerError> {
    let service_daemon = service_daemon.get_service_daemon();

    let receiver = service_daemon.browse(META_QUERY)?;
    let service_daemon_clone = service_daemon.clone();

    let (result_sender, result_receiver) = tokio::sync::mpsc::channel(255);

    task_manager
        .with_timeout(entire_duration)
        .when_timed_out(move || {
            tracing::debug!("mdns meta query finished");
            while let Err(e) = service_daemon_clone.stop_browse(META_QUERY) {
                match e {
                    mdns_sd::Error::Again => {
                        tracing::trace!("mdns stop_browse transient error, trying again");
                    }
                    fatal => {
                        tracing::error!(error = %fatal, "mdns stop_browse fatal error");
                        break;
                    }
                }
            }
        })
        .spawn(move |task_manager| async move {
            loop {
                let response = receiver.recv_async().await;
                let response = match response {
                    Ok(response) => response,
                    Err(e) => {
                        tracing::error!("mdns query error: {}", e);
                        break;
                    }
                };

                tracing::debug!(service_event=?response);
                let ServiceEvent::ServiceFound(_, fullname) = response else {
                    continue;
                };

                let service_daemon = service_daemon.clone();
                let service_daemon_clone = service_daemon.clone();
                let fullname_clone = fullname.clone();
                let result_sender = result_sender.clone();

                task_manager
                    .with_timeout(single_query_duration)
                    .when_timed_out(move || {
                        tracing::debug!("mdns query finished for {}", fullname_clone);
                        while let Err(e) = service_daemon_clone.stop_browse(&fullname_clone) {
                            match e {
                                mdns_sd::Error::Again => {
                                    tracing::trace!("mdns stop_browse transient error, trying again");
                                }
                                fatal => {
                                    tracing::error!(error = %fatal, "mdns stop_browse fatal error");
                                    break;
                                }
                            }
                        }
                    })
                    .spawn(move |_| async move {
                        let receiver = service_daemon.browse(&fullname)?;
                        'outer: while let Ok(response) = receiver.recv_async().await {
                            tracing::debug!(sub_service_event=?response);
                            if let ServiceEvent::ServiceResolved(info) = response {
                                let server = info.get_fullname();
                                let port = info.get_port();
                                let ip = info.get_addresses();

                                for ip in ip {
                                    let ip = *ip;
                                    let server = server.to_string();
                                    if result_sender.send((ip, Some(server), port)).await.is_err() {
                                        break 'outer;
                                    }
                                }
                            }
                        }
                        anyhow::Ok(())
                    });
            }
            anyhow::Ok(())
        });
    Ok(result_receiver)
}
