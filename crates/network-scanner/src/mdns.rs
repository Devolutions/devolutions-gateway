use mdns_sd::ServiceEvent;

use crate::{
    task_utils::{PortReceiver, TaskManager},
    ScannerError,
};

const META_QUERY: &str = "_services._dns-sd._udp.local.";

#[derive(Clone)]
pub struct MdnsDeamon {
    service_deamon: mdns_sd::ServiceDaemon,
}

impl MdnsDeamon {
    pub fn new() -> Result<Self, ScannerError> {
        let service_deamon = mdns_sd::ServiceDaemon::new()?;
        Ok(Self { service_deamon })
    }
}

pub fn mdns_query_scan(
    service_deamon: MdnsDeamon,
    task_manager: TaskManager,
    entire_duration: std::time::Duration,
    single_query_duration: std::time::Duration,
) -> Result<PortReceiver, ScannerError> {
    let service_deamon = service_deamon.service_deamon;

    let receiver = service_deamon.browse(META_QUERY)?;
    let service_deamon_clone = service_deamon.clone();

    let (result_sender, result_receiver) = tokio::sync::mpsc::channel(255);

    task_manager
        .with_timeout(entire_duration)
        .when_finished(move || {
            tracing::debug!("mdns meta query finished");
            while let Err(e) = service_deamon_clone.stop_browse(META_QUERY) {
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

                let service_deamon = service_deamon.clone();
                let service_deamon_clone = service_deamon.clone();
                let fullname_clone = fullname.clone();
                let result_sender = result_sender.clone();

                task_manager
                    .with_timeout(single_query_duration)
                    .when_finished(move || {
                        tracing::debug!("mdns query finished for {}", fullname_clone);
                        while let Err(e) = service_deamon_clone.stop_browse(META_QUERY) {
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
                        let receiver = service_deamon.browse(&fullname)?;
                        while let Ok(response) = receiver.recv_async().await {
                            tracing::debug!(sub_service_event=?response);
                            if let ServiceEvent::ServiceResolved(info) = response {
                                let server = info.get_fullname();
                                let port = info.get_port();
                                let ip = info.get_addresses();

                                for ip in ip {
                                    let ip = *ip;
                                    let server = server.to_string();
                                    let _ = result_sender.send((ip, Some(server), port)).await;
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
