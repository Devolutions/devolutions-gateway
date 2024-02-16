use mdns_sd::ServiceEvent;

use crate::{
    scanner::Protocol,
    task_utils::{ScanEntryReceiver, TaskManager},
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
) -> Result<ScanEntryReceiver, ScannerError> {
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
                        'outer: while let Ok(response) = receiver.recv_async().await {
                            tracing::debug!(sub_service_event=?response);
                            if let ServiceEvent::ServiceResolved(info) = response {
                                let full_name = info.get_fullname();
                                let (server, protocol) =
                                    parse_fullname(full_name).unwrap_or((full_name.to_string(), None));

                                let port = info.get_port();
                                let ip = info.get_addresses();

                                for ip in ip {
                                    let ip = *ip;
                                    let server = server.to_string();
                                    if let Err(_) = result_sender.send((ip, Some(server), port, protocol.clone())).await
                                    {
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

fn parse_fullname(fullname: &str) -> Option<(String, Option<Protocol>)> {
    let mut iter = fullname.split('.');
    let device_name = iter.next()?;
    let mut service_type = String::new();
    for part in iter {
        if part.starts_with('_') {
            service_type.push_str(part);
            service_type.push('.');
        }
    }
    // remove the trailing dot
    service_type.pop()?;

    let protocol = match service_type.as_str() {
        "_http._tcp" => Some(Protocol::Http),
        "_https._tcp" => Some(Protocol::Https),
        "_ssh._tcp" => Some(Protocol::Ssh),
        "_sftp._tcp" => Some(Protocol::Sftp),
        "_scp._tcp" => Some(Protocol::Scp),
        "_telnet._tcp" => Some(Protocol::Telnet),
        "_ldap._tcp" => Some(Protocol::Ldap),
        "_ldaps._tcp" => Some(Protocol::Ldaps),
        // https://jonathanmumm.com/tech-it/mdns-bonjour-bible-common-service-strings-for-various-vendors/
        // OSX Screen Sharing
        "_rfb._tcp" => Some(Protocol::Ard),
        // Note: RDP, VNC, Wayk, and SSH-based PowerShell (SshPwsh) are not standardized service types
        _ => None,
    };

    Some((device_name.to_string(), protocol))
}
