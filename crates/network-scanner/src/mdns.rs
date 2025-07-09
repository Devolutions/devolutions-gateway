use anyhow::Context;
use mdns_sd::ServiceEvent;
use tokio::sync::mpsc;

use crate::ScannerError;
use crate::scanner::ServiceType;
use crate::task_utils::TaskManager;

#[derive(Clone)]
pub struct MdnsDaemon {
    service_daemon: Option<mdns_sd::ServiceDaemon>,
}

impl MdnsDaemon {
    pub fn new() -> Result<Self, ScannerError> {
        Ok(Self { service_daemon: None })
    }

    // Lazy initialization of the service daemon
    pub fn get_service_daemon(&mut self) -> Result<mdns_sd::ServiceDaemon, ScannerError> {
        Ok(match &self.service_daemon {
            Some(daemon) => daemon.clone(),
            None => {
                let service_daemon =
                    mdns_sd::ServiceDaemon::new().with_context(|| "Failed to create service daemon")?;
                self.service_daemon = Some(service_daemon.clone());
                service_daemon
            }
        })
    }

    pub fn stop(&self) {
        let service_daemon = match &self.service_daemon {
            Some(daemon) => daemon.clone(),
            None => return,
        };

        let receiver = match service_daemon.shutdown() {
            Ok(receiver) => receiver,
            Err(e) => {
                // if e is try again, we should try again, but only once
                let result = if matches!(e, mdns_sd::Error::Again) {
                    service_daemon.shutdown()
                } else {
                    Err(e)
                };

                let Ok(receiver) = result.inspect_err(|e| {
                    warn!(error = %e, "Failed to shutdown service daemon");
                }) else {
                    return;
                };

                receiver
            }
        };

        // Receive the last event (Shutdown), preventing the receiver from being dropped, avoid logging an error from the sender side(the mdns crate)
        let _ = receiver.recv_timeout(std::time::Duration::from_millis(100));
    }
}

// ARD is a variant of the RFB (VNC) protocol, so it’s not included in this list.
const SERVICE_TYPES_INTERESTED: [ServiceType; 10] = [
    ServiceType::Http,
    ServiceType::Https,
    ServiceType::Ldap,
    ServiceType::Ldaps,
    ServiceType::Rdp,
    ServiceType::Sftp,
    ServiceType::Scp,
    ServiceType::Ssh,
    ServiceType::Telnet,
    ServiceType::Vnc,
];

#[derive(Debug, Clone)]
pub enum MdnsEvent {
    ServiceResolved {
        addr: std::net::IpAddr,
        device_name: String,
        port: u16,
        protocol: Option<ServiceType>,
    },
    Start {
        service_type: ServiceType,
    },
}

pub fn mdns_query_scan(
    mut service_daemon: MdnsDaemon,
    task_manager: TaskManager,
    query_duration: std::time::Duration,
) -> Result<mpsc::Receiver<MdnsEvent>, ScannerError> {
    let daemon = service_daemon.get_service_daemon()?;
    let (result_sender, result_receiver) = mpsc::channel(255);

    for service in SERVICE_TYPES_INTERESTED {
        let service_name: &str = service.into();
        let service_name = format!("{service_name}.local.");
        let (result_sender, daemon_clone, service_name_clone) =
            (result_sender.clone(), daemon.clone(), service_name.clone());
        let receiver = daemon.browse(service_name.as_ref()).with_context(|| {
            let err_msg = format!("failed to browse for service: {service_name}");
            error!(error = err_msg);
            err_msg
        })?;

        let receiver_clone = receiver.clone();
        task_manager
            .with_timeout(query_duration)
            .when_finish(move || {
                debug!("Stopping browse for mDns service");
                if let Err(e) = daemon_clone.stop_browse(service_name_clone.as_ref()) {
                    warn!(error = %e, "Failed to stop browsing for service");
                }
                // Receive the last event (StopBrowse), preventing the receiver from being dropped,this will satisfy the sender side to avoid logging an error
                let _ = receiver_clone.recv_timeout(std::time::Duration::from_millis(10));
            })
            .spawn(move |_| async move {
                debug!(?service_name, "Starting browse for service");

                while let Ok(service_event) = receiver.recv_async().await {
                    debug!(?service_event);
                    if let ServiceEvent::ServiceResolved(msg) = service_event {
                        let fullname = msg.get_fullname();
                        let (device_name, protocol) =
                            parse_fullname(fullname).unwrap_or_else(|| (fullname.to_owned(), None));

                        let port = msg.get_port();

                        for addr in msg.get_addresses() {
                            let entry = MdnsEvent::ServiceResolved {
                                addr: *addr,
                                device_name: device_name.clone(),
                                port,
                                protocol,
                            };

                            if let Err(e) = result_sender.send(entry).await {
                                error!(error = %e, "Failed to send result");
                            }
                        }
                    }
                }

                anyhow::Ok(())
            })
    }

    Ok(result_receiver)
}

fn parse_fullname(fullname: &str) -> Option<(String, Option<ServiceType>)> {
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

    let protocol = service_type.as_str().try_into().ok();

    Some((device_name.to_owned(), protocol))
}

impl TryFrom<&str> for ServiceType {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "_http._tcp" => Ok(ServiceType::Http),
            "_https._tcp" => Ok(ServiceType::Https),
            "_ssh._tcp" => Ok(ServiceType::Ssh),
            "_sftp._tcp" => Ok(ServiceType::Sftp),
            "_scp._tcp" => Ok(ServiceType::Scp),
            "_telnet._tcp" => Ok(ServiceType::Telnet),
            "_ldap._tcp" => Ok(ServiceType::Ldap),
            "_ldaps._tcp" => Ok(ServiceType::Ldaps),
            // ARD is a variant of RFB (VNC) protocol.
            "_rfb._tcp" => Ok(ServiceType::Vnc),
            "_rdp._tcp" | "_rdp._udp" => Ok(ServiceType::Rdp),
            _ => Err(anyhow::anyhow!("unknown protocol: {}", value)),
        }
    }
}

impl From<ServiceType> for &str {
    fn from(val: ServiceType) -> Self {
        match val {
            ServiceType::Ard => "_rfb._tcp",
            ServiceType::Http => "_http._tcp",
            ServiceType::Https => "_https._tcp",
            ServiceType::Ldap => "_ldap._tcp",
            ServiceType::Ldaps => "_ldaps._tcp",
            ServiceType::Sftp => "_sftp._tcp",
            ServiceType::Scp => "_scp._tcp",
            ServiceType::Ssh => "_ssh._tcp",
            ServiceType::Telnet => "_telnet._tcp",
            ServiceType::Vnc => "_rfb._tcp",
            ServiceType::Rdp => "_rdp._tcp",
        }
    }
}
