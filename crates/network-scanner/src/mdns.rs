use anyhow::Context;
use mdns_sd::ServiceEvent;

use crate::scanner::{ScanEntry, ServiceType};
use crate::task_utils::{ScanEntryReceiver, TaskManager};
use crate::ScannerError;

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

    pub fn stop(&self) {
        let receiver = match self.service_daemon.shutdown() {
            Ok(receiver) => receiver,
            Err(e) => {
                // if e is try again, we should try again, but only once
                let result = if matches!(e, mdns_sd::Error::Again) {
                    self.service_daemon.shutdown()
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

pub fn mdns_query_scan(
    service_daemon: MdnsDaemon,
    task_manager: TaskManager,
    query_duration: std::time::Duration,
) -> Result<ScanEntryReceiver, ScannerError> {
    let service_daemon = service_daemon.get_service_daemon();
    let (result_sender, result_receiver) = tokio::sync::mpsc::channel(255);

    for service in SERVICE_TYPES_INTERESTED {
        let service_name: &str = service.into();
        let service_name = format!("{}.local.", service_name);
        let (result_sender, service_daemon, service_daemon_clone, service_name_clone) = (
            result_sender.clone(),
            service_daemon.clone(),
            service_daemon.clone(),
            service_name.clone(),
        );
        let receiver = service_daemon.browse(service_name.as_ref()).with_context(|| {
            let err_msg = format!("failed to browse for service: {}", service_name);
            error!(error = err_msg);
            err_msg
        })?;

        let receiver_clone = receiver.clone();
        task_manager
            .with_timeout(query_duration)
            .after_finish(move |_| {
                debug!(service_name = ?service_name_clone, "Stopping browse for service");
                if let Err(e) = service_daemon_clone.stop_browse(service_name_clone.as_ref()) {
                    warn!(error = %e, "Failed to stop browsing for service");
                }
                // Receive the last event (StopBrowse), preventing the receiver from being dropped,this will satisfy the sender side to avoid loging an error
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

                        for ip in msg.get_addresses() {
                            let entry = ScanEntry::Regular {
                                addr: *ip,
                                hostname: Some(device_name.clone()),
                                port,
                                service_type: protocol,
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
