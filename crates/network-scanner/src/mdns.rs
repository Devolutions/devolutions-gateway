use anyhow::Context;
use mdns_sd::ServiceEvent;

use crate::{
    scanner::Protocol,
    task_utils::{ScanEntryReceiver, TaskManager},
    ScannerError,
};

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

const SERVICES_INTRESTED: [Protocol; 11] = [
    Protocol::Ard,
    Protocol::Http,
    Protocol::Https,
    Protocol::Ldap,
    Protocol::Ldaps,
    Protocol::Rdp,
    Protocol::Sftp,
    Protocol::Scp,
    Protocol::Ssh,
    Protocol::Telnet,
    Protocol::Vnc,
];

pub fn mdns_query_scan(
    service_daemon: MdnsDaemon,
    task_manager: TaskManager,
    single_query_duration: std::time::Duration,
) -> Result<ScanEntryReceiver, ScannerError> {
    let service_daemon = service_daemon.get_service_daemon();
    let (result_sender, result_receiver) = tokio::sync::mpsc::channel(255);

    for service in SERVICES_INTRESTED {
        let service_name: &str = service.into();
        let service_name = format!("{}.local.", service_name);
        let (result_sender, service_daemon, service_deamon_clone, service_name_clone) = (
            result_sender.clone(),
            service_daemon.clone(),
            service_daemon.clone(),
            service_name.clone(),
        );
        task_manager
            .with_timeout(single_query_duration)
            .when_finish(move || {
                tracing::debug!("Stopping browse for service: {}", service_name_clone);
                if let Err(e) = service_deamon_clone.stop_browse(service_name_clone.as_ref()) {
                    tracing::warn!("failed to stop browsing for service: {}", e);
                }
            })
            .spawn(move |_| async move {
                tracing::debug!("Browsing for service: {}", service_name);
                let receiver = service_daemon.browse(service_name.as_ref()).with_context(|| {
                    let err_msg = format!("Failed to browse for service: {}", service_name);
                    tracing::error!("{}", err_msg);
                    err_msg
                })?;

                while let Ok(service_event) = receiver.try_recv() {
                    tracing::debug!("ServiceEvent: {:?}", service_event);
                    if let ServiceEvent::ServiceResolved(msg) = service_event {
                        let (device_name, protocol) =
                            parse_fullname(&msg.get_fullname()).unwrap_or((msg.get_fullname().to_string(), None));

                        let port = msg.get_port();

                        for ip in msg.get_addresses() {
                            if let Err(e) = result_sender
                                .send((ip.clone(), Some(device_name.clone()), port, protocol.clone()))
                                .await
                            {
                                tracing::error!("Failed to send result: {}", e);
                            }
                        }
                    }
                }

                tracing::debug!("Browsing for service: {} finished", service_name);
                anyhow::Ok(())
            })
    }

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

    let protocol = service_type.as_str().try_into().ok();

    Some((device_name.to_string(), protocol))
}

impl TryFrom<&str> for Protocol {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "_http._tcp" => Ok(Protocol::Http),
            "_https._tcp" => Ok(Protocol::Https),
            "_ssh._tcp" => Ok(Protocol::Ssh),
            "_sftp._tcp" => Ok(Protocol::Sftp),
            "_scp._tcp" => Ok(Protocol::Scp),
            "_telnet._tcp" => Ok(Protocol::Telnet),
            "_ldap._tcp" => Ok(Protocol::Ldap),
            "_ldaps._tcp" => Ok(Protocol::Ldaps),
            // https://jonathanmumm.com/tech-it/mdns-bonjour-bible-common-service-strings-for-various-vendors/
            // OSX Screen Sharing
            "_rfb._tcp" => Ok(Protocol::Ard),
            "_rdp._tcp" | "_rdp._udp" => Ok(Protocol::Rdp),
            _ => Err(anyhow::anyhow!("Unknown protocol: {}", value)),
        }
    }
}

impl<'a> Into<&'a str> for Protocol {
    fn into(self) -> &'a str {
        match self {
            Self::Ard => "_rfb._tcp",
            Self::Http => "_http._tcp",
            Self::Https => "_https._tcp",
            Self::Ldap => "_ldap._tcp",
            Self::Ldaps => "_ldaps._tcp",
            Self::Sftp => "_sftp._tcp",
            Self::Scp => "_scp._tcp",
            Self::Ssh => "_ssh._tcp",
            Self::Telnet => "_telnet._tcp",
            Self::Vnc => "_rfb._tcp",
            Self::Rdp => "_rdp._tcp",
        }
    }
}
