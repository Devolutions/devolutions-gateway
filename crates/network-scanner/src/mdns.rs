use mdns_sd::ServiceEvent;

use crate::{
    task_utils::{ PortReceiver, TaskManager},
    ScannerError,
};

const META_QUERY: &'static str = "_services._dns-sd._udp.local.";

pub fn mdns_query_scan(
    service_deamon: mdns_sd::ServiceDaemon,
    task_manager: TaskManager,
) -> Result<PortReceiver, ScannerError> {
    let receiver = service_deamon.browse(META_QUERY)?;
    let (result_sender, result_receiver) = tokio::sync::mpsc::channel(255);
    task_manager.spawn(move |task_manager| async move {
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
            let result_sender = result_sender.clone();
            task_manager.spawn_no_sub_task(async move {
                let receiver = service_deamon.browse(&fullname).expect("failed to browse");
                while let Ok(response) = receiver.recv_async().await {
                    tracing::debug!(sub_service_event=?response);
                    if let ServiceEvent::ServiceResolved(info) = response {
                        let server = info.get_fullname();
                        let port = info.get_port();
                        let ip = info.get_addresses();

                        for ip in ip {
                            let ip = ip.clone();
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
