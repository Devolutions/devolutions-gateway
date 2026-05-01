use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use network_scanner_net::runtime::Socket2Runtime;
use network_scanner_net::socket::AsyncRawSocket;
use network_scanner_proto::netbios::NetBiosPacket;
use socket2::{Domain, SockAddr, Type};
use tokio::sync::mpsc;

use crate::ip_utils::IpV4AddrRange;
use crate::{ScannerError, assume_init};

const MESSAGE: [u8; 50] = [
    0xA2, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01,
];

#[derive(Debug, Clone)]
pub enum NetBiosEvent {
    Start {
        ip: Ipv4Addr,
    },
    Success {
        ip: Ipv4Addr,
        name: String,
        /// Round-trip time in milliseconds, when measured.
        time: Option<u128>,
    },
    Failed {
        ip: Ipv4Addr,
    },
}

const NET_BIOS_PORT: u16 = 137;
pub fn netbios_query_scan(
    runtime: Arc<Socket2Runtime>,
    ip_range: IpV4AddrRange,
    single_query_duration: std::time::Duration,
    netbios_scan_interval: std::time::Duration,
    task_manager: crate::task_utils::TaskManager,
) -> Result<mpsc::Receiver<NetBiosEvent>, ScannerError> {
    let (sender, receiver) = mpsc::channel(255);
    task_manager.spawn(move |task_manager: crate::task_utils::TaskManager| async move {
        for ip in ip_range.into_iter() {
            let socket = runtime.new_socket(Domain::IPV4, Type::DGRAM, None)?;
            let (sender, task_manager) = (sender.clone(), task_manager.clone());

            sender
                .send(NetBiosEvent::Start { ip })
                .await
                .context("failed to send netbios start event")?;

            netbios_query_one(ip, socket, sender, single_query_duration, task_manager);
            tokio::time::sleep(netbios_scan_interval).await;
        }
        anyhow::Ok(())
    });

    Ok(receiver)
}

pub(crate) fn netbios_query_one(
    ip: Ipv4Addr,
    mut socket: AsyncRawSocket,
    result_sender: mpsc::Sender<NetBiosEvent>,
    duration: std::time::Duration,
    task_manager: crate::task_utils::TaskManager,
) {
    task_manager.with_timeout(duration).spawn(move |_| async move {
        let socket_addr: SocketAddr = (ip, NET_BIOS_PORT).into();
        let addr = SockAddr::from(socket_addr);

        let mut buf: [MaybeUninit<u8>; 1024] = [MaybeUninit::<u8>::uninit(); 1024];

        let send_at = std::time::Instant::now();
        let result: anyhow::Result<usize> = async {
            socket.send_to(&MESSAGE, &addr).await?;
            let n = socket.recv(&mut buf).await?;
            Ok(n)
        }
        .await;

        let bytes_received = match result {
            Ok(n) => n,
            Err(_) => {
                return result_sender
                    .send(NetBiosEvent::Failed { ip })
                    .await
                    .context("failed to send netbios failed event");
            }
        };

        // SAFETY: `recv` initialised exactly `bytes_received` bytes of `buf`;
        // we cap the slice here so callers never observe uninitialised
        // memory. Anything past `bytes_received` stays `MaybeUninit::uninit`
        // and is not aliased through this reference.
        let buf = unsafe { assume_init(&buf[..bytes_received]) };

        let packet = NetBiosPacket::from(ip, buf);
        let time = Some(send_at.elapsed().as_millis());

        result_sender
            .send({
                NetBiosEvent::Success {
                    ip: packet.ip,
                    name: packet.name(),
                    time,
                }
            })
            .await?;

        anyhow::Result::<()>::Ok(())
    });
}
