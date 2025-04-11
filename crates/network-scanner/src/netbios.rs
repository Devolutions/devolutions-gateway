use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use network_scanner_net::runtime::Socket2Runtime;
use network_scanner_net::socket::AsyncRawSocket;
use network_scanner_proto::netbios::NetBiosPacket;
use socket2::{Domain, SockAddr, Type};

use crate::ip_utils::IpV4AddrRange;
use crate::task_utils::IpHostReceiver;
use crate::{assume_init, ScannerError};

const MESSAGE: [u8; 50] = [
    0xA2, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01,
];

const NET_BIOS_PORT: u16 = 137;
pub fn netbios_query_scan(
    runtime: Arc<Socket2Runtime>,
    ip_range: IpV4AddrRange,
    single_query_duration: std::time::Duration,
    netbios_scan_interval: std::time::Duration,
    task_manager: crate::task_utils::TaskManager,
) -> Result<IpHostReceiver, ScannerError> {
    let (sender, receiver) = tokio::sync::mpsc::channel(255);
    task_manager.spawn(move |task_manager: crate::task_utils::TaskManager| async move {
        for ip in ip_range.into_iter() {
            let socket = runtime.new_socket(Domain::IPV4, Type::DGRAM, None)?;
            let (sender, task_manager) = (sender.clone(), task_manager.clone());
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
    result_sender: crate::task_utils::IpHostSender,
    duration: std::time::Duration,
    task_manager: crate::task_utils::TaskManager,
) {
    task_manager.with_timeout(duration).spawn(move |_| async move {
        let socket_addr: SocketAddr = (ip, NET_BIOS_PORT).into();
        let addr = SockAddr::from(socket_addr);

        socket.send_to(&MESSAGE, &addr).await?;
        let mut buf: [MaybeUninit<u8>; 1024] = [MaybeUninit::<u8>::uninit(); 1024];
        socket.recv(&mut buf).await?;

        // SAFETY: TODO: explain why it’s safe.
        let buf = unsafe { assume_init(&buf) };

        let packet = NetBiosPacket::from(ip, buf);

        result_sender.send((ip.into(), Some(packet.name()))).await?;

        anyhow::Result::<()>::Ok(())
    });
}
