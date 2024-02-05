use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use network_scanner_net::{runtime::Socket2Runtime, socket::AsyncRawSocket};
use network_scanner_proto::netbios::NetBiosPacket;
use socket2::{Domain, SockAddr, Type};
use tokio::time::timeout;

use crate::{assume_init, ip_utils::IpAddrRange, ScannerError};

const MESSAGE: [u8; 50] = [
    0xA2, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01,
];

const NET_BIOS_PORT: u16 = 137;
type ResultReceiver = tokio::sync::mpsc::Receiver<(Ipv4Addr, String)>;
pub fn netbios_query_scan(
    runtime: Arc<Socket2Runtime>,
    ip_range: IpAddrRange,
    single_query_duration: std::time::Duration,
    netbios_scan_interval: std::time::Duration,
) -> Result<ResultReceiver, ScannerError> {
    if ip_range.is_ipv6() {
        return Err(ScannerError::DoesNotSupportIpv6("netbios".to_string()));
    }

    let (sender, receiver) = tokio::sync::mpsc::channel(255);
    tokio::spawn(async move {
        for ip in ip_range.into_iter() {
            let socket = runtime.new_socket(Domain::IPV4, Type::DGRAM, None)?;
            let sender = sender.clone();
            netbios_query_one(ip, socket, sender, single_query_duration);
            tokio::time::sleep(netbios_scan_interval).await;
        }
        anyhow::Ok(())
    });

    Ok(receiver)
}

pub fn netbios_query_one(
    ip: IpAddr,
    mut socket: AsyncRawSocket,
    sender: tokio::sync::mpsc::Sender<(Ipv4Addr, String)>,
    duration: std::time::Duration,
) -> tokio::task::JoinHandle<Result<(), anyhow::Error>> {
    let handler = tokio::spawn(async move {
        let socket_addr: SocketAddr = (ip, NET_BIOS_PORT).into();
        let addr = SockAddr::from(socket_addr);
        socket.send_to(&MESSAGE, &addr).await?;

        let mut buf: [MaybeUninit<u8>; 1024] = [MaybeUninit::<u8>::uninit(); 1024];
        timeout(duration, socket.recv(&mut buf)).await??;
        unsafe {
            let buf = assume_init(&buf);
            let IpAddr::V4(ipv4) = ip else {
                anyhow::bail!("unreachable");
            };
            let packet = NetBiosPacket::from(ipv4, buf);
            sender.send((ipv4, packet.name())).await?
        }
        anyhow::Result::<()>::Ok(())
    });
    handler
}
