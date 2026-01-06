use std::fs::File;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;

use anyhow::Context as _;
use bytes::BytesMut;
use devolutions_gateway_task::ChildTask;
use etherparse::PacketBuilder;
use pcap_file::pcap::{PcapPacket, PcapWriter};
use tokio::sync::mpsc;

use crate::interceptor::{Dissector, Inspector, PeerSide};

pub struct PcapInspector {
    side: PeerSide,
    sender: mpsc::UnboundedSender<(PeerSide, Vec<u8>)>,
}

impl Inspector for PcapInspector {
    fn inspect_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.sender
            .send((self.side, bytes.to_vec()))
            .context("PCAP inspector task is terminated")?;
        Ok(())
    }
}

impl PcapInspector {
    /// Returns client side and server side inspector
    pub fn init(
        client_addr: SocketAddr,
        server_addr: SocketAddr,
        pcap_path: impl AsRef<Path>,
        dissector: impl Dissector + Send + 'static,
    ) -> anyhow::Result<(Self, Self)> {
        let file = File::create(pcap_path).context("failed to crate pcap file")?;
        let pcap_writer = PcapWriter::new(file).context("failed to create pcap writer")?;

        let (sender, receiver) = mpsc::unbounded_channel();

        ChildTask::spawn(writer_task(receiver, pcap_writer, client_addr, server_addr, dissector)).detach();

        Ok((
            Self {
                side: PeerSide::Client,
                sender: sender.clone(),
            },
            Self {
                side: PeerSide::Server,
                sender,
            },
        ))
    }
}

async fn writer_task(
    mut receiver: mpsc::UnboundedReceiver<(PeerSide, Vec<u8>)>,
    mut pcap_writer: PcapWriter<File>,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    mut dissector: impl Dissector,
) {
    const FAKE_CLIENT_IP_ADDR: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    const FAKE_SERVER_IP_ADDR: Ipv4Addr = Ipv4Addr::new(2, 2, 2, 2);

    let mut server_seq_number = 0;
    let mut server_acc = BytesMut::new();

    let mut client_seq_number = 0;
    let mut client_acc = BytesMut::new();

    debug!(%client_addr, %server_addr, "PCAP writer task started");

    while let Some((side, bytes)) = receiver.recv().await {
        trace!(packet_size = bytes.len(), ?side, "New packet intercepted");

        let (acc, source_addr, dest_addr, seq_number, ack_number) = match side {
            PeerSide::Client => (
                &mut client_acc,
                SocketAddrV4::new(FAKE_CLIENT_IP_ADDR, client_addr.port()),
                SocketAddrV4::new(FAKE_SERVER_IP_ADDR, server_addr.port()),
                &mut client_seq_number,
                server_seq_number,
            ),
            PeerSide::Server => (
                &mut server_acc,
                SocketAddrV4::new(FAKE_SERVER_IP_ADDR, server_addr.port()),
                SocketAddrV4::new(FAKE_CLIENT_IP_ADDR, client_addr.port()),
                &mut server_seq_number,
                client_seq_number,
            ),
        };

        acc.extend_from_slice(&bytes);

        let messages = dissector.dissect_all(side, acc);

        for message in messages {
            // Build TCP/IP packet.
            let mut tcp_ip_packet = Vec::new();
            PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
                .ipv4(source_addr.ip().octets(), dest_addr.ip().octets(), 128)
                .tcp(dest_addr.port(), dest_addr.port(), *seq_number, 0x7fff)
                .ack(ack_number)
                .syn()
                .write(&mut tcp_ip_packet, &message)
                .expect("enough memory for serializing and writing the TCP/IP packet");

            // Write packet in pcap file.
            let since_epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("now after UNIX_EPOCH");

            let packet = PcapPacket::new(
                since_epoch,
                u32::try_from(tcp_ip_packet.len()).expect("packet length not too big"),
                &tcp_ip_packet,
            );

            if let Err(error) = pcap_writer.write_packet(&packet) {
                error!(%error, "Failed to write the packet into the pcap file");
            }

            // Update the seq_number.
            *seq_number += u32::try_from(message.len()).expect("message not too big");
        }
    }

    debug!(%client_addr, %server_addr, "PCAP writer task terminated");
}
