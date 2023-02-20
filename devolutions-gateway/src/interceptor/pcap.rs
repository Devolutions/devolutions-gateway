use crate::interceptor::{Dissector, Inspector, PeerSide};
use anyhow::Context as _;
use bytes::BytesMut;
use packet::builder::Builder;
use packet::ether::{Builder as BuildEthernet, Protocol};
use packet::ip::v6::Builder as BuildV6;
use packet::tcp::flag::Flags;
use pcap_file::pcap::{PcapPacket, PcapWriter};
use std::fs::File;
use std::net::SocketAddr;
use std::path::Path;
use tokio::sync::mpsc;

const TCP_IP_PACKET_MAX_SIZE: usize = 16384;

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
        pcap_filename: impl AsRef<Path>,
        dissector: impl Dissector + Send + 'static,
    ) -> anyhow::Result<(Self, Self)> {
        let file = File::create(pcap_filename).context("Error creating file")?;
        let pcap_writer = PcapWriter::new(file).context("Error creating pcap writer")?;

        let (sender, receiver) = mpsc::unbounded_channel();

        tokio::spawn(writer_task(receiver, pcap_writer, client_addr, server_addr, dissector));

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
    server_addr: SocketAddr,
    client_addr: SocketAddr,
    mut dissector: impl Dissector,
) {
    let mut server_seq_number = 0;
    let mut server_acc = BytesMut::new();

    let mut client_seq_number = 0;
    let mut client_acc = BytesMut::new();

    while let Some((side, bytes)) = receiver.recv().await {
        debug!("New packet intercepted. Packet size = {}", bytes.len());

        let (acc, source_addr, dest_addr, seq_number, ack_number) = match side {
            PeerSide::Client => (
                &mut client_acc,
                client_addr,
                server_addr,
                &mut client_seq_number,
                server_seq_number,
            ),
            PeerSide::Server => (
                &mut server_acc,
                server_addr,
                client_addr,
                &mut server_seq_number,
                client_seq_number,
            ),
        };

        acc.extend_from_slice(&bytes);

        let messages = dissector.dissect_all(side, acc);

        for data in messages {
            for data_chunk in data.chunks(TCP_IP_PACKET_MAX_SIZE) {
                // Build tcpip packet
                let tcpip_packet = match (source_addr, dest_addr) {
                    (SocketAddr::V4(source), SocketAddr::V4(dest)) => {
                        BuildEthernet::default()
                            .destination([0x00, 0x15, 0x5D, 0x01, 0x64, 0x04].into())
                            .unwrap() // 00:15:5D:01:64:04
                            .source([0x00, 0x15, 0x5D, 0x01, 0x64, 0x01].into())
                            .unwrap() // 00:15:5D:01:64:01
                            .protocol(Protocol::Ipv4)
                            .unwrap()
                            .ip()
                            .unwrap()
                            .v4()
                            .unwrap()
                            .source(*source.ip())
                            .unwrap()
                            .destination(*dest.ip())
                            .unwrap()
                            .ttl(128)
                            .unwrap()
                            .tcp()
                            .unwrap()
                            .window(0x7fff)
                            .unwrap()
                            .source(source_addr.port())
                            .unwrap()
                            .destination(dest_addr.port())
                            .unwrap()
                            .acknowledgment(ack_number)
                            .unwrap()
                            .sequence(*seq_number)
                            .unwrap()
                            .flags(Flags::from_bits_truncate(0x0018))
                            .unwrap()
                            .payload(data_chunk)
                            .unwrap()
                            .build()
                            .unwrap()
                    }
                    (SocketAddr::V6(_source), SocketAddr::V6(_dest)) => BuildV6::default().build().unwrap(),
                    (_, _) => unreachable!(),
                };

                // Write packet in pcap file
                let since_epoch = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("Time went backwards");

                let packet = PcapPacket::new(since_epoch, tcpip_packet.len() as u32, &tcpip_packet);

                if let Err(e) = pcap_writer.write_packet(&packet) {
                    error!("Error writing pcap file: {}", e);
                }

                // Update the seq_number
                *seq_number += data_chunk.len() as u32;
            }
        }
    }
}
