use std::net::Ipv4Addr;

use bytes::{BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};

/// IP protocol number for our relay protocol (253 = experimental)
pub const RELAY_PROTOCOL_NUMBER: u8 = 253;

/// Minimum IPv4 header size (no options)
const IPV4_HEADER_SIZE: usize = 20;

/// Build an IPv4 packet containing relay protocol payload
///
/// # Arguments
/// * `src_ip` - Source IP address (agent's tunnel IP)
/// * `dst_ip` - Destination IP address (gateway's tunnel IP)
/// * `payload` - Relay protocol message bytes
///
/// # Returns
/// Complete IPv4 packet ready to send through WireGuard tunnel
///
/// # Packet Format
/// ```text
/// IPv4 Header (20 bytes):
/// ┌────────┬────────┬─────────────┬─────────────┬───────────┬──────┬────────┬─────────────┐
/// │ Ver/HL │  DSCP  │ Total Len   │ Ident       │ Flags/Off │ TTL  │ Proto  │ Checksum    │
/// │ (1B)   │ (1B)   │ (2B)        │ (2B)        │ (2B)      │ (1B) │ (1B)   │ (2B)        │
/// ├────────┴────────┴─────────────┴─────────────┴───────────┴──────┴────────┴─────────────┤
/// │ Source IP (4B)                                                                         │
/// ├────────────────────────────────────────────────────────────────────────────────────────┤
/// │ Destination IP (4B)                                                                    │
/// └────────────────────────────────────────────────────────────────────────────────────────┘
/// Payload (variable):
/// ┌────────────────────────────────────────────────────────────────────────────────────────┐
/// │ Relay Protocol Message                                                                 │
/// └────────────────────────────────────────────────────────────────────────────────────────┘
/// ```
pub fn build_ip_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, payload: &[u8]) -> Result<Bytes> {
    let total_len = IPV4_HEADER_SIZE + payload.len();

    if total_len > 65535 {
        return Err(Error::InvalidIpPacket(format!("packet too large: {} bytes", total_len)));
    }

    let mut buf = BytesMut::with_capacity(total_len);

    // Byte 0: Version (4) + IHL (5 = 20 bytes)
    buf.put_u8(0x45); // IPv4, 20-byte header

    // Byte 1: DSCP/ECN (0 = default)
    buf.put_u8(0x00);

    // Bytes 2-3: Total length (big-endian)
    buf.put_u16(u16::try_from(total_len).expect("validated IPv4 packet length should fit into u16"));

    // Bytes 4-5: Identification (0 = not used)
    buf.put_u16(0x0000);

    // Bytes 6-7: Flags + Fragment offset (0x4000 = Don't Fragment)
    buf.put_u16(0x4000);

    // Byte 8: TTL (64 hops)
    buf.put_u8(64);

    // Byte 9: Protocol (253 = experimental, for our relay protocol)
    buf.put_u8(RELAY_PROTOCOL_NUMBER);

    // Bytes 10-11: Header checksum (calculate later)
    let checksum_offset = buf.len();
    buf.put_u16(0x0000); // Placeholder

    // Bytes 12-15: Source IP
    buf.put_slice(&src_ip.octets());

    // Bytes 16-19: Destination IP
    buf.put_slice(&dst_ip.octets());

    // Calculate and insert header checksum
    let checksum = calculate_ipv4_checksum(&buf[..IPV4_HEADER_SIZE]);
    buf[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());

    // Append payload
    buf.put_slice(payload);

    Ok(buf.freeze())
}

/// Extract relay protocol payload from an IPv4 packet
///
/// # Arguments
/// * `ip_packet` - Complete IPv4 packet bytes
///
/// # Returns
/// Relay protocol message bytes (without IP header)
pub fn extract_payload(ip_packet: &[u8]) -> Result<Bytes> {
    if ip_packet.len() < IPV4_HEADER_SIZE {
        return Err(Error::PacketTooSmall {
            size: ip_packet.len(),
            min: IPV4_HEADER_SIZE,
        });
    }

    // Extract header length (in 32-bit words)
    let version_ihl = ip_packet[0];
    let version = version_ihl >> 4;
    let ihl = (version_ihl & 0x0F) as usize;

    if version != 4 {
        return Err(Error::InvalidIpPacket(format!("not IPv4: version = {}", version)));
    }

    let header_len = ihl * 4;

    if header_len < IPV4_HEADER_SIZE {
        return Err(Error::InvalidIpPacket(format!(
            "header too small: {} bytes",
            header_len
        )));
    }

    // Verify protocol number
    let protocol = ip_packet[9];
    if protocol != RELAY_PROTOCOL_NUMBER {
        return Err(Error::ProtocolMismatch {
            expected: RELAY_PROTOCOL_NUMBER,
            actual: protocol,
        });
    }

    // Extract payload
    if ip_packet.len() < header_len {
        return Err(Error::PacketTooSmall {
            size: ip_packet.len(),
            min: header_len,
        });
    }

    Ok(Bytes::copy_from_slice(&ip_packet[header_len..]))
}

/// Calculate IPv4 header checksum
///
/// # Arguments
/// * `header` - IPv4 header bytes (20 bytes, with checksum field set to 0)
///
/// # Returns
/// 16-bit checksum in host byte order
fn calculate_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum all 16-bit words
    for i in (0..header.len()).step_by(2) {
        let word = u16::from_be_bytes([header[i], header[i + 1]]);
        sum += u32::from(word);
    }

    // Fold carry bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    u16::try_from(!sum & 0xFFFF).expect("folded IPv4 checksum should fit into u16")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_extract_packet() {
        let src_ip = Ipv4Addr::new(10, 10, 0, 2);
        let dst_ip = Ipv4Addr::new(10, 10, 0, 1);
        let payload = b"Hello, WireGuard tunnel!";

        // Build packet
        let packet = build_ip_packet(src_ip, dst_ip, payload).expect("packet should build");

        // Verify header
        assert_eq!(packet.len(), IPV4_HEADER_SIZE + payload.len());
        assert_eq!(packet[0], 0x45); // IPv4, 20-byte header
        assert_eq!(packet[9], RELAY_PROTOCOL_NUMBER);

        // Verify source and destination IPs
        assert_eq!(&packet[12..16], &src_ip.octets());
        assert_eq!(&packet[16..20], &dst_ip.octets());

        // Extract payload
        let extracted = extract_payload(&packet).expect("payload should extract");
        assert_eq!(&extracted[..], payload);
    }

    #[test]
    fn test_checksum_calculation() {
        // Example packet from RFC 1071
        let header = [
            0x45, 0x00, 0x00, 0x3c, // Version/IHL, DSCP, Total Length
            0x1c, 0x46, 0x40, 0x00, // ID, Flags/Offset
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol, Checksum (0)
            0xac, 0x10, 0x0a, 0x63, // Source IP
            0xac, 0x10, 0x0a, 0x0c, // Dest IP
        ];

        let checksum = calculate_ipv4_checksum(&header);
        // The checksum should be non-zero for valid headers
        assert_ne!(checksum, 0);

        // Build a packet and verify checksum is calculated
        let packet = build_ip_packet(Ipv4Addr::new(172, 16, 10, 99), Ipv4Addr::new(172, 16, 10, 12), b"test")
            .expect("packet should build");

        // Extract checksum from packet
        let packet_checksum = u16::from_be_bytes([packet[10], packet[11]]);
        assert_ne!(packet_checksum, 0);
    }

    #[test]
    fn test_extract_payload_invalid_version() {
        let mut packet = vec![0u8; IPV4_HEADER_SIZE];
        packet[0] = 0x60; // IPv6

        let result = extract_payload(&packet);
        assert!(matches!(result, Err(Error::InvalidIpPacket(_))));
    }

    #[test]
    fn test_extract_payload_wrong_protocol() {
        let packet = build_ip_packet(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), b"test")
            .expect("packet should build");

        // Modify protocol field to TCP (6)
        let mut modified = packet.to_vec();
        modified[9] = 6;

        let result = extract_payload(&modified);
        assert!(matches!(
            result,
            Err(Error::ProtocolMismatch {
                expected: RELAY_PROTOCOL_NUMBER,
                actual: 6
            })
        ));
    }

    #[test]
    fn test_packet_too_small() {
        let small_packet = vec![0u8; 10];
        let result = extract_payload(&small_packet);

        assert!(matches!(result, Err(Error::PacketTooSmall { size: 10, min: 20 })));
    }

    #[test]
    fn test_empty_payload() {
        let src_ip = Ipv4Addr::new(10, 10, 0, 2);
        let dst_ip = Ipv4Addr::new(10, 10, 0, 1);
        let payload = b"";

        let packet = build_ip_packet(src_ip, dst_ip, payload).expect("packet should build");
        assert_eq!(packet.len(), IPV4_HEADER_SIZE);

        let extracted = extract_payload(&packet).expect("payload should extract");
        assert!(extracted.is_empty());
    }

    #[test]
    fn test_large_payload() {
        let src_ip = Ipv4Addr::new(10, 10, 0, 2);
        let dst_ip = Ipv4Addr::new(10, 10, 0, 1);
        let payload = vec![0xAB; 1024]; // 1KB payload

        let packet = build_ip_packet(src_ip, dst_ip, &payload).expect("packet should build");
        assert_eq!(packet.len(), IPV4_HEADER_SIZE + 1024);

        let extracted = extract_payload(&packet).expect("payload should extract");
        assert_eq!(extracted.len(), 1024);
        assert_eq!(extracted[0], 0xAB);
    }
}
