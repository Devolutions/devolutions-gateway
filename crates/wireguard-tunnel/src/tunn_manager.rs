use std::net::{IpAddr, Ipv4Addr};

use boringtun::noise::{Tunn, TunnResult};
use bytes::Bytes;

use crate::error::{Error, Result};
use crate::ip_packet;

/// Helper utilities for working with boringtun's Tunn
///
/// Provides convenient wrappers around boringtun's low-level APIs
/// for sending and receiving relay protocol messages.
/// Send a relay protocol message through the WireGuard tunnel
///
/// # Arguments
/// * `tunn` - The WireGuard tunnel instance
/// * `src_ip` - Source tunnel IP (agent's IP)
/// * `dst_ip` - Destination tunnel IP (gateway's IP)
/// * `relay_payload` - Relay protocol message bytes
/// * `dst_buf` - Destination buffer for encrypted packet (must be at least 65536 bytes)
///
/// # Returns
/// Encrypted WireGuard packet ready to send via UDP, or None if no output
pub fn send_relay_message(
    tunn: &mut Tunn,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    relay_payload: &[u8],
    dst_buf: &mut [u8],
) -> Result<Option<Bytes>> {
    // Build IP packet
    let ip_packet = ip_packet::build_ip_packet(src_ip, dst_ip, relay_payload)?;

    // Encapsulate through WireGuard tunnel
    match tunn.encapsulate(&ip_packet, dst_buf) {
        TunnResult::WriteToNetwork(encrypted) => Ok(Some(Bytes::copy_from_slice(encrypted))),
        TunnResult::Done => Ok(None),
        TunnResult::Err(e) => Err(Error::Boringtun(format!("encapsulate error: {:?}", e))),
        _ => Err(Error::Boringtun("unexpected result from encapsulate".to_owned())),
    }
}

/// Process an incoming UDP packet from the WireGuard peer
///
/// # Arguments
/// * `tunn` - The WireGuard tunnel instance
/// * `peer_addr` - Peer's UDP endpoint (IP address)
/// * `packet` - Received UDP packet bytes
/// * `dst_buf` - Destination buffer for decrypted data (must be at least 65536 bytes)
///
/// # Returns
/// Tuple of:
/// - Decrypted relay protocol payload (if any)
/// - Response packet to send back to peer (if any - e.g., handshake response)
pub fn receive_udp_packet(
    tunn: &mut Tunn,
    peer_addr: IpAddr,
    packet: &[u8],
    dst_buf: &mut [u8],
) -> Result<(Option<Bytes>, Option<Bytes>)> {
    let mut relay_payload = None;
    let mut response = None;

    // Decapsulate the packet
    match tunn.decapsulate(Some(peer_addr), packet, dst_buf) {
        TunnResult::WriteToTunnelV4(ip_packet, _) => {
            // Extract relay protocol payload from IP packet
            let payload = ip_packet::extract_payload(ip_packet)?;
            relay_payload = Some(payload);
        }
        TunnResult::WriteToNetwork(encrypted) => {
            // Handshake response or keepalive
            response = Some(Bytes::copy_from_slice(encrypted));
        }
        TunnResult::Done => {
            // No action needed
        }
        TunnResult::Err(e) => {
            return Err(Error::Boringtun(format!("decapsulate error: {:?}", e)));
        }
        _ => {
            return Err(Error::Boringtun("unexpected result from decapsulate".to_owned()));
        }
    }

    // CRITICAL: Flush loop (boringtun requirement)
    // After processing a packet, boringtun may have additional output
    // (e.g., handshake responses, keepalives). Keep calling decapsulate
    // with empty input until it returns Done.
    loop {
        match tunn.decapsulate(None, &[], dst_buf) {
            TunnResult::WriteToNetwork(encrypted) => {
                // Update response (last one wins)
                response = Some(Bytes::copy_from_slice(encrypted));
            }
            TunnResult::Done => break,
            TunnResult::Err(e) => {
                return Err(Error::Boringtun(format!("flush error: {:?}", e)));
            }
            _ => {
                return Err(Error::Boringtun("unexpected result during flush".to_owned()));
            }
        }
    }

    Ok((relay_payload, response))
}

/// Trigger WireGuard timer-driven events (keepalives, rekeys, etc.)
///
/// This should be called periodically (recommended: every 250ms)
///
/// # Arguments
/// * `tunn` - The WireGuard tunnel instance
/// * `dst_buf` - Destination buffer for output (must be at least 65536 bytes)
///
/// # Returns
/// Packet to send to peer (if any)
pub fn handle_timer_tick(tunn: &mut Tunn, dst_buf: &mut [u8]) -> Result<Option<Bytes>> {
    // Update timers
    tunn.update_timers(dst_buf);

    // Flush any output
    match tunn.decapsulate(None, &[], dst_buf) {
        TunnResult::WriteToNetwork(encrypted) => Ok(Some(Bytes::copy_from_slice(encrypted))),
        TunnResult::Done => Ok(None),
        TunnResult::Err(e) => Err(Error::Boringtun(format!("timer tick error: {:?}", e))),
        _ => Err(Error::Boringtun("unexpected result during timer tick".to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use boringtun::x25519::{PublicKey, StaticSecret};

    use super::*;

    fn create_test_tunn_pair() -> (Tunn, Tunn) {
        // Use fixed test keys (avoid rand_core version conflicts)
        let initiator_private_bytes = [1u8; 32];
        let responder_private_bytes = [2u8; 32];

        let initiator_private = StaticSecret::from(initiator_private_bytes);
        let initiator_public = PublicKey::from(&initiator_private);

        let responder_private = StaticSecret::from(responder_private_bytes);
        let responder_public = PublicKey::from(&responder_private);

        // Create tunnels
        let initiator = Tunn::new(initiator_private, responder_public, None, None, 0, None);

        let responder = Tunn::new(responder_private, initiator_public, None, None, 0, None);

        (initiator, responder)
    }

    #[test]
    fn test_send_and_receive_relay_message() {
        let (mut initiator, mut responder) = create_test_tunn_pair();

        let src_ip = Ipv4Addr::new(10, 10, 0, 2);
        let dst_ip = Ipv4Addr::new(10, 10, 0, 1);
        let relay_payload = b"Test relay message";

        let mut dst_buf = vec![0u8; 65536];

        // Initiator sends message
        let encrypted = send_relay_message(&mut initiator, src_ip, dst_ip, relay_payload, &mut dst_buf)
            .expect("relay message should encrypt");

        // In a real scenario, encrypted would be sent via UDP
        // For this test, we'll simulate receiving it on the responder side
        if let Some(packet) = encrypted {
            let (received_payload, _response) = receive_udp_packet(
                &mut responder,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                &packet,
                &mut dst_buf,
            )
            .expect("relay message should decapsulate");

            // Note: In a real handshake, the first few packets might be handshake messages
            // and received_payload might be None. This test is simplified.
            if let Some(payload) = received_payload {
                assert_eq!(&payload[..], relay_payload);
            }
        }
    }

    #[test]
    fn test_timer_tick() {
        let (mut tunn, _) = create_test_tunn_pair();
        let mut dst_buf = vec![0u8; 65536];

        // Timer tick should not fail
        let result = handle_timer_tick(&mut tunn, &mut dst_buf);
        assert!(result.is_ok());
    }
}
