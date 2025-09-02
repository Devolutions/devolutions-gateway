#![allow(unused_crate_dependencies)]

//! Integration tests for traffic-audit-libsql implementation.
//!
//! These tests verify the complete claim/ack lifecycle with proper multi-consumer
//! semantics, lease management, and data integrity.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tokio::time::sleep;
use traffic_audit::{EventOutcome, TrafficAuditRepo, TrafficEvent, TransportProtocol};
use traffic_audit_libsql::LibSqlTrafficAuditRepo;
use uuid::Uuid;

/// Opens a new repository instance with migrations applied.
///
/// This ensures the database file exists and is properly initialized
/// before running test operations.
async fn open_repo(path_or_url: &str) -> LibSqlTrafficAuditRepo {
    let repo = LibSqlTrafficAuditRepo::open(path_or_url)
        .await
        .expect("open repository");
    repo.setup().await.expect("setup repository");
    repo
}

/// Creates a test TrafficEvent with varying fields based on index.
///
/// This generates diverse events for testing different scenarios:
/// - Different outcomes, protocols, hosts, IPs, ports
/// - Varying byte counts and timing
/// - Unicode host names for some events
fn make_event(i: u32) -> TrafficEvent {
    let base_time = 1_700_000_000_000i64; // Nov 2023 in milliseconds
    let connect_time = base_time + (i as i64 * 1000); // 1 second apart
    let active_duration = (i as i64 % 5000) + 100; // 100-5099ms

    TrafficEvent {
        session_id: Uuid::new_v4(),
        outcome: match i % 3 {
            0 => EventOutcome::ConnectFailure,
            1 => EventOutcome::NormalTermination,
            _ => EventOutcome::AbnormalTermination,
        },
        protocol: if i % 4 == 0 {
            TransportProtocol::Udp
        } else {
            TransportProtocol::Tcp
        },
        target_host: if i % 7 == 0 {
            format!("tést-{}.不適切.invalid", i) // Unicode test
        } else {
            format!("host-{}.example.com", i)
        },
        target_ip: if i % 5 == 0 {
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16))
        } else {
            IpAddr::V4(Ipv4Addr::new(192, 168, (i / 256) as u8, (i % 256) as u8))
        },
        target_port: ((i % 60000) + 1024) as u16, // 1024-61023
        connect_at_ms: connect_time,
        disconnect_at_ms: connect_time + active_duration,
        active_duration_ms: active_duration,
        bytes_tx: (i as u64) * 1024, // Varying sizes
        bytes_rx: (i as u64) * 512,
    }
}

/// Test database migration and PRAGMA application.
///
/// This is one of the few tests that can run immediately since it only
/// tests the setup functionality without requiring full implementation.
#[tokio::test(flavor = "current_thread")]
async fn migrations_and_pragmas_applied() {
    // If this doesn't panic or return errors, setup succeeded - migrations and PRAGMAs were applied.
    let _repo = open_repo(":memory:").await;
}

/// Happy path: push events, claim them, then ack - should work end-to-end.
///
/// **Expected behavior**:
/// - Push N=3 events successfully
/// - Claim with max=10, lease=30s, consumer="t1" returns all 3 events
/// - Events have correct field values
/// - After ack, subsequent claim returns empty
#[tokio::test(flavor = "current_thread")]
async fn push_then_claim_then_ack_happy_path() {
    let repo = open_repo(":memory:").await;

    // Push 3 test events.
    let events: Vec<_> = (0..3).map(make_event).collect();
    for event in &events {
        repo.push(event.clone()).await.expect("push event");
    }

    // Claim them all.
    let claimed = repo.claim("t1", 30_000, 10).await.expect("claim events");
    assert_eq!(claimed.len(), 3, "should claim all 3 events");

    // Verify event data is preserved.
    for (claimed_event, original) in claimed.iter().zip(&events) {
        assert_eq!(claimed_event.event.session_id, original.session_id);
        assert_eq!(claimed_event.event.outcome, original.outcome);
        assert_eq!(claimed_event.event.target_host, original.target_host);
        assert_eq!(claimed_event.event.target_ip, original.target_ip);
    }

    // Ack all events.
    let ids: Vec<i64> = claimed.iter().map(|e| e.id).collect();
    repo.ack(&ids).await.expect("ack events");

    // Subsequent claim should return nothing.
    let claimed2 = repo.claim("t2", 30_000, 10).await.expect("second claim");
    assert_eq!(claimed2.len(), 0, "no events should remain after ack");
}

/// Multiple consumers should get disjoint sets of events.
///
/// **Expected behavior**:
/// - Push N=200 events
/// - Spawn 2 tasks claiming concurrently in batches of 25 with same lease duration
/// - Union of all claimed IDs should equal 200
/// - Intersection of claimed ID sets should be empty (no duplicates)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_claimers_get_disjoint_sets() {
    let tmp_dir = tempfile::TempDir::new().unwrap();
    let db_path = tmp_dir.path().join("concurrent_claimers_get_disjoint_sets");
    let repo = open_repo(db_path.to_str().unwrap()).await;

    // Push 200 events.
    let events: Vec<_> = (0..200).map(make_event).collect();
    for event in events {
        repo.push(event).await.expect("push event");
    }

    let consumer1_repo = open_repo(db_path.to_str().unwrap()).await;
    let consumer2_repo = open_repo(db_path.to_str().unwrap()).await;

    // Create two consumers that claim concurrently (and in parallel, because multi-thread flavor).
    let task1 = tokio::spawn(claim_all_in_batches(consumer1_repo, "consumer1", 30_000, 25));
    let task2 = tokio::spawn(claim_all_in_batches(consumer2_repo, "consumer2", 30_000, 25));

    let claimed1 = task1.await.unwrap();
    let claimed2 = task2.await.unwrap();

    // Collect all IDs.
    let ids1: HashSet<i64> = claimed1.into_iter().collect();
    let ids2: HashSet<i64> = claimed2.into_iter().collect();

    // Verify no overlap (disjoint sets).
    assert_eq!(
        ids1.intersection(&ids2).count(),
        0,
        "consumers should get disjoint event sets"
    );

    // Verify complete coverage.
    assert_eq!(
        ids1.len() + ids2.len(),
        200,
        "all events should be claimed exactly once"
    );
}

async fn claim_all_in_batches(
    repo: LibSqlTrafficAuditRepo,
    consumer_id: &str,
    lease_ms: i64,
    batch_size: usize,
) -> Vec<i64> {
    let mut all_ids = Vec::new();

    loop {
        let claimed = repo
            .claim(consumer_id, lease_ms, batch_size)
            .await
            .expect("claim batch");

        if claimed.is_empty() {
            break;
        }

        // Extract IDs and ack immediately.
        let ids: Vec<i64> = claimed.iter().map(|e| e.id).collect();
        repo.ack(&ids).await.expect("ack batch");
        all_ids.extend(ids);

        // Small delay to allow other consumer to interleave.
        sleep(Duration::from_millis(1)).await;
    }

    all_ids
}

/// Lease expiry should allow events to be reclaimed by other consumers.
///
/// **Expected behavior**:
/// - Push 5 events
/// - Consumer c1 claims with short lease (100ms)
/// - Sleep 150ms to expire lease
/// - Consumer c2 should be able to claim the same events
#[tokio::test(flavor = "current_thread")]
async fn lease_expiry_reclaim() {
    let repo = open_repo(":memory:").await;

    // Push 5 events.
    for i in 0..5 {
        repo.push(make_event(i)).await.expect("push event");
    }

    // Consumer 1 claims with short lease.
    let claimed1 = repo.claim("c1", 100, 10).await.expect("c1 claim");
    assert_eq!(claimed1.len(), 5, "c1 should claim all 5 events");

    // Sleep to expire lease.
    sleep(Duration::from_millis(150)).await;

    // Consumer 2 should now be able to claim the same events.
    let claimed2 = repo.claim("c2", 30_000, 10).await.expect("c2 claim");
    assert_eq!(claimed2.len(), 5, "c2 should claim all 5 events after lease expiry");

    // Verify same events were reclaimed (not new ones).
    let ids1: HashSet<i64> = claimed1.iter().map(|e| e.id).collect();
    let ids2: HashSet<i64> = claimed2.iter().map(|e| e.id).collect();
    assert_eq!(ids1, ids2, "same events should be reclaimed after lease expiry");
}

/// Event IDs should be returned in monotonic ascending order.
///
/// **Expected behavior**:
/// - Push 20 events
/// - Claim 7 events repeatedly
/// - Collected ID sequence should be strictly increasing
/// - No gaps or duplicates in the sequence
#[tokio::test(flavor = "current_thread")]
async fn ordering_is_monotonic_id_asc() {
    let repo = open_repo(":memory:").await;

    // Push 20 events.
    for i in 0..20 {
        repo.push(make_event(i)).await.expect("push event");
    }

    let mut all_ids = Vec::new();

    // Claim in batches of 7.
    loop {
        let claimed = repo.claim("consumer", 30_000, 7).await.expect("claim");
        if claimed.is_empty() {
            break;
        }

        let ids: Vec<i64> = claimed.iter().map(|e| e.id).collect();
        repo.ack(&ids).await.expect("ack");
        all_ids.extend(ids);
    }

    assert_eq!(all_ids.len(), 20, "should process all 20 events");

    // Verify strict ascending order.
    for i in 1..all_ids.len() {
        assert!(
            all_ids[i] > all_ids[i - 1],
            "IDs should be in strict ascending order: {} > {}",
            all_ids[i],
            all_ids[i - 1]
        );
    }
}

/// Unicode hostnames and IPv6 addresses should round-trip correctly.
///
/// **Expected behavior**:
/// - Push event with Unicode hostname and IPv6 address
/// - Claim and verify exact field preservation
/// - Special characters and full IPv6 range should be supported
#[tokio::test(flavor = "current_thread")]
async fn unicode_and_ipv6_roundtrip() {
    let repo = open_repo(":memory:").await;

    let mut event = make_event(0);
    event.target_host = "tést-{}.不適切.invalid".to_string(); // Unicode characters
    event.target_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0, 0, 0x8a2e, 0x370, 0x7334));

    repo.push(event.clone()).await.expect("push unicode event");

    let claimed = repo.claim("consumer", 30_000, 1).await.expect("claim");
    assert_eq!(claimed.len(), 1, "should claim the unicode event");

    let claimed_event = &claimed[0].event;
    assert_eq!(
        claimed_event.target_host, event.target_host,
        "Unicode hostname should be preserved"
    );
    assert_eq!(
        claimed_event.target_ip, event.target_ip,
        "IPv6 address should be preserved"
    );
}

/// Port and byte count boundary values should be handled correctly.
///
/// **Expected behavior**:
/// - Test port values 0 and 65535 (boundary values)
/// - Test large byte counts (close to u64 max)
/// - Verify no overflow or truncation occurs
/// - All values should round-trip exactly
#[tokio::test(flavor = "current_thread")]
async fn port_and_bytes_ranges() {
    let repo = open_repo(":memory:").await;

    // Test boundary values
    let test_cases = vec![
        (0u16, 0u64, 0u64),                            // Minimum values
        (65535u16, i64::MAX as u64, i64::MAX as u64),  // Maximum storable values
        (8080u16, 1_000_000_000u64, 2_000_000_000u64), // Large but reasonable
    ];

    for (port, bytes_tx, bytes_rx) in test_cases {
        let mut event = make_event(0);
        event.target_port = port;
        event.bytes_tx = bytes_tx;
        event.bytes_rx = bytes_rx;

        repo.push(event.clone()).await.expect("push boundary event");

        let claimed = repo.claim("consumer", 30_000, 1).await.expect("claim");
        assert_eq!(claimed.len(), 1, "should claim boundary event");

        let claimed_event = &claimed[0].event;
        assert_eq!(claimed_event.target_port, port, "port should be preserved");
        assert_eq!(claimed_event.bytes_tx, bytes_tx, "bytes_tx should be preserved");
        assert_eq!(claimed_event.bytes_rx, bytes_rx, "bytes_rx should be preserved");

        repo.ack(&[claimed[0].id]).await.expect("ack boundary event");
    }
}

/// Lease extension should update event visibility correctly.
///
/// **Expected behavior**:
/// - Consumer c1 claims events with initial lease
/// - c1 extends lease on claimed events
/// - Consumer c2 cannot claim until extended lease expires
/// - After extended lease expires, c2 can claim
#[tokio::test(flavor = "current_thread")]
async fn extend_lease_updates_visibility() {
    let repo = open_repo(":memory:").await;

    // Push 3 events
    for i in 0..3 {
        repo.push(make_event(i)).await.expect("push event");
    }

    // Consumer 1 claims with very short initial lease
    let claimed1 = repo.claim("c1", 50, 10).await.expect("c1 initial claim");
    assert_eq!(claimed1.len(), 3, "c1 should claim all events");

    let ids: Vec<i64> = claimed1.iter().map(|e| e.id).collect();

    // Wait for original lease to definitely expire
    sleep(Duration::from_millis(60)).await;

    // CRITICAL: Consumer 2 should NOT be able to extend c1's lease
    // If the "AND locked_by = ?" condition is missing, this would incorrectly succeed
    repo.extend_lease(&ids, "c2", 50)
        .await
        .expect("c2 extend lease call should not fail");

    // After c2's incorrect extend attempt, c2 should still be able to claim the events
    // because c2 shouldn't have been able to extend c1's lease
    let claimed2 = repo
        .claim("c2", 30_000, 10)
        .await
        .expect("c2 claim after c2 tried to extend c1's lease");
    assert_eq!(
        claimed2.len(),
        3,
        "c2 should claim all events because c2 cannot extend c1's lease (consumer isolation)"
    );

    // Ack the events claimed by c2
    let ids2: Vec<i64> = claimed2.iter().map(|e| e.id).collect();
    repo.ack(&ids2).await.expect("ack c2 events");

    // Push new events for the rest of the test
    for i in 10..13 {
        repo.push(make_event(i)).await.expect("push new event");
    }

    // Now test the proper extend_lease functionality
    let claimed3 = repo.claim("c1", 50, 10).await.expect("c1 claim new events");
    assert_eq!(claimed3.len(), 3, "c1 should claim new events");

    let ids3: Vec<i64> = claimed3.iter().map(|e| e.id).collect();

    // Wait for original lease to expire
    sleep(Duration::from_millis(60)).await;

    // c1 extends its own lease (this should work)
    repo.extend_lease(&ids3, "c1", 50).await.expect("c1 extend own lease");

    // c2 should not be able to claim because c1 properly extended the lease
    let claimed4 = repo
        .claim("c2", 30_000, 10)
        .await
        .expect("c2 claim after c1 extended own lease");
    assert_eq!(
        claimed4.len(),
        0,
        "c2 should not claim events because c1 extended its own lease"
    );

    // Wait for extended lease to expire (50ms from extension call)
    sleep(Duration::from_millis(60)).await;

    // Now c2 should be able to claim since extended lease has expired
    let claimed3 = repo
        .claim("c2", 30_000, 10)
        .await
        .expect("c2 after extended lease expires");
    assert_eq!(claimed3.len(), 3, "c2 should claim after extended lease expires");
}

/// Stress test for concurrent claim operations ensuring exactly-once semantics.
///
/// **Implementation Note**: This test uses multi_thread flavor to create real
/// concurrency and race conditions. It should be the only multi_thread test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_claim_stress_exactly_once() {
    const NUM_EVENTS: u32 = 1000;
    const NUM_CONSUMERS: usize = 4;
    const BATCH_SIZE: usize = 50;

    let tmp_dir = tempfile::TempDir::new().unwrap();
    let db_path = tmp_dir.path().join("concurrent_claim_stress_exactly_once");
    let repo = open_repo(db_path.to_str().unwrap()).await;

    // Push events.
    for i in 0..NUM_EVENTS {
        repo.push(make_event(i)).await.expect("push event");
    }

    // Start multiple concurrent consumers.
    let consumers: Vec<_> = (0..NUM_CONSUMERS)
        .map(|i| {
            let consumer_id = format!("stress_consumer_{}", i);
            let db_path = db_path.clone();
            tokio::spawn(async move {
                let repo = open_repo(db_path.to_str().unwrap()).await;
                claim_all_in_batches(repo, &consumer_id, 5_000, BATCH_SIZE).await
            })
        })
        .collect();

    // Wait for all consumers to complete.
    let mut all_claimed_ids = HashSet::new();
    for consumer in consumers {
        let claimed_ids = consumer.await.expect("consumer task");
        // Verify no duplicate IDs across consumers
        for id in claimed_ids {
            assert!(
                all_claimed_ids.insert(id),
                "ID {} was claimed by multiple consumers",
                id
            );
        }
    }

    // Verify all events were processed exactly once
    assert_eq!(
        all_claimed_ids.len(),
        NUM_EVENTS as usize,
        "all events should be processed exactly once"
    );
}

/// Basic throughput sanity check with 10k events.
///
/// **Expected behavior**:
/// - Process 10,000 events in reasonable time (< 5 seconds)
/// - All events should be processed without errors
/// - Memory usage should remain reasonable
#[tokio::test(flavor = "current_thread")]
async fn throughput_10k_events_sanity_check() {
    let repo = open_repo(":memory:").await;

    const NUM_EVENTS: u32 = 10_000;
    let start = std::time::Instant::now();

    // Push events in batches for better performance
    for batch_start in (0..NUM_EVENTS).step_by(100) {
        for i in batch_start..(batch_start + 100).min(NUM_EVENTS) {
            repo.push(make_event(i)).await.expect("push event");
        }
    }

    let push_elapsed = start.elapsed();
    println!("Pushed {} events in {:?}", NUM_EVENTS, push_elapsed);

    // Process all events
    let mut processed = 0;
    let process_start = std::time::Instant::now();

    loop {
        let claimed = repo.claim("throughput_test", 30_000, 500).await.expect("claim batch");

        if claimed.is_empty() {
            break;
        }

        let ids: Vec<i64> = claimed.iter().map(|e| e.id).collect();
        repo.ack(&ids).await.expect("ack batch");
        processed += claimed.len();
    }

    let process_elapsed = process_start.elapsed();
    let total_elapsed = start.elapsed();

    assert_eq!(processed, NUM_EVENTS as usize, "should process all events");

    println!("Processed {processed} events in {process_elapsed:?}");
    println!("Total time: {total_elapsed:?}");

    // Sanity check: should complete in reasonable time.
    assert!(
        total_elapsed.as_secs() < 5,
        "throughput test should complete within 5 seconds"
    );
}

/// Purge functionality should remove old unclaimed events.
///
/// **Expected behavior**:
/// - Push some events
/// - Claim some events (so they become unavailable for purging)
/// - Wait some time (simulated)
/// - Purge events older than a cutoff time
/// - Verify appropriate events were purged vs preserved
#[tokio::test(flavor = "current_thread")]
async fn purge_removes_old_unclaimed_events() {
    let repo = open_repo(":memory:").await;

    // Get current time for testing
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("now after UNIX_EPOCH")
        .as_millis() as i64;

    // Push 10 events
    for i in 0..10 {
        let event = make_event(i);
        repo.push(event).await.expect("push event");
    }

    // Claim 3 events (these should not be purged even after cutoff)
    let claimed = repo.claim("test_consumer", 300_000, 3).await.expect("claim events");
    assert_eq!(claimed.len(), 3, "should claim 3 events");

    // Set purge cutoff to slightly in the future (all current events should be old)
    let cutoff_time = now + 1000; // 1 second in the future

    // Purge old events - should purge 7 unclaimed events, keep 3 claimed
    let purged_count = repo.purge(cutoff_time).await.expect("purge old events");
    assert_eq!(purged_count, 7, "should purge 7 old unclaimed events");

    // Verify claimed events are still available
    let remaining = repo
        .claim("test_consumer2", 300_000, 20)
        .await
        .expect("claim remaining");
    assert_eq!(remaining.len(), 0, "no unclaimed events should remain after purge");

    // Original claimed events should still be tracked (can't claim them again)
    let attempt_reclaim = repo
        .claim("test_consumer3", 300_000, 20)
        .await
        .expect("attempt reclaim");
    assert_eq!(attempt_reclaim.len(), 0, "claimed events should still be locked");
}

/// Purge cutoff time should be strictly respected.
///
/// **Expected behavior**:
/// - Events newer than cutoff time should never be purged
/// - Events older than cutoff time should be purged (if unclaimed)
/// - Cutoff time acts as a precise boundary
#[tokio::test(flavor = "current_thread")]
async fn purge_respects_cutoff_time_boundary() {
    let repo = open_repo(":memory:").await;

    // Push first batch of events
    for i in 0..5 {
        let event = make_event(i);
        repo.push(event).await.expect("push old events");
    }

    // Get timestamp after first batch - this will be our cutoff
    sleep(Duration::from_millis(50)).await;
    let cutoff_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("now after UNIX_EPOCH")
        .as_millis() as i64;

    // Wait to ensure clear separation
    sleep(Duration::from_millis(50)).await;

    // Push second batch of events (these should be after cutoff)
    for i in 5..10 {
        let event = make_event(i);
        repo.push(event).await.expect("push new events");
    }

    // Purge using the cutoff time
    let purged_count = repo.purge(cutoff_time).await.expect("purge old events");

    // Should purge the first batch (5 events) but preserve the second batch
    assert_eq!(purged_count, 5, "should purge exactly the old events");

    // Verify the newer events are still available
    let remaining = repo.claim("test_consumer", 300_000, 20).await.expect("claim remaining");
    assert_eq!(
        remaining.len(),
        5,
        "newer events should remain after cutoff-based purge"
    );

    // CRITICAL: Verify that the remaining events are actually the NEW ones (port 1029-1033)
    // not the OLD ones (port 1024-1028). This catches mutations where purge drops wrong events.
    let mut remaining_ports: Vec<u16> = remaining.iter().map(|e| e.event.target_port).collect();
    remaining_ports.sort();
    let expected_ports: Vec<u16> = (1029..1034).collect(); // Ports for events 5-9: ((5%60000)+1024) to ((9%60000)+1024)

    assert_eq!(
        remaining_ports, expected_ports,
        "remaining events should be the NEW events (ports 1029-1033), not old events (ports 1024-1028)"
    );

    // Double-check: ensure we don't have any of the old event ports
    for port in 1024..1029 {
        assert!(
            !remaining_ports.contains(&port),
            "old event with port {} should have been purged",
            port
        );
    }
}

/// Ack should only delete the specified events and be safe with wrong IDs.
///
/// **Expected behavior**:
/// - Acking non-existent IDs should be safe (no events deleted)
/// - Acking wrong IDs should not delete unrelated events  
/// - Only the specifically acked events should be removed
#[tokio::test(flavor = "current_thread")]
async fn ack_only_deletes_correct_events() {
    let repo = open_repo(":memory:").await;

    // Push 5 events
    for i in 0..5 {
        let event = make_event(i);
        repo.push(event).await.expect("push event");
    }

    // Claim 3 events with short lease so we can wait for expiry
    let claimed = repo.claim("consumer1", 100, 3).await.expect("claim events");
    assert_eq!(claimed.len(), 3, "should claim 3 events");

    // Store the claimed IDs and their ports for verification
    let claimed_ids: Vec<i64> = claimed.iter().map(|e| e.id).collect();

    // Try to ack with mix of correct and wrong IDs
    let mut ids_to_ack = claimed_ids.clone();
    ids_to_ack.push(99999); // Non-existent ID
    ids_to_ack.push(88888); // Another non-existent ID

    // Ack should work (be safe with non-existent IDs)
    repo.ack(&ids_to_ack).await.expect("ack with mixed IDs should be safe");

    // Immediately after ack, claimed events still aren't claimable (lease hasn't expired)
    let immediate_remaining = repo.claim("consumer2", 300_000, 10).await.expect("immediate claim");
    assert_eq!(
        immediate_remaining.len(),
        2,
        "should have 2 unclaimed events immediately"
    );

    // CRITICAL: Wait for lease to expire, then check if acked events come back
    // If ack worked properly, acked events should NOT come back even after lease expires
    sleep(Duration::from_millis(150)).await; // Wait for lease to expire

    let post_expiry_remaining = repo.claim("consumer3", 300_000, 10).await.expect("post-expiry claim");

    // If ack worked: should get 0 event (claimed the remaining 2 above)
    // If ack is broken: would get the 3 events we initially claimed (acked ones would come back)
    assert_eq!(
        post_expiry_remaining.len(),
        0,
        "after lease expiry, acked events should NOT return"
    );
}

/// Protocol field should be correctly stored and retrieved.
///
/// This test catches regressions in the protocol field handling.
///
/// **Expected behavior**:
/// - TCP events are stored and retrieved as TCP
/// - UDP events are stored and retrieved as UDP
/// - Protocol mapping functions work correctly in both directions
#[tokio::test(flavor = "current_thread")]
async fn protocol_field_correctly_preserved() {
    let repo = open_repo(":memory:").await;

    // Create a TCP event
    let mut tcp_event = make_event(100);
    tcp_event.protocol = TransportProtocol::Tcp;

    // Create a UDP event
    let mut udp_event = make_event(200);
    udp_event.protocol = TransportProtocol::Udp;

    // Push both events
    repo.push(tcp_event.clone()).await.expect("push TCP event");
    repo.push(udp_event.clone()).await.expect("push UDP event");

    // Claim both events
    let claimed = repo.claim("protocol_test", 60000, 10).await.expect("claim events");
    assert_eq!(claimed.len(), 2, "should claim both events");

    // Find the events by their distinctive bytes_tx values
    let claimed_tcp = claimed
        .iter()
        .find(|e| e.event.bytes_tx == tcp_event.bytes_tx)
        .expect("should find TCP event");
    let claimed_udp = claimed
        .iter()
        .find(|e| e.event.bytes_tx == udp_event.bytes_tx)
        .expect("should find UDP event");

    // Verify protocols are preserved correctly
    assert_eq!(
        claimed_tcp.event.protocol,
        TransportProtocol::Tcp,
        "TCP event should be stored and retrieved as TCP"
    );
    assert_eq!(
        claimed_udp.event.protocol,
        TransportProtocol::Udp,
        "UDP event should be stored and retrieved as UDP"
    );
}
