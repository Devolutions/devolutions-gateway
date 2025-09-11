//! Integration tests for WinEvent backend.

#![cfg(windows)]

use sysevent::{Entry, Severity, SystemEventSink};
use sysevent_winevent::WinEvent;

#[test]
fn real_emission() {
    let winevent = WinEvent::new("Devolutions Gateway Tests").expect("failed to create Windows Event Log");

    let entry = Entry::new("Integration test message")
        .severity(Severity::Info)
        .field("test_key", "test_value");

    winevent.emit(entry).expect("failed to emit message");
    winevent.flush().expect("failed to flush");
}

#[test]
fn structured_data() {
    let winevent = WinEvent::new("Devolutions Gateway Tests").expect("failed to create Windows Event Log");

    let entry = Entry::new("Structured data test for Windows")
        .severity(Severity::Error)
        .event_code(2001)
        .field("component", "authentication")
        .field("error_code", "AUTH_FAILED")
        .field("client_ip", "192.168.1.100");

    winevent.emit(entry).expect("failed to emit message");
    winevent.flush().expect("failed to flush");
}

#[test]
fn concurrent_emission() {
    use std::sync::Arc;
    use std::thread;

    let winevent = WinEvent::new("Devolutions Gateway Tests").expect("failed to create Windows Event Log");
    let winevent = Arc::new(winevent);

    let handles: Vec<_> = (0..4)
        .map(|i| {
            let winevent = Arc::clone(&winevent);

            thread::spawn(move || {
                winevent
                    .emit(Entry::new(format!("Concurrent message {i}")).severity(Severity::Info))
                    .expect("emit");
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should complete");
    }
}

#[test]
fn large_message() {
    let winevent = WinEvent::new("Devolutions Gateway Tests").expect("failed to create Windows Event Log");

    let entry = Entry::new("x".repeat(32000)).severity(Severity::Info);

    winevent.emit(entry).expect("failed to emit message");
    winevent.flush().expect("failed to flush");
}
