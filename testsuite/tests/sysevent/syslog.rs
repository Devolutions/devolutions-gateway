//! Integration tests for syslog backend.

#![cfg(unix)]

use sysevent::{Entry, Facility, Severity, SystemEventSink};
use sysevent_syslog::{Syslog, SyslogOptions};

#[test]
fn real_emission() {
    let syslog = Syslog::new(c"dgw-tests", SyslogOptions::default()).expect("failed to create syslog");

    let entry = Entry::new("Integration test message").severity(Severity::Info);

    syslog.emit(entry).expect("failed to emit message");
    syslog.flush().expect("failed to flush");
}

#[test]
fn structured_data() {
    let syslog = Syslog::new(c"dgw-tests", SyslogOptions::default()).expect("failed to create syslog backend");

    let entry = Entry::new("Structured data test")
        .severity(Severity::Warning)
        .facility(Facility::Local0)
        .field("user_id", 12345)
        .field("session_id", "abcdef")
        .field("action", "test_operation");

    syslog.emit(entry).expect("emit structured entry");
}

#[test]
fn large_message() {
    let syslog = Syslog::new(c"dgw-tests", SyslogOptions::default()).expect("failed to create syslog");

    let entry = Entry::new("x".repeat(1025)).severity(Severity::Info);

    syslog.emit(entry).expect("failed to emit message");
    syslog.flush().expect("failed to flush");
}

#[test]
fn concurrent_emission() {
    use std::sync::Arc;
    use std::thread;

    let syslog = Syslog::new(c"dgw-tests", SyslogOptions::default()).expect("failed to create syslog");
    let syslog = Arc::new(syslog);

    let handles: Vec<_> = (0..4)
        .map(|i| {
            let syslog = Arc::clone(&syslog);

            thread::spawn(move || {
                syslog
                    .emit(Entry::new(format!("Concurrent message {i}")).severity(Severity::Info))
                    .expect("emit");
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should complete");
    }
}
