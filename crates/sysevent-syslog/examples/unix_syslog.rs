use sysevent::{Entry, Facility, Severity, SystemEventSink};
use sysevent_syslog::{Syslog, SyslogOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Unix Syslog Backend Example");
    println!("===========================");

    // Configure syslog options.
    let options = SyslogOptions::default()
        .facility(Facility::Daemon)
        .log_pid(true)
        .no_delay(false)
        .log_perror(false);

    // Create syslog backend.
    let syslog = Syslog::new(c"dgw-unix-syslog-example", options)?;

    println!("Created syslog backend for 'system-wide-log-example'");

    // Emit various severity levels.
    let severities = [
        (Severity::Critical, "Critical system component failed"),
        (Severity::Error, "Error processing user request"),
        (Severity::Warning, "Deprecated API usage detected"),
        (Severity::Notice, "Configuration reloaded successfully"),
        (Severity::Info, "Service startup completed"),
        (Severity::Debug, "Processing request ID: 12345"),
    ];

    for (severity, message) in severities {
        let entry = Entry::new(message).severity(severity).facility(Facility::Daemon);

        match syslog.emit(entry) {
            Ok(()) => println!("✓ Emitted {} message", format!("{:?}", severity).to_lowercase()),
            Err(e) => println!(
                "✗ Failed to emit {} message: {}",
                format!("{:?}", severity).to_lowercase(),
                e
            ),
        }
    }

    // Emit structured data example.
    let structured_entry = Entry::new("Database connection established")
        .severity(Severity::Info)
        .facility(Facility::Daemon)
        .field("db_host", "localhost")
        .field("db_port", 5432)
        .field("connection_time_ms", 45);

    match syslog.emit(structured_entry) {
        Ok(()) => println!("✓ Emitted structured data message"),
        Err(e) => println!("✗ Failed to emit structured data message: {}", e),
    }

    // Demonstrate event code usage.
    let event_code_entry = Entry::new("Service degraded performance detected")
        .severity(Severity::Warning)
        .facility(Facility::Daemon)
        .event_code(2001);

    match syslog.emit(event_code_entry) {
        Ok(()) => println!("✓ Emitted message with event code"),
        Err(e) => println!("✗ Failed to emit message with event code: {}", e),
    }

    // Large message handling.
    let large_message = format!("Large diagnostic data: {}", "x".repeat(2000));
    let large_entry = Entry::new(large_message)
        .severity(Severity::Debug)
        .facility(Facility::Daemon);

    match syslog.emit(large_entry) {
        Ok(()) => println!("✓ Emitted large message (will be truncated if > 1024 bytes)"),
        Err(e) => println!("✗ Failed to emit large message: {}", e),
    }

    // Flush any pending messages.
    match syslog.flush() {
        Ok(()) => println!("✓ Flushed messages to syslog"),
        Err(e) => println!("✗ Failed to flush: {}", e),
    }

    println!("\nExample completed. Check your system logs with:");
    println!("  journalctl -t dgw-unix-syslog-example");
    println!("  tail -f /var/log/syslog | grep dgw-unix-syslog-example");
    println!("  tail -f /var/log/messages | grep dgw-unix-syslog-example");

    Ok(())
}
