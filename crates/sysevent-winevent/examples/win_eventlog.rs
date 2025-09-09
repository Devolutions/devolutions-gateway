use sysevent::{Entry, Severity, SystemEventSink};
use sysevent_winevent::WinEvent;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Windows Event Log Backend Example");
    println!("==================================");

    // Create Windows Event Log backend.
    let winevent = WinEvent::new("DgwSystemWideLogExample")?;

    println!("Created Windows Event Log backend for 'DgwSystemWideLogExample'");
    println!("Note: For production use, register the event source in the Registry:");
    println!(
        "  HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\DgwSystemWideLogExample"
    );

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
        let entry = Entry::new(message).severity(severity);

        match winevent.emit(entry) {
            Ok(()) => println!("✓ Emitted {} message", format!("{:?}", severity).to_lowercase()),
            Err(e) => println!(
                "✗ Failed to emit {} message: {}",
                format!("{:?}", severity).to_lowercase(),
                e
            ),
        }
    }

    // Emit structured data example
    let structured_entry = Entry::new("Database connection established")
        .severity(Severity::Info)
        .field("db_host", "localhost")
        .field("db_port", 1433)
        .field("connection_time_ms", 32);

    match winevent.emit(structured_entry) {
        Ok(()) => println!("✓ Emitted structured data message"),
        Err(e) => println!("✗ Failed to emit structured data message: {}", e),
    }

    // Demonstrate event code usage
    let event_code_entry = Entry::new("Service degraded performance detected")
        .severity(Severity::Warning)
        .event_code(2001);

    match winevent.emit(event_code_entry) {
        Ok(()) => println!("✓ Emitted message with event code 2001"),
        Err(e) => println!("✗ Failed to emit message with event code: {}", e),
    }

    // Large message handling
    let large_message = format!("Large diagnostic data: {}", "x".repeat(50000));
    let large_entry = Entry::new(large_message).severity(Severity::Debug);

    match winevent.emit(large_entry) {
        Ok(()) => println!("✓ Emitted large message (will be truncated if > 31KB)"),
        Err(e) => println!("✗ Failed to emit large message: {}", e),
    }

    // Unicode message handling
    let unicode_entry =
        Entry::new("Unicode test: Hello, 世界! Здравствуй мир! مرحبا بالعالم!").severity(Severity::Info);

    match winevent.emit(unicode_entry) {
        Ok(()) => println!("✓ Emitted Unicode message"),
        Err(e) => println!("✗ Failed to emit Unicode message: {}", e),
    }

    // Empty message handling
    let empty_entry = Entry::new("").severity(Severity::Notice);

    match winevent.emit(empty_entry) {
        Ok(()) => println!("✓ Emitted empty message (replaced with default text)"),
        Err(e) => println!("✗ Failed to emit empty message: {}", e),
    }

    // Flush any pending messages
    match winevent.flush() {
        Ok(()) => println!("✓ Flushed messages to Windows Event Log"),
        Err(e) => println!("✗ Failed to flush: {}", e),
    }

    println!("\nExample completed. Check the Windows Event Log:");
    println!("  1. Open Event Viewer (eventvwr.exe)");
    println!("  2. Navigate to Windows Logs > Application");
    println!("  3. Look for events from source 'SystemWideLogExample'");
    println!(
        "  4. Or use PowerShell: Get-WinEvent -FilterHashtable @{{LogName='Application'; ProviderName='DgwSystemWideLogExample'}}"
    );

    Ok(())
}
