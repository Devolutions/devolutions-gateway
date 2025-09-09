# sysevent-syslog

Syslog backend for system-wide critical event logging.

This crate provides Unix/Linux syslog implementation using standard libc calls.

## Platform Requirements

- Unix/Linux systems with syslog facilities
- Standard C library with openlog/syslog/closelog functions
- Thread-safe operation across concurrent emission calls

## Examples

```rust,no_run
use sysevent::{Entry, Severity, Facility, SystemEventSink};
use sysevent_syslog::{Syslog, SyslogOptions};

let options = SyslogOptions::default()
    .facility(Facility::Daemon)
    .log_pid(true);

let syslog = Syslog::new(c"myapp", options)?;

let entry = Entry::new("Database connection failed")
    .severity(Severity::Critical);

syslog.emit(entry)?;
# Ok::<(), sysevent::SysEventError>(())
```
