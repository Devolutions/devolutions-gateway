# sysevent-winevent

Windows Event Log backend for system-wide critical event logging.

This crate provides Windows Event Log implementation using Win32 APIs.

## Platform Requirements  

- Windows systems with Event Log service
- Appropriate permissions to write to event log
- Event source registration in Windows Registry (recommended)

## Event Source Registration

For proper operation, register the event source in the Registry:
`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\{SourceName}`

## Examples

```rust,no_run
use sysevent::{Entry, Severity, SystemEventSink};
use sysevent_winevent::WinEvent;

let winevent = WinEvent::new("MyApplication")?;

let entry = Entry::new("Service startup failed").severity(Severity::Critical);

winevent.emit(entry)?;
# Ok::<(), sysevent::SysEventError>(())
```
