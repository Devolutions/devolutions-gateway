#![cfg_attr(all(doc, windows), doc = include_str!("../README.md"))]
#![cfg(windows)]

use std::sync::Arc;

use sysevent::{Entry, Severity, SysEventError, SystemEventSink};
use windows_sys::Win32::System::EventLog;

type EventLogHandle = usize;

/// Windows Event Log backend implementation.
#[derive(Debug)]
pub struct WinEvent {
    handle: Arc<EventLogHandle>,
}

impl WinEvent {
    /// Creates a new Windows Event Log backend with the specified source name.
    ///
    /// The source name should match a registered event source in the Windows Registry
    /// for proper message formatting and categorization.
    pub fn new(source_name: &str) -> Result<Self, SysEventError> {
        let source_name_utf16 = to_null_terminated_utf16(source_name);

        // SAFETY: Proper UTF-16, null-terminated string.
        let handle = unsafe { EventLog::RegisterEventSourceW(std::ptr::null(), source_name_utf16.as_ptr()) };

        if is_null_handle(handle) {
            return Err(SysEventError::Platform(format!(
                "failed to register event source '{source_name}'"
            )));
        }

        Ok(Self {
            handle: Arc::new(handle as EventLogHandle),
        })
    }

    fn emit_to_event_log(&self, entry: Entry) -> Result<(), SysEventError> {
        let event_type = severity_to_event_type(entry.severity);
        let event_id = entry.event_code.unwrap_or(1000); // Default event ID

        let message = if entry.message.is_empty() {
            "Empty log message".to_owned()
        } else {
            entry.message
        };

        // Windows Event Log limits has a 31,839 characters size limit.
        // Defensively truncate when the message is big (31836 bytes of UTF-8).
        let truncated_message = if message.len() > 31836 {
            // Enough space should be available for "...".
            let mut idx = 31836;

            // Ensure idx is on a char boundary.
            loop {
                if message.get(..idx).is_some() {
                    break;
                }
                idx -= 1;
            }

            let mut s = message;
            s.truncate(idx);
            s.push_str("...");
            s
        } else {
            message
        };

        // Prepare strings for structured logging.
        let mut string_ptrs = Vec::new(); // Will be actually used as the parameter of the FFI function.
        #[expect(
            clippy::collection_is_never_read,
            reason = "string_ptrs hold pointers to the string we store inside this Vec"
        )]
        let mut utf16_strings = Vec::new(); // Keep the UTF-16 strings alive.

        // Add the English message as the first parameter for debugging context.
        let message_utf16 = to_null_terminated_utf16(&truncated_message);
        string_ptrs.push(message_utf16.as_ptr());
        utf16_strings.push(message_utf16);

        // Pass field values as insertion strings.
        // The .mc message template will format the complete message using %1, %2, etc, so the key is ignored.
        for (_key, value) in &entry.fields {
            let value_utf16 = to_null_terminated_utf16(value);
            string_ptrs.push(value_utf16.as_ptr());
            utf16_strings.push(value_utf16);
        }

        let num_strings = u16::try_from(string_ptrs.len()).expect("not too many fields");

        // SAFETY:
        // - handle is valid (checked at construction)
        // - strings array is valid with correct count
        // - binary data pointer is null with size 0
        let success = unsafe {
            EventLog::ReportEventW(
                *self.handle as windows_sys::Win32::Foundation::HANDLE,
                event_type,
                0, // category
                event_id,
                std::ptr::null_mut(), // user SID
                num_strings,
                0, // binary data size
                string_ptrs.as_ptr(),
                std::ptr::null(), // binary data
            )
        };

        if success == 0 {
            return Err(SysEventError::Platform(
                "failed to report event to Windows Event Log: ReportEventW returned 0".to_owned(),
            ));
        }

        Ok(())
    }
}

impl SystemEventSink for WinEvent {
    fn emit(&self, entry: Entry) -> Result<(), SysEventError> {
        self.emit_to_event_log(entry)
    }

    fn flush(&self) -> Result<(), SysEventError> {
        // Windows Event Log is synchronous by default - no buffering to flush.
        Ok(())
    }
}

impl Drop for WinEvent {
    fn drop(&mut self) {
        if !is_null_handle(*self.handle as windows_sys::Win32::Foundation::HANDLE) {
            // SAFETY: DeregisterEventSource is thread-safe and idempotent.
            unsafe {
                EventLog::DeregisterEventSource(*self.handle as windows_sys::Win32::Foundation::HANDLE);
            }
        }
    }
}

/// Returns whether a `HANDLE` returned by a Win32 API call represents failure to
/// register/open, i.e. is `NULL`.
///
/// `RegisterEventSourceW` signals failure with a `NULL` handle -- *not*
/// `INVALID_HANDLE_VALUE` (`(HANDLE)-1`), which is what some other Win32 APIs (e.g.
/// `CreateFileW`) use instead; see the `RegisterEventSourceW` documentation. Treating a
/// `NULL` handle as valid would let every subsequent `ReportEventW` call silently fail
/// against a handle that was never actually registered, rather than surfacing the real
/// registration failure at construction time.
fn is_null_handle(handle: windows_sys::Win32::Foundation::HANDLE) -> bool {
    handle.is_null()
}

fn severity_to_event_type(severity: Severity) -> u16 {
    match severity {
        Severity::Critical => EventLog::EVENTLOG_ERROR_TYPE,
        Severity::Error => EventLog::EVENTLOG_ERROR_TYPE,
        Severity::Warning => EventLog::EVENTLOG_WARNING_TYPE,
        Severity::Notice | Severity::Info | Severity::Debug => EventLog::EVENTLOG_INFORMATION_TYPE,
    }
}

/// Converts a null-terminated string to UTF-16 for Windows APIs.
fn to_null_terminated_utf16(input: &str) -> Vec<u16> {
    input.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── is_null_handle: the RegisterEventSourceW NULL-vs-INVALID_HANDLE_VALUE seam ───
    //
    // `RegisterEventSourceW`/`DeregisterEventSource` themselves are not mockable here
    // (they are direct FFI calls into `advapi32.dll`), but the failure-classification
    // logic they depend on is a pure function over a raw handle value, so it is fully
    // testable without touching the real Windows Event Log.

    #[test]
    fn null_handle_is_detected_as_failure() {
        assert!(is_null_handle(std::ptr::null_mut()));
    }

    #[test]
    fn invalid_handle_value_is_not_treated_as_a_null_handle() {
        // Some Win32 APIs (e.g. `CreateFileW`) signal failure with `INVALID_HANDLE_VALUE`
        // (`(HANDLE)-1`), but `RegisterEventSourceW` never returns it: pins that
        // `is_null_handle` checks specifically for `NULL`, not `INVALID_HANDLE_VALUE`,
        // which is the exact distinction this function exists to get right.
        let invalid = windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        assert!(!invalid.is_null(), "sanity check: INVALID_HANDLE_VALUE is not NULL");
        assert!(!is_null_handle(invalid));
    }

    #[test]
    fn nonzero_handle_is_not_a_failure() {
        let handle = 0x1234usize as windows_sys::Win32::Foundation::HANDLE;
        assert!(!is_null_handle(handle));
    }

    #[test]
    fn severity_to_event_type_mapping() {
        assert_eq!(
            severity_to_event_type(Severity::Critical),
            EventLog::EVENTLOG_ERROR_TYPE
        );
        assert_eq!(severity_to_event_type(Severity::Error), EventLog::EVENTLOG_ERROR_TYPE);
        assert_eq!(
            severity_to_event_type(Severity::Warning),
            EventLog::EVENTLOG_WARNING_TYPE
        );
        assert_eq!(
            severity_to_event_type(Severity::Notice),
            EventLog::EVENTLOG_INFORMATION_TYPE
        );
        assert_eq!(
            severity_to_event_type(Severity::Info),
            EventLog::EVENTLOG_INFORMATION_TYPE
        );
        assert_eq!(
            severity_to_event_type(Severity::Debug),
            EventLog::EVENTLOG_INFORMATION_TYPE
        );
    }

    #[test]
    fn severity_event_type_completeness() {
        // Ensure all severity levels are properly mapped
        let severities = [
            Severity::Critical,
            Severity::Error,
            Severity::Warning,
            Severity::Notice,
            Severity::Info,
            Severity::Debug,
        ];

        for severity in severities {
            let event_type = severity_to_event_type(severity);
            assert!(event_type > 0, "Event type should be positive for {:?}", severity);
        }
    }

    #[test]
    fn to_null_terminated_utf16_basic() {
        let result = to_null_terminated_utf16("hello");
        assert_eq!(result, [104, 101, 108, 108, 111, 0]);
    }

    #[test]
    fn to_null_terminated_utf16_conversion_edge_cases() {
        // Test empty string.
        let empty = to_null_terminated_utf16("");
        assert_eq!(empty, [0]); // Just null terminator

        // Test Unicode characters.
        let unicode = to_null_terminated_utf16("Hello 世界");
        assert!(unicode.len() > 1);
        assert_eq!(unicode.last(), Some(&0)); // Null terminated
    }
}
