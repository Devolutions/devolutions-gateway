#![cfg_attr(doc, doc = include_str!("../README.md"))]

use std::ffi::{CStr, CString};

use sysevent::{Entry, Facility, Severity, SysEventError, SystemEventSink};

/// Configuration options for syslog connection.
#[derive(Debug, Clone)]
pub struct SyslogOptions {
    /// Default facility if entry doesn't specify one
    pub default_facility: Facility,
    /// Include PID in log messages (LOG_PID flag)
    pub log_pid: bool,
    /// Connect immediately vs on first message (LOG_NDELAY flag)  
    pub no_delay: bool,
    /// Also log to stderr (LOG_PERROR flag)
    pub log_perror: bool,
}

impl Default for SyslogOptions {
    fn default() -> Self {
        Self {
            default_facility: Facility::User,
            log_pid: true,
            no_delay: false,
            log_perror: false,
        }
    }
}

impl SyslogOptions {
    /// Sets the default facility.
    #[must_use]
    pub fn facility(mut self, facility: Facility) -> Self {
        self.default_facility = facility;
        self
    }

    /// Sets whether to include PID in messages.
    #[must_use]
    pub fn log_pid(mut self, enabled: bool) -> Self {
        self.log_pid = enabled;
        self
    }

    /// Sets whether to connect immediately.
    #[must_use]
    pub fn no_delay(mut self, enabled: bool) -> Self {
        self.no_delay = enabled;
        self
    }

    /// Sets whether to also log to stderr.
    #[must_use]
    pub fn log_perror(mut self, enabled: bool) -> Self {
        self.log_perror = enabled;
        self
    }

    fn to_flags(&self) -> libc::c_int {
        let mut flags = 0;
        if self.log_pid {
            flags |= libc::LOG_PID;
        }
        if self.no_delay {
            flags |= libc::LOG_NDELAY;
        }
        if self.log_perror {
            flags |= libc::LOG_PERROR;
        }
        flags
    }
}

/// Syslog backend implementation.
#[derive(Debug)]
pub struct Syslog {
    options: SyslogOptions,
}

impl Syslog {
    /// Creates a new syslog backend with the specified application name and options.
    ///
    /// # Arguments
    /// * `appname` - Application identifier string (e.g., c"myapp")
    /// * `options` - Configuration options for syslog behavior
    pub fn new(appname: &'static CStr, options: SyslogOptions) -> Result<Self, SysEventError> {
        // SAFETY:
        // - `openlog` is thread-safe.
        // - The appname pointer remains valid for the lifetime of the Syslog instance ('static).
        unsafe {
            libc::openlog(
                appname.as_ptr(),
                options.to_flags(),
                0, // facility will be specified per-message
            );
        }

        Ok(Self { options })
    }
}

impl SystemEventSink for Syslog {
    fn emit(&self, entry: Entry) -> Result<(), SysEventError> {
        let facility = entry.facility.unwrap_or(self.options.default_facility);
        let priority = i32::from(calculate_pri(facility, entry.severity));
        let message = format_syslog_message(entry);
        emit_to_syslog(priority, &message)
    }

    fn flush(&self) -> Result<(), SysEventError> {
        // Syslog is synchronous by default - no buffering to flush.
        Ok(())
    }
}

impl Drop for Syslog {
    fn drop(&mut self) {
        // SAFETY: closelog is thread-safe and idempotent
        unsafe {
            libc::closelog();
        }
    }
}

fn emit_to_syslog(priority: i32, message: &str) -> Result<(), SysEventError> {
    // Escape percent characters to prevent format string interpretation.
    let escaped_message = escape_percent(message);

    // Truncate message to syslog limits (1024 bytes per RFC 3164).
    let truncated = if escaped_message.len() > 1024 {
        // Leave room for "..."
        format!("{}...", &escaped_message[..1021])
    } else {
        escaped_message
    };

    let c_message = CString::new(truncated)
        .map_err(|_| SysEventError::Invalid("message contains null byte after escaping".to_owned()))?;

    // SAFETY: syslog is thread-safe, and we have valid C strings
    // The format string "%s" is safe and the message has been escaped
    unsafe {
        libc::syslog(priority, c"%s".as_ptr(), c_message.as_ptr());
    }

    Ok(())
}

/// Utility function to safely escape percent characters for syslog messages.
///
/// All `%` characters are converted to `%%` to prevent format string interpretation.
fn escape_percent(input: &str) -> String {
    input.replace('%', "%%")
}

/// Calculates the syslog PRI value from facility and severity.
///
/// PRI = Facility * 8 + Severity
const fn calculate_pri(facility: Facility, severity: Severity) -> u16 {
    (facility.as_u8() as u16) * 8 + (severity.as_u8() as u16)
}

fn format_syslog_message(mut entry: Entry) -> String {
    if let Some(event_code) = entry.event_code {
        entry.fields.push(("event_code".to_owned(), event_code.to_string()));
    }

    let mut s = if entry.message.is_empty() {
        "Empty log message".to_owned()
    } else {
        entry.message
    };

    // Format message with structured data.
    if !entry.fields.is_empty() {
        let mut first = true;
        s.push(' ');
        s.push('[');
        entry.fields.iter().for_each(|(k, v)| {
            if first {
                first = false;
            } else {
                s.push(',');
            }
            s.push_str(k);
            s.push('=');
            s.push_str(v);
        });
        s.push(']');
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;
    use sysevent::Severity;

    #[test]
    fn syslog_options_builder() {
        let opts = SyslogOptions::default()
            .facility(Facility::Daemon)
            .log_pid(false)
            .no_delay(true)
            .log_perror(true);

        assert_eq!(opts.default_facility, Facility::Daemon);
        assert!(!opts.log_pid);
        assert!(opts.no_delay);
        assert!(opts.log_perror);
    }

    #[test]
    fn syslog_options_flags() {
        let opts = SyslogOptions::default().log_pid(true).no_delay(true).log_perror(true);
        assert_eq!(opts.to_flags(), libc::LOG_PID | libc::LOG_NDELAY | libc::LOG_PERROR);
    }

    #[test]
    fn message_escaping_comprehensive() {
        let test_cases = vec![
            ("no percent", "no percent"),
            ("100% complete", "100%% complete"),
            ("%%already escaped%%", "%%%%already escaped%%%%"),
            ("%s format string", "%%s format string"),
            ("multiple % symbols %d %s", "multiple %% symbols %%d %%s"),
        ];

        for (input, expected) in test_cases {
            assert_eq!(escape_percent(input), expected);
        }
    }

    #[test]
    fn all_facility_priority_combinations() {
        let facilities = [
            Facility::User,
            Facility::Daemon,
            Facility::Authpriv,
            Facility::Local0,
            Facility::Local1,
            Facility::Local2,
            Facility::Local3,
            Facility::Local4,
            Facility::Local5,
            Facility::Local6,
            Facility::Local7,
        ];
        let severities = [
            Severity::Critical,
            Severity::Error,
            Severity::Warning,
            Severity::Notice,
            Severity::Info,
            Severity::Debug,
        ];

        for facility in &facilities {
            for severity in &severities {
                let priority = calculate_pri(*facility, *severity);
                let expected = u16::from(facility.as_u8()) * 8 + u16::from(severity.as_u8());
                assert_eq!(priority, expected);
                assert!(priority <= 191); // Max possible value
            }
        }
    }

    #[test]
    fn pri_calculation() {
        assert_eq!(calculate_pri(Facility::Daemon, Severity::Warning), 28);
        assert_eq!(calculate_pri(Facility::User, Severity::Error), 11);
        assert_eq!(calculate_pri(Facility::Local0, Severity::Info), 134);
    }

    #[test]
    fn syslog_message_formatting() {
        assert_eq!(format_syslog_message(Entry::new("msg")), "msg");
        assert_eq!(format_syslog_message(Entry::new("")), "Empty log message");
        assert_eq!(
            format_syslog_message(Entry::new("msg").event_code(5)),
            "msg [event_code=5]"
        );
        assert_eq!(
            format_syslog_message(Entry::new("msg").field("abc", 10).field("efg", 'a')),
            "msg [abc=10,efg=a]"
        );
    }

    proptest! {
        #[test]
        fn escape_percent_all_percent_doubled(input in ".*") {
            let escaped = escape_percent(&input);
            let percent_count_original = input.matches('%').count();
            let percent_count_escaped = escaped.matches('%').count();

            // Every % becomes %%, so we should have double the count.
            prop_assert_eq!(percent_count_escaped, percent_count_original * 2);
        }

        #[test]
        fn escape_percent_no_other_chars_change(input in "[^%]*") {
            // String with no % characters should be unchanged.
            let escaped = escape_percent(&input);
            prop_assert_eq!(escaped, input);
        }

        #[test]
        fn escape_percent_roundtrip_invariant(input in ".*") {
            let escaped = escape_percent(&input);

            // Check that all % are properly doubled.
            let chars: Vec<char> = escaped.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                if chars[i] == '%' {
                    // Every % should be followed by another %.
                    prop_assert!(i + 1 < chars.len(), "trailing % found in escaped string: {}", escaped);
                    prop_assert_eq!(chars[i + 1], '%', "single % found in escaped string: {}", escaped);
                    i += 2; // Skip the %% pair
                } else {
                    i += 1;
                }
            }
        }
    }
}
