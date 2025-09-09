#![cfg_attr(doc, doc = include_str!("../README.md"))]

use std::time::SystemTime;

/// Severity levels for log entries, mapped to standard syslog levels.
///
/// ```
///# use sysevent::Severity;
/// assert!(Severity::Critical < Severity::Warning);
/// assert!(Severity::Debug > Severity::Info);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Severity {
    /// Critical conditions (2)
    Critical = 2,
    /// Error conditions (3)
    Error = 3,
    /// Warning conditions (4)
    Warning = 4,
    /// Normal but significant condition (5)
    Notice = 5,
    /// Informational messages (6)
    Info = 6,
    /// Debug-level messages (7)
    Debug = 7,
}

impl Severity {
    /// Returns the numeric syslog severity level (0-7).
    ///
    /// ```
    ///# use sysevent::Severity;
    /// assert_eq!(Severity::Critical.as_u8(), 2);
    /// ```
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Syslog facility codes for categorizing log entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Facility {
    /// User-level messages (1)
    User = 1,
    /// System daemons (3)
    Daemon = 3,
    /// Security/authorization messages (10)
    Authpriv = 10,
    /// Local use facility 0 (16)
    Local0 = 16,
    /// Local use facility 1 (17)
    Local1 = 17,
    /// Local use facility 2 (18)
    Local2 = 18,
    /// Local use facility 3 (19)
    Local3 = 19,
    /// Local use facility 4 (20)
    Local4 = 20,
    /// Local use facility 5 (21)
    Local5 = 21,
    /// Local use facility 6 (22)
    Local6 = 22,
    /// Local use facility 7 (23)
    Local7 = 23,
}

impl Facility {
    /// Returns the numeric syslog facility code.
    ///
    /// ```
    ///# use sysevent::Facility;
    /// assert_eq!(Facility::User.as_u8(), 1);
    /// assert_eq!(Facility::Local0.as_u8(), 16);
    /// assert_eq!(Facility::Local7.as_u8(), 23);
    /// ```
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A structured log entry containing event metadata and message.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Event occurrence time
    pub timestamp: SystemTime,
    /// Event severity level
    pub severity: Severity,
    /// Syslog facility (ignored on Windows)
    pub facility: Option<Facility>,
    /// Platform-specific event code
    pub event_code: Option<u32>,
    /// Primary message text
    pub message: String,
    /// Structured key-value pairs
    pub fields: Vec<(String, String)>,
}

impl Entry {
    /// Creates a new log entry with the given application name.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            timestamp: SystemTime::now(),
            severity: Severity::Info,
            facility: Some(Facility::User),
            event_code: None,
            message: message.into(),
            fields: Vec::new(),
        }
    }

    /// Sets the severity level.
    #[must_use]
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Sets the syslog facility.
    #[must_use]
    pub fn facility(mut self, facility: Facility) -> Self {
        self.facility = Some(facility);
        self
    }

    /// Sets the event code.
    #[must_use]
    pub fn event_code(mut self, code: u32) -> Self {
        self.event_code = Some(code);
        self
    }

    /// Adds a structured field.
    #[must_use]
    pub fn field<K: Into<String>, V: ToString>(mut self, key: K, value: V) -> Self {
        self.fields.push((key.into(), value.to_string()));
        self
    }
}

/// Errors that can occur during event emission.
#[derive(Debug)]
pub enum SysEventError {
    /// I/O operation failures
    Io(std::io::Error),
    /// OS-specific errors with description
    Platform(String),
    /// Input validation failures
    Invalid(String),
    /// System resource limits exceeded
    ResourceExhausted,
}

impl std::fmt::Display for SysEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SysEventError::Io(e) => write!(f, "I/O error: {e}"),
            SysEventError::Platform(msg) => write!(f, "platform error: {msg}"),
            SysEventError::Invalid(msg) => write!(f, "invalid input: {msg}"),
            SysEventError::ResourceExhausted => write!(f, "system resource exhausted"),
        }
    }
}

impl std::error::Error for SysEventError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SysEventError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SysEventError {
    fn from(e: std::io::Error) -> Self {
        SysEventError::Io(e)
    }
}

/// Object-safe trait for system event backends.
pub trait SystemEventSink: Send + Sync {
    /// Emits a log entry, returning immediate success/failure status.
    fn emit(&self, entry: Entry) -> Result<(), SysEventError>;

    /// Flushes any pending events to the underlying system.
    fn flush(&self) -> Result<(), SysEventError>;
}

pub struct NoopSink;

impl SystemEventSink for NoopSink {
    fn emit(&self, _: Entry) -> Result<(), SysEventError> {
        Ok(())
    }

    fn flush(&self) -> Result<(), SysEventError> {
        Ok(())
    }
}
