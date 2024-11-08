#[derive(Debug)]
pub struct ExecAgentError(pub u16);

impl ExecAgentError {
    pub const EXISTING_SESSION: Self = Self(0x0001);
    pub const START_FAILED: Self = Self(0x0002);
    pub const OTHER: Self = Self(0xFFFF);
}

pub struct ExecResultKind(pub u8);

impl ExecResultKind {
    /// Application exited normally. `code` contains application exit code.
    pub const EXITED: Self = Self(0x00);

    /// Session was closed because of system error.
    /// `code` contains system error code (e.g. WinAPI error code).
    pub const SESSION_ERROR_SYSETM: Self = Self(0x01);

    /// Session was closed because of agent-specific error.
    pub const SESSION_ERROR_AGENT: Self = Self(0x02);

    /// Execution was aborted by user via `AbortExecution` message.
    pub const ABORTED: Self = Self(0xFF);
}
