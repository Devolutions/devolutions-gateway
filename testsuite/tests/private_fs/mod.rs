//! Tests of private-fs through its public API.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
