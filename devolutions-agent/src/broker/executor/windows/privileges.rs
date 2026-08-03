//! Process-wide, reference-counted privilege enabling.
//!
//! `ScopedPrivileges` unconditionally disables privileges on drop, which is unsafe with
//! concurrent broker requests: dropping one scope would disable a privilege another
//! in-flight request still relies on (privileges are process-token state, not per-handle).
//! [`SharedPrivileges`] keeps a per-privilege reference count and only enables a privilege
//! on the first acquisition and disables it again when the last guard is dropped.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Context as _;
use tracing::error;
use win_api_wrappers::process::Process;
use win_api_wrappers::security::privilege;
use win_api_wrappers::str::U16CStr;
use win_api_wrappers::token::TokenPrivilegesAdjustment;
use windows::Win32::Security::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};

static PRIVILEGE_REFCOUNTS: Mutex<Option<HashMap<String, usize>>> = Mutex::new(None);

/// Guard keeping a set of process token privileges enabled.
///
/// Privileges are disabled on drop only when no other live guard still requires them.
pub(super) struct SharedPrivileges {
    names: Vec<&'static U16CStr>,
}

impl SharedPrivileges {
    /// Enable `names` on the current process token, reference-counted across all guards.
    pub(super) fn acquire(names: &[&'static U16CStr]) -> anyhow::Result<Self> {
        let mut guard = PRIVILEGE_REFCOUNTS.lock().expect("privilege refcount lock poisoned");
        let refcounts = guard.get_or_insert_with(HashMap::new);

        let mut to_enable = Vec::new();
        for name in names {
            let count = refcounts.entry(name.to_string_lossy()).or_insert(0);
            if *count == 0 {
                to_enable.push(*name);
            }
            *count += 1;
        }

        if let Err(error) = adjust(&to_enable, true) {
            // Roll back the reference counts taken above before reporting the failure.
            for name in names {
                if let Some(count) = refcounts.get_mut(&name.to_string_lossy()) {
                    *count = count.saturating_sub(1);
                }
            }
            return Err(error);
        }

        Ok(Self { names: names.to_vec() })
    }
}

impl Drop for SharedPrivileges {
    fn drop(&mut self) {
        let mut guard = PRIVILEGE_REFCOUNTS.lock().expect("privilege refcount lock poisoned");
        let Some(refcounts) = guard.as_mut() else {
            return;
        };

        let mut to_disable = Vec::new();
        for name in &self.names {
            if let Some(count) = refcounts.get_mut(&name.to_string_lossy()) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    to_disable.push(*name);
                }
            }
        }

        if let Err(error) = adjust(&to_disable, false) {
            error!(error = format!("{error:#}"), "Failed to disable shared privileges");
        }
    }
}

/// Enable or disable `names` on the current process token.
///
/// Must be called with the refcount lock held so enable/disable operations are serialized.
fn adjust(names: &[&U16CStr], enable: bool) -> anyhow::Result<()> {
    if names.is_empty() {
        return Ok(());
    }

    let mut luids = Vec::with_capacity(names.len());
    for name in names {
        luids.push(privilege::lookup_privilege_value(None, name).context("failed to look up privilege value")?);
    }

    let adjustment = if enable {
        TokenPrivilegesAdjustment::Enable(luids)
    } else {
        TokenPrivilegesAdjustment::Disable(luids)
    };

    let mut token = Process::current_process()
        .token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
        .context("failed to open process token for privilege adjustment")?;
    token
        .adjust_privileges(&adjustment)
        .context("failed to adjust privileges")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn nested_guards_keep_privilege_enabled_until_last_drop() {
        // SeChangeNotify is available to any token, making the test runnable without elevation.
        let name = privilege::SE_CHANGE_NOTIFY_NAME;

        let first = SharedPrivileges::acquire(&[name]).unwrap();
        let second = SharedPrivileges::acquire(&[name]).unwrap();

        drop(first);

        {
            let guard = PRIVILEGE_REFCOUNTS.lock().unwrap();
            let refcounts = guard.as_ref().unwrap();
            assert_eq!(refcounts.get(&name.to_string_lossy()), Some(&1));
        }

        drop(second);

        {
            let guard = PRIVILEGE_REFCOUNTS.lock().unwrap();
            let refcounts = guard.as_ref().unwrap();
            assert_eq!(refcounts.get(&name.to_string_lossy()), Some(&0));
        }
    }
}
