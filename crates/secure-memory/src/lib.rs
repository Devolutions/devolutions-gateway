#![cfg_attr(doc, doc = include_str!("../README.md"))]

#[cfg(any(test, not(any(unix, windows))))]
mod fallback;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use core::fmt;

#[cfg(not(any(unix, windows)))]
use fallback as platform;
#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

/// The memory-protection features that were successfully activated for a
/// [`ProtectedBytes`] allocation.
///
/// All fields are `false` when the platform backend is not available
/// (`fallback_backend == true`).
#[derive(Debug, Clone, Copy)]
pub struct ProtectionStatus {
    /// The pages are locked in RAM (`mlock` / `VirtualLock`).
    ///
    /// When `false` the OS may page the secret to disk under memory pressure.
    pub locked: bool,

    /// Guard pages are installed immediately before and after the data page.
    ///
    /// Any out-of-bounds access into adjacent memory will fault at the OS level.
    pub guard_pages: bool,

    /// The page is registered for exclusion from crash dumps.
    ///
    /// - **Linux**: `madvise(MADV_DONTDUMP)` — excluded from kernel core dumps
    ///   and user-space tools that respect VMA flags.
    /// - **Windows**: `WerRegisterExcludedMemoryBlock` — excluded from the mini
    ///   dump embedded in WER crash reports sent to Microsoft Watson only.
    ///   Full-memory dumps (`MiniDumpWithFullMemory`, ProcDump `-ma`, kernel live
    ///   dumps) capture all committed pages regardless. `MiniDumpWriteDump`
    ///   callbacks (`RemoveMemoryCallback` / `IncludeVmRegionCallback`) can filter
    ///   regions but only for cooperating dump writers, not externally triggered
    ///   dumps.
    /// - **macOS**: always `false`; no equivalent API exists.
    pub dump_excluded: bool,

    /// No OS-level hardening is available; using plain heap allocation.
    ///
    /// The secret is still zeroized on drop but none of the other protections
    /// are active. A debug message is logged once at construction time.
    pub fallback_backend: bool,
}

/// A fixed-size, protected in-memory secret.
///
/// On supported platforms the backing storage is a dedicated page-based
/// allocation with guard pages, memory locking, read-only page protection after
/// construction, and (where available) exclusion from core dumps. On all
/// platforms the bytes are zeroized before the backing allocation is released.
///
/// - `Debug` emits `[REDACTED]`; `Display` is absent; not `Clone` or `Copy`.
/// - One unavoidable stack copy in `new`: the `[u8; N]` argument is zeroized
///   immediately after being transferred into secure storage.
/// - `mlock` / `VirtualLock` prevent paging to disk but do not prevent transient
///   exposure in registers or on the call stack during `expose_secret`.
pub struct ProtectedBytes<const N: usize> {
    inner: platform::SecureAlloc<N>,
    status: ProtectionStatus,
}

impl<const N: usize> ProtectedBytes<N> {
    /// Move `bytes` into a new protected allocation.
    ///
    /// The local copy of `bytes` is zeroized immediately after it has been
    /// transferred into secure storage.
    ///
    /// # Panics
    ///
    /// Panics if the underlying OS page allocation fails (equivalent to
    /// out-of-memory). Hardening steps that fail at runtime (mlock limits,
    /// unavailable `madvise` flags, …) do **not** panic; they are downgraded
    /// and reported via [`ProtectedBytes::protection_status`] and a
    /// `tracing::debug!`.
    pub fn new(mut bytes: [u8; N]) -> Self {
        let (inner, status) = platform::SecureAlloc::new(&bytes);
        // Zeroize the stack copy now that the secret lives in secure storage.
        zeroize::Zeroize::zeroize(&mut bytes);
        Self { inner, status }
    }

    /// Borrow the secret bytes.
    ///
    /// Keep the returned reference as short-lived as possible.
    /// The CPU may hold the value in registers or on the stack during use.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; N] {
        self.inner.expose()
    }

    /// Return the protection status achieved at construction time.
    #[must_use]
    pub fn protection_status(&self) -> &ProtectionStatus {
        &self.status
    }
}

impl<const N: usize> fmt::Debug for ProtectedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProtectedBytes<{N}>([REDACTED])")
    }
}

// Intentionally absent: Display, Clone, Copy, Serialize, Deserialize.

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn construction_and_expose() {
        let secret = ProtectedBytes::new([0x42u8; 32]);
        assert_eq!(secret.expose_secret(), &[0x42u8; 32]);
    }

    #[test]
    fn redacted_debug_does_not_leak_bytes() {
        let secret = ProtectedBytes::new([0xFFu8; 32]);
        let s = format!("{secret:?}");
        assert!(s.contains("REDACTED"), "debug must say REDACTED, got: {s}");
        // Must not contain the byte value in decimal or hex.
        assert!(!s.contains("255"), "debug must not leak decimal value");
        assert!(!s.contains("ff"), "debug must not leak hex value");
        assert!(!s.contains("FF"), "debug must not leak hex value (upper)");
    }

    /// Verify that construction does not panic and that the status makes sense
    /// for the current platform.
    #[test]
    fn protection_status_coherent() {
        let secret = ProtectedBytes::new([1u8; 32]);
        let st = secret.protection_status();

        // fallback_backend is mutually exclusive with OS hardening.
        if st.fallback_backend {
            assert!(!st.locked);
            assert!(!st.guard_pages);
            assert!(!st.dump_excluded);
        }

        // dump_excluded without locked would be unusual; at minimum, if
        // dump_excluded is true then a real OS backend must be active.
        if st.dump_excluded {
            assert!(!st.fallback_backend);
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn os_backend_is_not_fallback() {
        let secret = ProtectedBytes::new([2u8; 32]);
        assert!(
            !secret.protection_status().fallback_backend,
            "expected OS backend on this platform"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn guard_pages_active() {
        let secret = ProtectedBytes::new([3u8; 32]);
        let st = secret.protection_status();
        assert!(st.guard_pages, "guard pages should be active");
    }

    // Test the fallback backend directly on all platforms.
    #[test]
    fn fallback_backend_constructs_correctly() {
        let (alloc, status) = fallback::SecureAlloc::<32>::new(&[0x99u8; 32]);
        assert_eq!(alloc.expose(), &[0x99u8; 32]);
        assert!(status.fallback_backend);
        assert!(!status.locked);
        assert!(!status.guard_pages);
        assert!(!status.dump_excluded);
    }
}
