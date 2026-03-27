//! Fallback backend: plain heap allocation with zeroize-on-drop.
//!
//! Used on platforms where neither the Unix nor the Windows backend is
//! available. All hardening features are absent; a debug message is logged
//! once at construction time.

use std::sync::Once;

use crate::ProtectionStatus;

/// Heap-backed allocation with zeroize-on-drop. No OS hardening.
pub(crate) struct SecureAlloc<const N: usize> {
    inner: Box<[u8; N]>,
}

impl<const N: usize> SecureAlloc<N> {
    pub(crate) fn new(src: &[u8; N]) -> (Self, ProtectionStatus) {
        warn_once();

        let mut b = Box::new([0u8; N]);
        b.copy_from_slice(src);

        let status = ProtectionStatus {
            locked: false,
            guard_pages: false,
            dump_excluded: false,
            fallback_backend: true,
        };
        (Self { inner: b }, status)
    }

    pub(crate) fn expose(&self) -> &[u8; N] {
        &self.inner
    }
}

impl<const N: usize> Drop for SecureAlloc<N> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self.inner.as_mut());
    }
}

fn warn_once() {
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        tracing::debug!(
            "secure-memory: advanced memory protection (mlock, guard pages, \
             dump exclusion) is not available on this platform; \
             falling back to plain heap allocation with zeroize-on-drop only"
        );
    });
}
