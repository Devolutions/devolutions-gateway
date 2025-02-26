use std::pin::Pin;
use std::{fmt, ops};

/// A wrapper for [`parking_lot::Mutex`] that supports obtaining `Pin<&mut T>` references to the contained value.
///
/// [`parking_lot::Mutex<T>`] itself does not have structural pinning.
/// The pinned-ness of the mutex type does not propagate to the field (the `T`).
///
/// `Pin<PinnableMutex<T>>` however can return a `Pin<MutexGuard<T>>`.
/// It’s a trade-off, because it can no longer provide mutable access without being pinned.
///
/// [`parking_lot::Mutex`] is both smaller than [`std::sync::Mutex`], and highly performant in low-contention scenarios,
/// making [`PinnableMutex`] ideal for shared, pollable resources.
///
/// # Example
///
/// ```
/// use std::future::Future;
/// use std::pin::Pin;
/// use std::sync::Arc;
/// use std::task::{Context, Poll};
/// use transport::PinnableMutex;
///
/// fn poll_shared_future<F: Future>(
///     fut: &Pin<Arc<PinnableMutex<F>>>,
///     ctx: &mut Context<'_>,
/// ) -> Poll<F::Output> {
///     fut.as_ref().lock().as_mut().poll(ctx)
/// }
/// ```
pub struct PinnableMutex<T: ?Sized>(parking_lot::Mutex<T>);
impl<T: ?Sized + fmt::Debug> fmt::Debug for PinnableMutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl<T> PinnableMutex<T> {
    pub fn new(t: T) -> Self {
        Self(parking_lot::Mutex::new(t))
    }

    pub fn into_inner(self) -> T {
        self.0.into_inner()
    }
}

impl<T: ?Sized> PinnableMutex<T> {
    pub fn lock(self: Pin<&Self>) -> PinMutexGuard<'_, T> {
        // SAFETY: Public API of PinnableMutex ensures the data is properly pinned.
        unsafe { Pin::new_unchecked(self.get_ref().0.lock()) }
    }

    pub fn lock_no_pin(&self) -> NoPinMutexGuard<'_, T> {
        NoPinMutexGuard(self.0.lock())
    }

    pub fn try_lock(self: Pin<&Self>) -> Option<PinMutexGuard<'_, T>> {
        self.get_ref().0.try_lock().map(|x| {
            // SAFETY: Public API of PinnableMutex ensures the data is properly pinned.
            unsafe { Pin::new_unchecked(x) }
        })
    }

    pub fn try_lock_no_pin(&self) -> Option<NoPinMutexGuard<'_, T>> {
        self.0.try_lock().map(NoPinMutexGuard)
    }

    pub fn get_mut(self: Pin<&mut Self>) -> Pin<&mut T> {
        // SAFETY: We do nothing else other than wrapping into a Pin again, to perform the projection.
        let inner = unsafe { Pin::into_inner_unchecked(self) }.0.get_mut();

        // SAFETY: Public API of PinnableMutex ensures the data is properly pinned.
        unsafe { Pin::new_unchecked(inner) }
    }

    pub fn get_mut_no_pin(&mut self) -> &mut T {
        self.0.get_mut()
    }
}

/// A pinned mutex guard
pub type PinMutexGuard<'a, T> = Pin<parking_lot::MutexGuard<'a, T>>;

/// A mutex guard that is not pinned
pub struct NoPinMutexGuard<'a, T: ?Sized>(parking_lot::MutexGuard<'a, T>);

impl<T: ?Sized + fmt::Debug> fmt::Debug for NoPinMutexGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T: ?Sized + fmt::Display> fmt::Display for NoPinMutexGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl<T: ?Sized> ops::Deref for NoPinMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized + Unpin> ops::DerefMut for NoPinMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
