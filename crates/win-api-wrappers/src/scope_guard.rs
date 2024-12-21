/// A generic RAII scope guard running a closure on drop
pub struct ScopeGuard<T, F: FnOnce(T)>(Option<ScopeGuardInner<T, F>>);

struct ScopeGuardInner<T, F: FnOnce(T)> {
    value: T,
    on_drop_fn: F,
}

impl<T, F: FnOnce(T)> ScopeGuard<T, F> {
    pub fn new(value: T, on_drop_fn: F) -> Self {
        Self(Some(ScopeGuardInner { value, on_drop_fn }))
    }

    pub fn as_ptr(&self) -> *const T {
        &self.0.as_ref().expect("always Some").value as *const _
    }

    pub fn as_mut_ptr(&mut self) -> *mut T {
        &mut self.0.as_mut().expect("always Some").value as *mut _
    }
}

impl<T, F: FnOnce(T)> AsRef<T> for ScopeGuard<T, F> {
    fn as_ref(&self) -> &T {
        &self.0.as_ref().expect("always Some").value
    }
}

impl<T, F: FnOnce(T)> AsMut<T> for ScopeGuard<T, F> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0.as_mut().expect("always Some").value
    }
}

impl<T, F: FnOnce(T)> Drop for ScopeGuard<T, F> {
    fn drop(&mut self) {
        let inner = self.0.take().expect("always Some");
        (inner.on_drop_fn)(inner.value)
    }
}
