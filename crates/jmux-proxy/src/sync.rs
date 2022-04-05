#[cfg(not(loom))]
pub(crate) use self::std::*;

#[cfg(not(loom))]
mod std {
    pub use std::sync::atomic::{AtomicUsize, Ordering};
    pub use std::sync::Arc;
}

#[cfg(loom)]
pub(crate) use self::loom::*;

#[cfg(loom)]
mod loom {
    pub use loom::sync::atomic::{AtomicUsize, Ordering};
    pub use loom::sync::Arc;
}
