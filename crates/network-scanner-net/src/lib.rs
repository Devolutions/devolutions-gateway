use std::mem::MaybeUninit;

pub mod runtime;
pub mod socket;
#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error)]
pub enum ScannnerNetError {
    #[error("std::io::Error")]
    StdIoError(#[from] std::io::Error),

    #[error("async run time has failed with error: {0}")]
    AsyncRuntimeError(String),
}

/// Assume the `buf`fer to be initialised.
///
/// # Safety
///
/// It is up to the caller to guarantee that the MaybeUninit<T> elements really are in an initialized state.
/// Calling this when the content is not yet fully initialized causes undefined behavior.
// TODO: replace with `MaybeUninit::slice_assume_init_ref` once stable.
// https://github.com/rust-lang/rust/issues/63569
pub unsafe fn assume_init(buf: &[MaybeUninit<u8>]) -> &[u8] {
    &*(buf as *const [MaybeUninit<u8>] as *const [u8])
}
