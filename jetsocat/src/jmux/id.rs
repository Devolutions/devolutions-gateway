use bitvec::prelude::*;
use std::convert::TryFrom;

pub trait Id: Copy + From<u32> + Into<u32> {}

/// Distant identifier for a channel
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct DistantChannelId(u32);

impl From<u32> for DistantChannelId {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl From<DistantChannelId> for u32 {
    fn from(id: DistantChannelId) -> Self {
        id.0
    }
}

impl Id for DistantChannelId {}

impl std::fmt::Display for DistantChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "d#{}", self.0)
    }
}

/// Local identifier for a channel
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct LocalChannelId(u32);

impl From<u32> for LocalChannelId {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl From<LocalChannelId> for u32 {
    fn from(id: LocalChannelId) -> Self {
        id.0
    }
}

impl Id for LocalChannelId {}

impl std::fmt::Display for LocalChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "l#{}", self.0)
    }
}

pub struct IdAllocator<T: Id> {
    taken: BitVec,
    _pd: std::marker::PhantomData<T>,
}

impl<T: Id> Default for IdAllocator<T> {
    fn default() -> Self {
        Self {
            taken: BitVec::new(),
            _pd: std::marker::PhantomData,
        }
    }
}

impl<T: Id> IdAllocator<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates an ID
    ///
    /// Returns `None` when allocator is out of memory.
    pub fn alloc(&mut self) -> Option<T> {
        match self.taken.iter_zeros().next() {
            Some(freed_idx) => {
                // - Reclaim a freed ID -
                let freed_idx_u32 = u32::try_from(freed_idx).expect("freed IDs should fit in an u32 integer");
                self.taken.set(freed_idx, true);
                Some(T::from(freed_idx_u32))
            }
            None => {
                // - Allocate a new ID -
                let new_idx = self.taken.len();
                // If new_idx doesn’t fit in a u32, we are in the highly improbable case of an "out of memory" for this ID allocator
                let new_idx_u32 = u32::try_from(new_idx).ok()?;
                self.taken.push(true);
                Some(T::from(new_idx_u32))
            }
        }
    }

    /// Frees an ID
    ///
    /// Freed IDs can be later reclaimed.
    pub fn free(&mut self, id: T) {
        let idx = usize::try_from(Into::<u32>::into(id)).expect("ID should fit in an usize integer");
        self.taken.set(idx, false);
    }
}
