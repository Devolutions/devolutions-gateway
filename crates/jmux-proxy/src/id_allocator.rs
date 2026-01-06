use std::convert::TryFrom;

use bitvec::prelude::*;
use jmux_proto::LocalChannelId;

pub(crate) trait Id: Copy + From<u32> + Into<u32> {}

impl Id for LocalChannelId {}

pub(crate) struct IdAllocator<T: Id> {
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
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Allocates an ID
    ///
    /// Returns `None` when allocator is out of memory.
    pub(crate) fn alloc(&mut self) -> Option<T> {
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
    pub(crate) fn free(&mut self, id: T) {
        let idx = usize::try_from(Into::<u32>::into(id)).expect("ID should fit in an usize integer");
        self.taken.set(idx, false);
    }
}
