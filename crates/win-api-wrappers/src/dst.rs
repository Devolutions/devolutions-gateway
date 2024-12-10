//! Helpers for dynamically sized types found in Win32 API.

use crate::raw_buffer::{InitedBuffer, RawBuffer};

/// Definition for a Win32-style dynamically sized type.
///
/// # Safety
///
/// - The offsets must be in bound of the container.
/// - The container must not be `#[repr(packed)]`.
pub unsafe trait Win32DstDef {
    type Container;

    type Item;

    type ItemCount: TryInto<usize, Error = core::num::TryFromIntError> + Copy;

    /// Offset to the item count, in bounds of the container.
    const ITEM_COUNT_OFFSET: usize;

    /// Offset to the array, in bounds of the container.
    const ARRAY_OFFSET: usize;

    /// Builds a container holding a single element.
    fn new_container(first_item: Self::Item) -> Self::Container;

    /// Increments count by one.
    fn increment_count(count: Self::ItemCount) -> Self::ItemCount;
}

/// Wrapper over a Win32-style dynamically sized type.
pub struct Win32Dst<Def: Win32DstDef> {
    /// INVARIANT: The array holds exactly `Def::ItemCount` elements.
    /// INVARIANT: `Def::ITEM_COUNT_OFFSET` is in bounds of the allocated container.
    /// INVARIANT: `Def::ARRAY_OFFSET` is in bounds of the allocated container.
    /// INVARIANT: `Def::Container` is not #[repr(packed)], so the fields are properly aligned when reading.
    inner: InitedBuffer<Def::Container>,
}

impl<Def: Win32DstDef> Win32Dst<Def> {
    pub fn new(first_item: Def::Item) -> Self {
        use core::alloc::Layout;

        let container = Def::new_container(first_item);

        let layout = Layout::new::<Def::Container>();

        // SAFETY: The layout initialization is checked using the Layout::new method.
        let mut inner = unsafe { RawBuffer::alloc_zeroed(layout).expect("OOM") };

        // SAFETY: The pointed memory is valid for writes and is properly aligned.
        unsafe { inner.as_mut_ptr().cast::<Def::Container>().write(container) };

        // SAFETY: We initialized the value above.
        let inner = unsafe { inner.assume_init() };

        Self { inner }
    }

    /// Creates a new [`Win32Dst`] from the provided [`InitedBuffer`].
    ///
    /// # Safety
    ///
    /// The underlying array must holds exactly the amount of `Def::Item` specified inside the `Def::ItemCount`.
    pub unsafe fn from_raw(buffer: InitedBuffer<Def::Container>) -> Self {
        Self { inner: buffer }
    }

    pub fn as_raw(&self) -> &InitedBuffer<Def::Container> {
        &self.inner
    }

    pub fn push(&mut self, value: Def::Item) {
        let current_count = self.count();

        let raw_buffer = self.inner.as_inner_mut();

        let layout = raw_buffer.layout();

        let current_size = layout.size();
        let new_size = current_size + size_of::<Def::Item>();

        let rounded_new_size = new_size + new_size % layout.align();

        // Ensure `new_size`, when rounded up to the nearest multiple of `layout.align()`,
        // does not overflow `isize` (i.e., the rounded value must be less than or
        // equal to `isize::MAX`).
        isize::try_from(rounded_new_size).expect("array contains too many elements");

        // SAFETY:
        // - We ensure new_size is valid just above.
        // - We immediately write the new value in-place, keeping the underlying TOKEN_PRIVILEGES valid.
        unsafe { raw_buffer.realloc(new_size).expect("OOM") };

        // From here, the invariants of InitedBuffer are not holding anymore -->

        // SAFETY: Per invariants, the offset is in bounds of the container.
        let array_ptr = unsafe { raw_buffer.as_mut_ptr().byte_add(Def::ARRAY_OFFSET) };

        // SAFETY:
        // - The new pointer is placed somewhere where ptr + rounded_new_size does not overflow isize, and array_offset < rounded_new_size.
        // - current_count is a reasonable value as per invariants.
        let new_item_ptr = unsafe {
            array_ptr
                .cast::<Def::Item>()
                .add(current_count.try_into().expect("fit into usize"))
        };

        // SAFETY: The pointed memory is valid for writes and is properly aligned.
        unsafe { new_item_ptr.write(value) };

        // Update the item count.

        // SAFETY: Per invariants, the offset is in bounds of the container.
        let count_ptr = unsafe { raw_buffer.as_mut_ptr().byte_add(Def::ITEM_COUNT_OFFSET) };

        // SAFETY: The pointed memory is valid for writes and is properly aligned.
        unsafe {
            count_ptr
                .cast::<Def::ItemCount>()
                .write(Def::increment_count(current_count))
        }

        // <-- At this point, the InitedBuffer invariants are holding again.
    }

    pub fn count(&self) -> Def::ItemCount {
        // SAFETY: Per invariants, the offset must be in bounds of the allocated object.
        let count_ptr = unsafe { self.inner.as_ptr().byte_add(Def::ITEM_COUNT_OFFSET) };

        unsafe { count_ptr.cast::<Def::ItemCount>().read() }
    }

    pub fn as_slice(&self) -> &[Def::Item] {
        let count = self.count().try_into().expect("fit into usize");

        // SAFETY: Per invariants, the offset must be in bounds of the allocated object.
        let array_ptr = unsafe { self.inner.as_ptr().byte_add(Def::ARRAY_OFFSET) };

        // SAFETY: Per invariants, the array contains `count` items.
        unsafe { core::slice::from_raw_parts(array_ptr.cast::<Def::Item>(), count) }
    }
}

#[cfg(test)]
mod tests {
    use std::mem;

    use super::*;

    struct MockContainer {
        count: u32,
        array: [u128; 1],
    }

    struct MockDef;

    unsafe impl Win32DstDef for MockDef {
        type Container = MockContainer;

        type Item = u128;

        type ItemCount = u32;

        const ITEM_COUNT_OFFSET: usize = mem::offset_of!(MockContainer, count);

        const ARRAY_OFFSET: usize = mem::offset_of!(MockContainer, array);

        fn new_container(first_item: Self::Item) -> Self::Container {
            MockContainer {
                count: 1,
                array: [first_item],
            }
        }

        fn increment_count(count: Self::ItemCount) -> Self::ItemCount {
            count + 1
        }
    }

    type MockDst = Win32Dst<MockDef>;

    // Ideally run with miri.
    #[test]
    fn smoke() {
        let mut dst = MockDst::new(u128::MAX);

        dst.push(u128::MIN);

        for item in dst.as_slice() {
            core::hint::black_box(item);
        }

        assert_eq!(dst.as_slice().len(), 2);
    }
}
