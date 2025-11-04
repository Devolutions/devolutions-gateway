//! Helpers for dynamically sized types found in Win32 API.

use crate::raw_buffer::{InitedBuffer, RawBuffer};

/// Definition for a Win32-style dynamically sized type.
///
/// # Safety
///
/// - The offsets must be in bound of the container.
/// - The container must be annotated with `#[repr(C)]`
/// - The container must not be annotated `#[repr(packed)]`.
/// - The array is defined last in the struct.
/// - The array defined in the container must be an array exactly of length 1,
///   otherwise the Drop implementation will attempt to drop some items twice.
pub unsafe trait Win32DstDef {
    type Container;

    type Item;

    type ItemCount: TryInto<usize> + Copy;

    /// Extra parameters to construct the container.
    type Parameters;

    /// Offset to the item count, in bounds of the container.
    const ITEM_COUNT_OFFSET: usize;

    /// Offset to the array, in bounds of the container.
    const ARRAY_OFFSET: usize;

    /// Builds a container holding a single element.
    fn new_container(params: Self::Parameters, first_item: Self::Item) -> Self::Container;

    /// Increments count by one.
    fn increment_count(count: Self::ItemCount) -> Self::ItemCount;
}

/// Wrapper over a Win32-style dynamically sized type.
pub struct Win32Dst<Def>
where
    Def: Win32DstDef,
{
    /// INVARIANT: The array holds exactly `Def::ItemCount` elements.
    /// INVARIANT: `Def::ITEM_COUNT_OFFSET` is in bounds of the allocated container.
    /// INVARIANT: `Def::ARRAY_OFFSET` is in bounds of the allocated container.
    /// INVARIANT: `Def::Container` is #[repr(C)], and not #[repr(packed)], so the fields are properly aligned when reading.
    inner: InitedBuffer<Def::Container>,
}

impl<Def> Win32Dst<Def>
where
    Def: Win32DstDef,
{
    pub fn new(params: Def::Parameters, first_item: Def::Item) -> Self {
        use core::alloc::Layout;

        let container = Def::new_container(params, first_item);

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
    /// The underlying array must hold exactly the amount of `Def::Item` specified inside the `Def::ItemCount`.
    pub unsafe fn from_raw(buffer: InitedBuffer<Def::Container>) -> Self {
        Self { inner: buffer }
    }

    pub fn as_raw(&self) -> &InitedBuffer<Def::Container> {
        &self.inner
    }

    pub fn as_raw_mut(&mut self) -> &mut InitedBuffer<Def::Container> {
        &mut self.inner
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
        // - We immediately write the new value in-place, keeping the underlying object valid.
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
                .add(current_count.try_into().ok().expect("count is too big"))
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

        // SAFETY: Per invariants, the data at the offset ITEM_COUNT_OFFSET is a valid ItemCount value.
        unsafe { count_ptr.cast::<Def::ItemCount>().read() }
    }

    pub fn as_slice(&self) -> &[Def::Item] {
        let count = self.count().try_into().ok().expect("count is too big");

        // SAFETY: Per invariants, the offset must be in bounds of the allocated object.
        let array_ptr = unsafe { self.inner.as_ptr().byte_add(Def::ARRAY_OFFSET) };

        // SAFETY: Per invariants, the array contains `count` items.
        unsafe { core::slice::from_raw_parts(array_ptr.cast::<Def::Item>(), count) }
    }
}

impl<Def> Drop for Win32Dst<Def>
where
    Def: Win32DstDef,
{
    fn drop(&mut self) {
        use core::ptr::drop_in_place;

        let current_count = self.count().try_into().ok().expect("count is too big");

        let raw_buffer = self.inner.as_inner_mut();

        // SAFETY: Per invariants, the offset is in bounds of the container.
        let array_ptr = unsafe { raw_buffer.as_mut_ptr().byte_add(Def::ARRAY_OFFSET) };

        // We need to manually drop all the items past the first element of the array.
        for idx in 1..current_count {
            // SAFETY:
            // - The index is bounded by the allocated object.
            // - current_count is a reasonable value as per invariants.
            let item_ptr = unsafe { array_ptr.cast::<Def::Item>().add(idx) };

            // SAFETY:
            // - item_ptr is valid for both reads and writes.
            // - item_ptr is properly aligned.
            // - item_ptr is nonnull.
            // - We assume the safety invariants which may be associated to the item are properly upheld.
            // - The RawBuffer is owned by us, and no-one else can access it (unless unsafe code is used).
            // - As per invariants, the container is defined as #[repr(C)].
            unsafe { drop_in_place::<Def::Item>(item_ptr) };
        }

        // Finally, we drop the container itself.
        // This includes the first item.

        // SAFETY: Safe for the same reason it is safe for the items.
        unsafe { drop_in_place::<Def::Container>(self.inner.as_mut_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::undocumented_unsafe_blocks,
        reason = "test code with known safety properties"
    )]
    #![expect(clippy::print_stdout, reason = "test code uses print for diagnostics")]

    //! Ideally, these tests should be run under Miri to check for UBs and memory leaks.

    use std::mem;

    use super::*;

    #[test]
    fn pod_item() {
        let mut list = U128List::new((), u128::MAX);

        list.push(u128::MIN);

        assert_eq!(list.as_slice(), &[u128::MAX, u128::MIN]);

        #[repr(C)]
        struct U128Container {
            count: u32,
            array: [u128; 1],
        }

        struct U128ListDef;

        unsafe impl Win32DstDef for U128ListDef {
            type Container = U128Container;

            type Item = u128;

            type ItemCount = u32;

            type Parameters = ();

            const ITEM_COUNT_OFFSET: usize = mem::offset_of!(U128Container, count);

            const ARRAY_OFFSET: usize = mem::offset_of!(U128Container, array);

            fn new_container(_: Self::Parameters, first_item: Self::Item) -> Self::Container {
                U128Container {
                    count: 1,
                    array: [first_item],
                }
            }

            fn increment_count(count: Self::ItemCount) -> Self::ItemCount {
                count + 1
            }
        }

        type U128List = Win32Dst<U128ListDef>;
    }

    #[test]
    fn allocated_item() {
        let mut list = StringList::new("some_metadata".to_owned(), "hello".to_owned());

        list.push("world".to_owned());
        list.push("foo".to_owned());
        list.push("bar".to_owned());

        for item in list.as_slice() {
            println!("{item}")
        }

        assert_eq!(list.as_slice().len(), 4);

        #[repr(C)]
        struct StringContainer {
            count: u8,
            _some_allocated_metadata: String,
            array: [String; 1],
        }

        struct StringListDef;

        unsafe impl Win32DstDef for StringListDef {
            type Container = StringContainer;

            type Item = String;

            type ItemCount = u8;

            type Parameters = String;

            const ITEM_COUNT_OFFSET: usize = mem::offset_of!(StringContainer, count);

            const ARRAY_OFFSET: usize = mem::offset_of!(StringContainer, array);

            fn new_container(some_allocated_metadata: Self::Parameters, first_item: Self::Item) -> Self::Container {
                StringContainer {
                    count: 1,
                    _some_allocated_metadata: some_allocated_metadata,
                    array: [first_item],
                }
            }

            fn increment_count(count: Self::ItemCount) -> Self::ItemCount {
                count + 1
            }
        }

        type StringList = Win32Dst<StringListDef>;
    }
}
