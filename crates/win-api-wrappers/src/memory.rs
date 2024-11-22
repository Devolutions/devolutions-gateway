use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr;

pub trait FreeMemory {
    /// # Safety
    ///
    /// `ptr` must be a pointer which must be freed by this implementation.
    unsafe fn free(ptr: *mut c_void);
}

/// RAII wrapper for some form of memory.
///
/// The free function is not called if the pointer is null.
pub struct MemoryWrapper<FreeImpl: FreeMemory, T = c_void> {
    // INVARIANT: `ptr` is a pointer which must be freed by `FreeImpl`
    ptr: *mut T,

    _marker: PhantomData<FreeImpl>,
}

impl<FreeImpl: FreeMemory, T> MemoryWrapper<FreeImpl, T> {
    pub const fn null() -> Self {
        Self {
            ptr: ptr::null_mut(),
            _marker: PhantomData,
        }
    }

    /// Constructs a MemoryWrapper from a raw pointer.
    ///
    /// # Safety
    ///
    /// - `ptr` must be a valid pointer.
    /// - `ptr` must be freed by the associated free implementation `FreeImpl`.
    pub const unsafe fn from_raw(ptr: *mut T) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    pub const fn as_ptr(&self) -> *const T {
        self.ptr.cast_const()
    }

    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr
    }

    /// Forms a slice from the inner pointer and a length.
    ///
    /// The `len` argument is the number of **elements**, not the number of bytes.
    ///
    /// # Safety
    ///
    /// - Pointer must be valid for reads for `len * mem::size_of::<T>()` many bytes, and it must be properly aligned.
    /// - Pointer must point to `len` consecutive properly initialized values of type `T`.
    /// - The memory referenced by the returned slice must not be mutated for the duration of the borrowing, except inside an `UnsafeCell`.
    /// - The total size `len * mem::size_of::<T>()` of the slice must be no larger than `isize::MAX`, and adding that size to `data` must not "wrap around" the address space.
    pub unsafe fn cast_slice(&self, len: usize) -> &[T] {
        // SAFETY:
        // - Same preconditions as the current function.
        // - We are also tying the lifetime of the slice to the MemoryWrapper instance, ensuring the memory is not freed as long as it is being used.
        unsafe { std::slice::from_raw_parts(self.ptr, len) }
    }

    pub fn cast<U>(self) -> MemoryWrapper<FreeImpl, U> {
        let casted = MemoryWrapper {
            ptr: self.ptr.cast::<U>(),
            _marker: PhantomData,
        };

        // We transferred the owneship, do not call drop.
        core::mem::forget(self);

        casted
    }
}

impl<FreeImpl: FreeMemory, T> Drop for MemoryWrapper<FreeImpl, T> {
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }

        // SAFETY: Per invariant on `ptr`, `ptr` is a pointer which must be freed by `FreeImpl`.
        unsafe { FreeImpl::free(self.ptr.cast()) };
    }
}
