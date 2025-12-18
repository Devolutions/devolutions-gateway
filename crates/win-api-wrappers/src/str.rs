//! Utility module providing types for manipulating wide strings.

// Re-export relevant items from the widestring crate.
pub use widestring::{
    U16CStr, U16CString, U16Str, U16String, Utf16Str, Utf16String, decode_utf16, decode_utf16_lossy, encode_utf16,
    include_utf16str, u16cstr, u16str, utf16str,
};

#[cfg(target_os = "windows")]
pub use self::win_ext::*;

#[cfg(target_os = "windows")]
mod win_ext {
    use windows::Win32::Foundation::UNICODE_STRING;
    use windows::core::{PCWSTR, PWSTR};

    use super::{U16CStr, U16CString};

    pub trait U16CStrExt {
        /// # Safety
        ///
        /// This function is unsafe as there is no guarantee that the given pointer is valid or
        /// has a nul terminator, and the function could scan past the underlying buffer.
        ///
        /// In addition, the data must meet the safety conditions of
        /// [std::slice::from_raw_parts_mut].
        ///
        /// # Panics
        ///
        /// This function panics if `ptr` is null.
        ///
        /// # Caveat
        ///
        /// The lifetime for the returned string is inferred from its usage. To prevent
        /// accidental misuse, it's suggested to tie the lifetime to whichever source lifetime
        /// is safe in the context, such as by providing a helper function taking the lifetime
        /// of a host value for the string, or by explicit annotation.
        unsafe fn from_pwstr<'a>(ptr: PWSTR) -> &'a mut U16CStr;

        /// # Safety
        ///
        /// This function is unsafe as there is no guarantee that the given pointer is valid or
        /// has a nul terminator, and the function could scan past the underlying buffer.
        ///
        /// In addition, the data must meet the safety conditions of
        /// [std::slice::from_raw_parts]. In particular, the returned string reference *must not
        /// be mutated* for the duration of lifetime `'a`, except inside an
        /// [`UnsafeCell`][std::cell::UnsafeCell].
        ///
        /// # Panics
        ///
        /// This function panics if `ptr` is null.
        ///
        /// # Caveat
        ///
        /// The lifetime for the returned string is inferred from its usage. To prevent
        /// accidental misuse, it's suggested to tie the lifetime to whichever source lifetime
        /// is safe in the context, such as by providing a helper function taking the lifetime
        /// of a host value for the string, or by explicit annotation.
        unsafe fn from_pcwstr<'a>(ptr: PCWSTR) -> &'a U16CStr;

        fn as_pwstr(&mut self) -> PWSTR;

        fn as_pcwstr(&self) -> PCWSTR;
    }

    impl U16CStrExt for U16CStr {
        unsafe fn from_pwstr<'a>(ptr: PWSTR) -> &'a mut U16CStr {
            // SAFETY: Same safety invariants as the function itself.
            unsafe { U16CStr::from_ptr_str_mut(ptr.as_ptr()) }
        }

        unsafe fn from_pcwstr<'a>(ptr: PCWSTR) -> &'a U16CStr {
            // SAFETY: Same safety invariants as the function itself.
            unsafe { U16CStr::from_ptr_str(ptr.as_ptr()) }
        }

        fn as_pwstr(&mut self) -> PWSTR {
            PWSTR(self.as_mut_ptr())
        }

        fn as_pcwstr(&self) -> PCWSTR {
            PCWSTR(self.as_ptr())
        }
    }

    pub trait U16CStringExt {
        /// Constructs a new wide C string copied from a nul-terminated string pointer.
        ///
        /// This will scan for nul values beginning with `p`. The first nul value will be used
        /// as the nul terminator for the string, similar to how libc string functions such as
        /// `strlen` work.
        ///
        /// # Safety
        ///
        /// This function is unsafe as there is no guarantee that the given pointer is valid or
        /// has a nul terminator, and the function could scan past the underlying buffer.
        ///
        /// In addition, the data must meet the safety conditions of
        /// [std::slice::from_raw_parts].
        ///
        /// # Panics
        ///
        /// This function panics if `ptr` is null.
        unsafe fn from_pwstr(ptr: PWSTR) -> U16CString;
    }

    impl U16CStringExt for U16CString {
        unsafe fn from_pwstr(ptr: PWSTR) -> U16CString {
            // SAFETY: Same safety invariants as the function itself.
            unsafe { U16CString::from_ptr_str(ptr.as_ptr()) }
        }
    }

    #[derive(Debug, Clone, Copy, thiserror::Error)]
    #[error("string too big")]
    pub struct StringTooBigErr;

    /// Guards mutable accesses to a U16CStr as a UNICODE_STRING.
    pub struct UnicodeStrMut<'a> {
        inner: UNICODE_STRING,
        _marker: core::marker::PhantomData<&'a mut U16CStr>,
    }

    impl<'a> UnicodeStrMut<'a> {
        pub fn new(s: &'a mut U16CStr) -> Result<UnicodeStrMut<'a>, StringTooBigErr> {
            // U16CStr strings are null-terminated.
            // Since UNICODE_STRING::Length must not include the null terminator, we decrement by one.
            let length = u16::try_from(s.as_slice_with_nul().len()).map_err(|_| StringTooBigErr)? - 1;

            let buffer = s.as_pwstr();

            Ok(UnicodeStrMut {
                inner: UNICODE_STRING {
                    Length: length,
                    MaximumLength: length,
                    Buffer: buffer,
                },
                _marker: std::marker::PhantomData,
            })
        }

        /// Returns a UNICODE_STRING structure which may be mutated.
        pub fn as_unicode_string(&mut self) -> UNICODE_STRING {
            self.inner
        }
    }

    /// Guards shared accesses to a U16CStr as a UNICODE_STRING.
    ///
    /// The inner UNICODE_STRING is holding a PWSTR, but the underlying pointer origins from a const
    /// pointer that must not be mutated.
    pub struct UnicodeStr<'a> {
        inner: UNICODE_STRING,
        _marker: core::marker::PhantomData<&'a U16CStr>,
    }

    impl<'a> UnicodeStr<'a> {
        pub fn new(s: &'a U16CStr) -> Result<UnicodeStr<'a>, StringTooBigErr> {
            // U16CStr strings are null-terminated.
            // Since UNICODE_STRING::Length must not include the null terminator, we decrement by one.
            let length = u16::try_from(s.as_slice_with_nul().len()).map_err(|_| StringTooBigErr)? - 1;

            let pcwstr = s.as_pcwstr();
            let buffer = PWSTR(pcwstr.0.cast_mut());

            Ok(UnicodeStr {
                inner: UNICODE_STRING {
                    Length: length,
                    MaximumLength: length,
                    Buffer: buffer,
                },
                _marker: std::marker::PhantomData,
            })
        }

        /// Returns a UNICODE_STRING structure that must not be mutated.
        pub fn as_unicode_string(&self) -> UNICODE_STRING {
            self.inner
        }
    }
}
