//! Utility module providing types for manipulating wide strings.

// Re-export relevant items from the widestring crate.
pub use widestring::{
    decode_utf16, decode_utf16_lossy, encode_utf16, include_utf16str, u16cstr, u16str, utf16str, U16CStr, U16CString,
    U16Str, U16String, Utf16Str, Utf16String,
};

#[cfg(target_os = "windows")]
pub use self::win_ext::*;

#[cfg(target_os = "windows")]
mod win_ext {
    use super::{U16CStr, U16CString};

    use windows::core::{PCWSTR, PWSTR};

    pub trait U16CStrExt {
        unsafe fn from_pwstr<'a>(ptr: PWSTR) -> &'a mut U16CStr;
        unsafe fn from_pcwstr<'a>(ptr: PCWSTR) -> &'a U16CStr;
        fn as_pwstr(&mut self) -> PWSTR;
        fn as_pcwstr(&self) -> PCWSTR;
    }

    impl U16CStrExt for U16CStr {
        unsafe fn from_pwstr<'a>(ptr: PWSTR) -> &'a mut U16CStr {
            unsafe { U16CStr::from_ptr_str_mut(ptr.as_ptr()) }
        }

        unsafe fn from_pcwstr<'a>(ptr: PCWSTR) -> &'a U16CStr {
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
        unsafe fn from_pwstr(ptr: PWSTR) -> U16CString;
        fn as_pwstr(&mut self) -> PWSTR;
        fn as_pcwstr(&self) -> PCWSTR;
    }

    impl U16CStringExt for U16CString {
        unsafe fn from_pwstr(ptr: PWSTR) -> U16CString {
            unsafe { U16CString::from_raw(ptr.as_ptr()) }
        }

        fn as_pwstr(&mut self) -> PWSTR {
            PWSTR(self.as_mut_ptr())
        }

        fn as_pcwstr(&self) -> PCWSTR {
            PCWSTR(self.as_ptr())
        }
    }
}
