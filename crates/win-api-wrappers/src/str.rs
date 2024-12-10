use windows::core::{PCWSTR, PWSTR};

pub use widestring::*;

trait U16CStrExt {
    fn as_pwstr(&mut self) -> PWSTR;
    fn as_pcwstr(&self) -> PCWSTR;
}

impl U16CStrExt for U16Cstr {
    fn as_pwstr(&mut self) -> PWSTR {
        PWSTR(self.as_mut_ptr())
    }

    fn as_pcwstr(&self) -> PCWSTR {
        PWSTR(self.as_ptr())
    }
}
