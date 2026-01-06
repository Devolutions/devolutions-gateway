use std::fmt::Debug;
use std::string::{FromUtf8Error, FromUtf16Error};

use thiserror::Error;
use windows::Win32::Foundation::{E_POINTER, WIN32_ERROR};
use windows::Win32::System::Rpc::RPC_STATUS;
use windows::core::HRESULT;

use crate::undoc::LSA_SID_NAME_MAPPING_OPERATION_ERROR;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    #[error(transparent)]
    Win32(#[from] windows::core::Error),
    #[error("Lsa SID name mapping error: {}", _0.0)]
    Lsa(LSA_SID_NAME_MAPPING_OPERATION_ERROR),
    #[error("null pointer: {0}")]
    NullPointer(&'static str),
}

impl Error {
    pub fn code(&self) -> i32 {
        match self {
            Error::Win32(err) => err.code().0,
            Error::Lsa(err) => err.0,
            Error::NullPointer(_) => E_POINTER.0,
        }
    }

    // FIXME: This function may be confusing. It may be best to mimick the windows crate.
    pub fn last_error() -> Self {
        Self::Win32(windows::core::Error::from_win32())
    }

    pub fn from_hresult(hresult: HRESULT) -> Self {
        Self::Win32(windows::core::Error::from_hresult(hresult))
    }

    pub fn from_win32(win32_error: WIN32_ERROR) -> Self {
        Self::from_hresult(HRESULT::from_win32(win32_error.0))
    }
}

impl From<HRESULT> for Error {
    fn from(err: HRESULT) -> Self {
        Self::from_hresult(err)
    }
}

impl From<RPC_STATUS> for Error {
    fn from(err: RPC_STATUS) -> Self {
        Self::from_hresult(err.to_hresult())
    }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Self {
        Self::Win32(windows::core::Error::from(err))
    }
}

impl From<FromUtf16Error> for Error {
    fn from(err: FromUtf16Error) -> Self {
        Self::Win32(windows::core::Error::from(err))
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Win32(windows::core::Error::from(err))
    }
}
