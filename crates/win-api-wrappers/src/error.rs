use std::{
    ffi::NulError,
    fmt::Debug,
    string::{FromUtf16Error, FromUtf8Error},
};

use windows::{
    core::HRESULT,
    Win32::{
        Foundation::{E_POINTER, WIN32_ERROR},
        System::Rpc::RPC_STATUS,
    },
};

use crate::undoc::LSA_SID_NAME_MAPPING_OPERATION_ERROR;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Win32(windows::core::Error),
    Lsa(LSA_SID_NAME_MAPPING_OPERATION_ERROR),
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
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Win32(err) => err.source(),
            Error::Lsa(_) => None,
            Error::NullPointer(_) => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Win32(err) => Debug::fmt(err, f),
            Error::Lsa(err) => err.fmt(f),
            Error::NullPointer(mem) => write!(f, "{} is null", mem),
        }
    }
}

impl Error {
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

impl From<windows::core::Error> for Error {
    fn from(err: windows::core::Error) -> Self {
        Self::Win32(err)
    }
}

impl From<windows::core::HRESULT> for Error {
    fn from(err: windows::core::HRESULT) -> Self {
        Self::from_hresult(err)
    }
}

impl From<Error> for windows::core::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::Win32(err) => err.clone(),
            Error::Lsa(err) => windows::core::Error::new(HRESULT(err.0), format!("Lsa Err {:?}", err)),
            Error::NullPointer(_) => Error::from_hresult(E_POINTER).into(),
        }
    }
}

impl From<Error> for std::io::Error {
    fn from(err: Error) -> Self {
        err.into()
    }
}

impl From<RPC_STATUS> for Error {
    fn from(err: RPC_STATUS) -> Self {
        Self::from_hresult(err.to_hresult())
    }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Self {
        err.into()
    }
}

impl From<FromUtf16Error> for Error {
    fn from(err: FromUtf16Error) -> Self {
        err.into()
    }
}

impl From<NulError> for Error {
    fn from(err: NulError) -> Self {
        err.into()
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        err.into()
    }
}
