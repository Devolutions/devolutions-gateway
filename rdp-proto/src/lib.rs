// FromPrimitive and ToPrimitive causes clippy error, so we disable it until
// https://github.com/rust-num/num-derive/issues/20 is fixed
#![cfg_attr(feature = "cargo-clippy", allow(clippy::useless_attribute))]

pub mod ber;

mod credssp;
mod encryption;
mod nego;
mod ntlm;
mod sspi;
mod tpdu;

pub use crate::credssp::{ts_request::TsRequest, CredSsp, CredSspClient, CredSspResult, CredSspServer};
pub use crate::nego::*;
pub use crate::ntlm::NTLM_VERSION_SIZE;
pub use crate::sspi::{Credentials, SspiError, SspiErrorType};
pub use crate::tpdu::*;
