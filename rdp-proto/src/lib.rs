//! The Rust implementation of the Remote Desktop Protocol.

// FromPrimitive and ToPrimitive causes clippy error, so we disable it until
// https://github.com/rust-num/num-derive/issues/20 is fixed
#![cfg_attr(feature = "cargo-clippy", allow(clippy::useless_attribute))]

#[macro_use]
mod utils;

mod ber;
mod credssp;
mod encryption;
mod nego;
mod ntlm;
mod per;
mod rdp;
mod sspi;
mod tpdu;

pub use crate::{
    credssp::{ts_request::TsRequest, CredSsp, CredSspClient, CredSspResult, CredSspServer, CredentialsProxy},
    nego::*,
    ntlm::NTLM_VERSION_SIZE,
    rdp::*,
    sspi::{Credentials, SspiError, SspiErrorType},
    tpdu::*,
};
