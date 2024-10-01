#[macro_use]
extern crate tracing;

#[cfg(target_os = "windows")]
#[path = ""]
mod lib_win {
    mod error;
    pub use error::Error;

    pub mod event;
    pub mod handle;
    pub mod identity;
    pub mod process;
    pub mod security;
    pub mod session;
    pub mod thread;
    pub mod token;
    pub mod utils;
    pub mod wts;

    // Allowed since the goal is to replicate the Windows API crate so that it's familiar, which itself uses the raw names from the API.
    #[allow(
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        unsafe_op_in_unsafe_fn,
        clippy::too_many_arguments,
        clippy::missing_safety_doc,
        clippy::undocumented_unsafe_blocks
    )]
    pub mod undoc;

    pub mod rpc;

    pub use windows as raw;
}

#[cfg(target_os = "windows")]
pub use lib_win::*;
