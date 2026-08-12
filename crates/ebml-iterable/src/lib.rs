//! This crate provides an iterator and a serializer for [EBML][EBML] files.  Its primary goal is to provide typed iteration and serialization as lightly and quickly as possible.
//!
//! [EBML][EBML] stands for Extensible Binary Meta-Language and is somewhat of a
//! binary version of XML. It's used for container formats like [WebM][webm] or
//! [MKV][mkv].
//!
//! # Important - Specifications
//! The iterator contained in this crate is spec-agnostic and requires a specification implementing the [`specs::EbmlSpecification`] and [`specs::EbmlTag`] traits to read files.  Typically, you would only use this crate to implement a custom specification - most often you would prefer a crate providing an existing specification, like [webm-iterable][webm-iterable].
//!
//! Implementing custom specifications can be made less painful and safer by enabling the `"derive-spec"` feature flag in this crate and using the [`#[ebml_specification]`](https://docs.rs/ebml-iterable-specification-derive/latest/ebml_iterable_specification_derive/attr.ebml_specification.html) macro.
//!
//! # Features
//!
//! There is currently only one optional feature in this crate, but that may change over time as needs arise.
//!
//! * **derive-spec** -
//!   When enabled, this provides the [`#[ebml_specification]`](https://docs.rs/ebml-iterable-specification-derive/latest/ebml_iterable_specification_derive/attr.ebml_specification.html) attribute macro to simplify implementation of the [`EbmlSpecification`][`specs::EbmlSpecification`] and [`EbmlTag`][`specs::EbmlTag`] traits.  This introduces dependencies on [`syn`](https://crates.io/crates/syn), [`quote`](https://crates.io/crates/quote), and [`proc-macro2`](https://crates.io/crates/proc-macro2), so expect compile times to increase a little.
//!
//! [EBML]: http://ebml.sourceforge.net/
//! [webm]: https://www.webmproject.org/
//! [mkv]: http://www.matroska.org/technical/specs/index.html
//! [rfc8794]: https://datatracker.ietf.org/doc/rfc8794/
//! [webm-iterable]: https://crates.io/crates/webm_iterable
//!

mod errors;
mod spec_util;
pub mod specs;
mod tag_decoder;
mod tag_iterator;
mod tag_iterator_util;
mod tag_parse;
mod tag_writer;
pub mod tools;

#[cfg(feature = "futures")]
pub mod nonblocking;

pub use self::tag_decoder::{PositionedTag, TagDecoder};
pub use self::tag_iterator::TagIterator;
pub use self::tag_writer::{TagWriter, WriteOptions};

pub mod iterator {
    pub use super::tag_iterator_util::AllowableErrors;
}

pub mod error {

    //!
    //! Potential errors that can occur when reading or writing EBML data.
    //!
    pub use super::errors::tag_iterator::{CorruptedFileError, TagIteratorError};
    pub use super::errors::tag_writer::TagWriterError;
    ///
    /// Error details that may be included in some thrown errors
    ///
    pub use super::errors::tool::ToolError;
}
