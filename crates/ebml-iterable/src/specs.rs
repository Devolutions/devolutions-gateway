//!
//! Provides the EBML specification types.
//!
//! Typically won't be used unless you are implementing a custom specification that uses EBML.  You can enable the `"derive-spec"` feature to obtain a macro to make implementation easier.
//!

pub use ebml_iterable_specification::{EbmlSpecification, EbmlTag, Master, PathPart, TagDataType};
#[cfg(feature = "derive-spec")]
pub use ebml_iterable_specification_derive::easy_ebml;
#[cfg(feature = "derive-spec")]
pub use ebml_iterable_specification_derive::ebml_specification;
