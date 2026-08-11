//! This crate provides a core ebml specification that is used by the ebml-iterable crate.
//!
//! The related ebml-iterable-specification-derive crate can be used to simplify implementation of this spec.
//!

///
/// Contains an empty specification for use with examples or very basic testing.
///
pub mod empty_spec;

///
/// Different data types defined in the EBML specification.
///
/// # Notes
///
/// This library made a concious decision to not work with "Date" elements from EBML due to lack of built-in support for dates in Rust. Specification implementations should treat Date elements as Binary so that consumers have the option of parsing the unaltered data using their library of choice, if needed.
///

// Possible future feature flag to enable Date functionality by having `chrono` as an optional dependency?
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum TagDataType {
    Master,
    UnsignedInt,
    Integer,
    Utf8,
    Binary,
    Float,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum PathPart {
    Id(u64),
    Global((Option<u64>, Option<u64>)),
}

///
/// This trait, along with [`EbmlTag`], should be implemented to define a specification so that EBML can be parsed correctly.  Typically implemented on an Enum of tag variants.
///
/// Any specification using EBML can take advantage of this library to parse or write binary data.  As stated in the docs, [`TagWriter`](https://docs.rs/ebml-iterable/latest/ebml_iterable/struct.TagWriter.html) needs nothing special if you stick with the `write_raw` method, but [`TagIterator`](https://docs.rs/ebml-iterable/latest/ebml_iterable/struct.TagIterator.html) requires a struct implementing this trait.  Custom specification implementations can refer to [webm-iterable](https://crates.io/crates/webm_iterable) as an example.
///
/// This trait and [`EbmlTag`] are typically implemented simultaneously.  They are separate traits as they have primarily different uses - [`EbmlSpecification`] should be brought into scope when dealing with the specification as a whole, whereas [`EbmlTag`] should be brought into scope when dealing with specific tags.
pub trait EbmlSpecification<T: EbmlSpecification<T> + EbmlTag<T> + Clone> {
    ///
    /// Pulls the data type for a tag from the spec, based on the tag id.
    ///
    /// This function *must* return [`None`] if the input id is not in the specification.  Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn get_tag_data_type(id: u64) -> Option<TagDataType>;

    ///
    /// Gets the id of a specific tag variant.
    ///
    /// Default implementation uses the [`EbmlTag`] implementation. Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn get_tag_id(item: &T) -> u64 {
        item.get_id()
    }

    ///
    /// Gets the schema path of a specific tag.
    ///
    /// This function is used to find the schema defined path of a tag.  If the tag is a root element, this function should return an empty array.
    ///
    fn get_path_by_id(id: u64) -> &'static [PathPart];

    ///
    /// Gets the schema path of a specific tag variant.
    ///
    /// Default implementation uses [`Self::get_path_by_id`] after obtaining the tag id using the [`EbmlTag`] implementation.
    ///
    fn get_path_by_tag(item: &T) -> &'static [PathPart] {
        Self::get_path_by_id(item.get_id())
    }

    ///
    /// Creates an unsigned integer type tag from the spec.
    ///
    /// This function *must* return `None` if the input id is not in the specification or if the input id data type is not [`TagDataType::UnsignedInt`]. Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn get_unsigned_int_tag(id: u64, data: u64) -> Option<T>;

    ///
    /// Creates a signed integer type tag from the spec.
    ///
    /// This function *must* return `None` if the input id is not in the specification or if the input id data type is not [`TagDataType::Integer`]. Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn get_signed_int_tag(id: u64, data: i64) -> Option<T>;

    ///
    /// Creates a utf8 type tag from the spec.
    ///
    /// This function *must* return `None` if the input id is not in the specification or if the input id data type is not [`TagDataType::Utf8`]. Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn get_utf8_tag(id: u64, data: String) -> Option<T>;

    ///
    /// Creates a binary type tag from the spec.
    ///
    /// This function *must* return `None` if the input id is not in the specification or if the input id data type is not [`TagDataType::Binary`]. Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn get_binary_tag(id: u64, data: &[u8]) -> Option<T>;

    ///
    /// Creates a float type tag from the spec.
    ///
    /// This function *must* return `None` if the input id is not in the specification or if the input id data type is not [`TagDataType::Float`]. Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn get_float_tag(id: u64, data: f64) -> Option<T>;

    ///
    /// Creates a master type tag from the spec.
    ///
    /// This function *must* return `None` if the input id is not in the specification or if the input id data type is not [`TagDataType::Master`]. Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn get_master_tag(id: u64, data: Master<T>) -> Option<T>;

    ///
    /// Creates a tag that does not conform to the spec.
    ///
    /// This function should return a "RawTag" variant that contains the tag id and tag data.  Tag data should only be retrievable as binary data. Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn get_raw_tag(id: u64, data: &[u8]) -> T;
}

///
/// This trait, along with [`EbmlSpecification`], should be implemented to define a specification so that EBML can be parsed correctly.  Typically implemented on an Enum of tag variants.
///
/// Any specification using EBML can take advantage of this library to parse or write binary data.  As stated in the docs, [`TagWriter`](https://docs.rs/ebml-iterable/latest/ebml_iterable/struct.TagWriter.html) needs nothing special if you stick with the `write_raw` method, but [`TagIterator`](https://docs.rs/ebml-iterable/latest/ebml_iterable/struct.TagIterator.html) requires a struct implementing this trait.  Custom specification implementations can refer to [webm-iterable](https://crates.io/crates/webm_iterable) as an example.
///
/// This trait and [`EbmlSpecification`] are typically implemented simultaneously.  They are separate traits as they have primarily different uses - [`EbmlSpecification`] should be brought into scope when dealing with the specification as a whole, whereas [`EbmlTag`] should be brought into scope when dealing with specific tags.
pub trait EbmlTag<T: Clone> {
    ///
    /// Gets the id of `self`.
    ///
    /// Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn get_id(&self) -> u64;

    ///
    /// Gets a reference to the data contained in `self` as an unsigned integer.
    ///
    /// This function *must* return `None` if the associated data type of `self` is not [`TagDataType::UnsignedInt`].  Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn as_unsigned_int(&self) -> Option<&u64>;

    ///
    /// Gets a reference to the data contained in `self` as an integer.
    ///
    /// This function *must* return `None` if the associated data type of `self` is not [`TagDataType::Integer`].  Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn as_signed_int(&self) -> Option<&i64>;

    ///
    /// Gets a reference to the data contained in `self` as string slice.
    ///
    /// This function *must* return `None` if the associated data type of `self` is not [`TagDataType::Utf8`].  Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn as_utf8(&self) -> Option<&str>;

    ///
    /// Gets a reference to the data contained in `self` as binary data.
    ///
    /// This function *must* return `None` if the associated data type of `self` is not [`TagDataType::Binary`].  Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn as_binary(&self) -> Option<&[u8]>;

    ///
    /// Gets a reference to the data contained in `self` as float data.
    ///
    /// This function *must* return `None` if the associated data type of `self` is not [`TagDataType::Float`].  Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn as_float(&self) -> Option<&f64>;

    ///
    /// Gets a reference to master data contained in `self`.
    ///
    /// This function *must* return `None` if the associated data type of `self` is not [`TagDataType::Master`].  Implementors can reference [webm-iterable](https://crates.io/crates/webm_iterable) for an example.
    ///
    fn as_master(&self) -> Option<&Master<T>>;
}

///
/// An enum that defines different possible states of a [`TagDataType::Master`] tag.
///
/// A "master" tag is a type of tag that contains other tags within it.  Because these tags are dynamically sized, the [`TagIterator`](https://docs.rs/ebml-iterable/latest/ebml_iterable/struct.TagIterator.html) emits these tags as [`Master::Start`] and [`Master::End`] variants by default so that the entire tag does not need to be buffered into memory all at once.  The [`Master::Full`] variant is a complete "master" tag that includes all child tags within it.
///
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Master<T: Clone> {
    ///
    /// Designates the start of a tag.
    ///
    Start,

    ///
    /// Designates the end of a tag.
    ///
    End,

    ///
    /// Designates a full tag.  `Vec<T>` contains all child tags contained in this master tag.
    ///
    Full(Vec<T>),
}

impl<T: Clone> Master<T> {
    ///
    /// Convenience method to pull children from a master tag.
    ///
    /// # Panics
    ///
    /// Panics if `self` is not a `Full` variant.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ebml_iterable_specification::empty_spec::EmptySpec;
    /// use ebml_iterable_specification::Master;
    ///
    /// let children = vec![EmptySpec::with_data(0x1253, &[1]), EmptySpec::with_data(0x1234, &[2])];
    /// // Clone children because creating a Master consumes it
    /// let tag = Master::Full(children.clone());
    /// let retrieved_children = tag.get_children();
    /// assert_eq!(retrieved_children, children);
    /// ```
    ///
    pub fn get_children(self) -> Vec<T> {
        match self {
            Master::Full(data) => data,
            Master::Start => panic!("`get_children` called on Master::Start variant"),
            Master::End => panic!("`get_children` called on Master::End variant"),
        }
    }
}
