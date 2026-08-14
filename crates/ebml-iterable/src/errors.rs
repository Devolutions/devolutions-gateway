use std::error::Error;
use std::fmt;

pub mod tool {
    use std::string::FromUtf8Error;

    use super::{fmt, Error};

    #[derive(Debug)]
    pub enum ToolError {
        ReadVintOverflow,
        WriteVintOverflow(u64),
        WriteSignedVintOverflow(i64),
        ReadU64Overflow(Vec<u8>),
        ReadI64Overflow(Vec<u8>),
        ReadF64Mismatch(Vec<u8>),
        FromUtf8Error(Vec<u8>, FromUtf8Error),
    }

    impl fmt::Display for ToolError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ToolError::ReadVintOverflow => write!(f, "Unrepresentable Vint size encountered."),
                ToolError::WriteVintOverflow(val) => write!(f, "Value too large to be written as a vint: {val}"),
                ToolError::WriteSignedVintOverflow(val) => {
                    write!(f, "Value outside range to be written as a vint: {val}")
                }
                ToolError::ReadU64Overflow(arr) => write!(f, "Could not read unsigned int from array: {arr:?}"),
                ToolError::ReadI64Overflow(arr) => write!(f, "Could not read int from array: {arr:?}"),
                ToolError::ReadF64Mismatch(arr) => write!(f, "Could not read float from array: {arr:?}"),
                ToolError::FromUtf8Error(arr, _source) => write!(f, "Could not read utf8 data: {arr:?}"),
            }
        }
    }

    impl Error for ToolError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                ToolError::FromUtf8Error(_arr, source) => Some(source),
                _ => None,
            }
        }
    }
}

pub mod tag_iterator {
    use std::io;

    use super::tool::ToolError;
    use super::{fmt, Error};

    ///
    /// Errors that indicate file data is corrupted.
    ///
    #[derive(Debug)]
    pub enum CorruptedFileError {
        ///
        /// An error indicating the reader found an ebml tag id not defined in the current specification.
        ///
        InvalidTagId {
            ///
            /// The position of the element.
            ///
            position: usize,

            ///
            /// The id of the tag that was found.
            ///
            tag_id: u64,
        },

        ///
        /// An error indicating the reader could not parse a valid tag due to corrupted tag data (size/contents).
        ///
        InvalidTagData {
            ///
            /// The position of the element.
            ///
            position: usize,

            ///
            /// The id of the tag that was found.
            ///
            tag_id: u64,
        },

        ///
        /// An error indicating the reader found an element outside of its expected hierarchy.
        ///
        HierarchyError {
            ///
            /// The id of the tag that was found.
            ///
            found_tag_id: u64,

            ///
            /// The id of the current "master" element that contains the tag that was found.
            ///
            current_parent_id: Option<u64>,
        },

        ///
        /// An error indicating the reader found a child element with incorrect sizing.
        ///
        OversizedChildElement {
            ///
            /// The position of the element.
            ///
            position: usize,

            ///
            /// The id of the tag that was found.
            ///
            tag_id: u64,

            ///
            /// The size of the tag that was found.
            ///
            size: usize,
        },

        ///
        /// An error indicating the reader found a tag with an invalid size.
        ///
        InvalidTagSize {
            ///
            /// The position of the element.
            ///
            position: usize,

            ///
            /// The id of the tag that was found.
            ///
            tag_id: u64,

            ///
            /// The size of the tag that was found.
            ///
            size: usize,
        },
    }

    impl fmt::Display for CorruptedFileError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                CorruptedFileError::InvalidTagId {
                    position,
                    tag_id
                } => write!(f, "Encountered invalid tag id [0x{tag_id:x?}] at position {position}"),
                CorruptedFileError::InvalidTagData {
                    position,
                    tag_id
                } => write!(f, "Encountered invalid tag data for tag id [0x{tag_id:x?}] at position {position}"),
                CorruptedFileError::HierarchyError {
                    found_tag_id,
                    current_parent_id,
                } => write!(f, "Found child tag [{found_tag_id:x?}] when processing parent [{current_parent_id:x?}]"),
                CorruptedFileError::OversizedChildElement {
                    position,
                    tag_id,
                    size : _
                } => write!(f, "Found an oversized tag [0x{tag_id:x?}] at position {position}"),
                CorruptedFileError::InvalidTagSize {
                    position,
                    tag_id,
                    size,
                } => write!(f, "Found an oversized tag [0x{tag_id:x?}] at position {position} with size {size}.  Max supported size is 8GB."),
            }
        }
    }

    ///
    /// Errors that can occur when reading ebml data.
    ///
    #[derive(Debug)]
    pub enum TagIteratorError {
        ///
        /// An error indicating that data in the file being read is not valid.
        ///
        CorruptedFileData(CorruptedFileError),

        ///
        /// An error indicating that the iterator reached the end of the input stream unexpectedly while reading a tag.
        ///
        /// This error will occur if the iterator is expecting more data (either due to expecting a size after reading a tag id or based on a tag size) but nothing is available in the input stream.
        ///
        UnexpectedEOF {
            ///
            /// The start position of the tag that was being read when EOF was reached.
            ///
            tag_start: usize,

            ///
            /// The id of the partially read tag, if available.
            ///
            tag_id: Option<u64>,

            ///
            /// The size of the partially read tag, if available.
            ///
            tag_size: Option<usize>,

            ///
            /// Any available data that was read for the tag before reaching EOF.
            ///
            partial_data: Option<Vec<u8>>,
        },

        ///
        /// An error indicating that tag data appears to be corrupted.
        ///
        /// This error typically occurs if tag data cannot be read as its expected data type (e.g. trying to read `[32,42,8]` as float data, since floats require either 4 or 8 bytes).
        ///
        CorruptedTagData {
            ///
            /// The id of the corrupted tag.
            ///
            tag_id: u64,

            ///
            /// An error describing why the data is corrupted.
            ///
            problem: ToolError,
        },

        ///
        /// An error that wraps an IO error when reading from the underlying source.
        ///
        ReadError {
            ///
            /// The [`io::Error`] that caused this problem.
            ///
            source: io::Error,
        },
    }

    impl fmt::Display for TagIteratorError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                TagIteratorError::CorruptedFileData(err) => write!(f, "Encountered corrupted data.  Message: {err}"),
                TagIteratorError::UnexpectedEOF {
                    tag_start,
                    tag_id,
                    tag_size,
                    partial_data: _
                } => write!(f, "Reached EOF unexpectedly. Partial tag data: {{tag offset:{tag_start}}} {{id:{tag_id:x?}}} {{size:{tag_size:?}}}"),
                TagIteratorError::CorruptedTagData {
                    tag_id,
                    problem,
                } => write!(f, "Error reading data for tag id (0x{tag_id:x?}). {problem}"),
                TagIteratorError::ReadError { source: _ } => write!(f, "Error reading from source."),
            }
        }
    }

    impl Error for TagIteratorError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                TagIteratorError::CorruptedFileData(_) => None,
                TagIteratorError::UnexpectedEOF {
                    tag_start: _,
                    tag_id: _,
                    tag_size: _,
                    partial_data: _,
                } => None,
                TagIteratorError::CorruptedTagData { tag_id: _, problem } => problem.source(),
                TagIteratorError::ReadError { source } => Some(source),
            }
        }
    }
}

pub mod tag_writer {
    use std::io;

    use super::{fmt, Error};

    ///
    /// Errors that can occur when writing ebml data.
    ///
    #[derive(Debug)]
    pub enum TagWriterError {
        ///
        /// An error indicating the tag to be written doesn't conform to the current specification.
        ///
        /// This error occurs if you attempt to write a tag outside of a valid document path.  See the [EBML RFC](https://www.rfc-editor.org/rfc/rfc8794.html#section-11.1.6.2) for details on element paths.
        ///
        UnexpectedTag { tag_id: u64, current_path: Vec<u64> },

        ///
        /// An error with a tag id.
        ///
        /// This error should only occur if writing "RawTag" variants, and only if the input id is not a valid vint.
        ///
        TagIdError(u64),

        ///
        /// An error with the size of a tag.
        ///
        /// Can occur if the tag size overflows the max value representable by a vint (`2^57 - 1`, or `144,115,188,075,855,871`).
        ///
        /// This can also occur if a non-[`Master`][`crate::specs::TagDataType::Master`] tag is sent to be written with an unknown size.
        ///
        TagSizeError(String),

        ///
        /// An error indicating a tag was closed unexpectedly.
        ///
        /// Can occur if a [`Master::End`][`crate::specs::Master::End`] variant is passed to the [`TagWriter`][`crate::TagWriter`] but the id doesn't match the currently open tag.
        ///
        UnexpectedClosingTag {
            ///
            /// The id of the tag being closed.
            ///
            tag_id: u64,

            ///
            /// The id of the currently open tag.
            ///
            expected_id: Option<u64>,
        },

        ///
        /// An error that wraps an IO error when writing to the underlying destination.
        ///
        WriteError { source: io::Error },
    }

    impl fmt::Display for TagWriterError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                TagWriterError::UnexpectedTag { tag_id, current_path } => {
                    write!(f, "Unexpected tag 0x{tag_id:x?} when writing to {current_path:x?}")
                }
                TagWriterError::TagIdError(id) => write!(f, "Tag id 0x{id:x?} is not a valid vint"),
                TagWriterError::TagSizeError(message) => write!(f, "Problem writing data tag size. {message}"),
                TagWriterError::UnexpectedClosingTag { tag_id, expected_id } => match expected_id {
                    Some(expected) => write!(f, "Unexpected closing tag 0x'{tag_id:x?}'. Expected 0x'{expected:x?}'"),
                    None => write!(f, "Unexpected closing tag 0x'{tag_id:x?}'"),
                },
                TagWriterError::WriteError { source: _ } => write!(f, "Error writing to destination."),
            }
        }
    }

    impl Error for TagWriterError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                TagWriterError::UnexpectedTag {
                    tag_id: _,
                    current_path: _,
                } => None,
                TagWriterError::TagIdError(_) => None,
                TagWriterError::TagSizeError(_) => None,
                TagWriterError::UnexpectedClosingTag {
                    tag_id: _,
                    expected_id: _,
                } => None,
                TagWriterError::WriteError { source } => Some(source),
            }
        }
    }
}
