use std::collections::{HashSet, VecDeque};
use std::io::Read;

use super::errors::tag_iterator::{CorruptedFileError, TagIteratorError};
use super::errors::tool::ToolError;
use super::specs::{EbmlSpecification, EbmlTag, Master, PathPart, TagDataType};
use super::tools;
use crate::spec_util::validate_tag_path;
use crate::tag_iterator_util::EBMLSize::{Known, Unknown};
use crate::tag_iterator_util::{AllowableErrors, EBMLSize, ProcessingTag, DEFAULT_BUFFER_LEN};

const INVALID_TAG_ID_ERROR: u8 = 0x01;
const INVALID_HIERARCHY_ERROR: u8 = 0x02;
const OVERSIZED_CHILD_ERROR: u8 = 0x04;

///
/// Provides an iterator over EBML files (read from a source implementing the [`std::io::Read`] trait). Can be configured to read specific "Master" tags as complete objects rather than just emitting when they start and end.
///
/// This is a generic struct that requires a specification implementing [`EbmlSpecification`] and [`EbmlTag`]. No specifications are included in this crate - you will need to either use another crate providing a spec (such as the Matroska spec implemented in the [webm-iterable](https://crates.io/crates/webm_iterable) or write your own spec if you want to iterate over a custom EBML file. The iterator outputs `TSpec` variants representing the type of tag (defined by the specification) and the accompanying tag data. "Master" tags (defined by the specification) usually will be read as `Start` and `End` variants, but the iterator can be configured to buffer Master tags into a `Full` variant using the `tags_to_buffer` parameter.
///
/// Note: The [`Self::with_capacity()`] method can be used to construct a `TagIterator` with a specified default buffer size.  This is only useful as a microoptimization to memory management if you know the maximum tag size of the file you're reading.
///
/// ## Example
///
/// ```no_run
/// use std::fs::File;
/// use ebml_iterable::TagIterator;
/// #
/// # use ebml_iterable::specs::{EbmlSpecification, TagDataType};
/// # use ebml_iterable_specification::empty_spec::EmptySpec;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let file = File::open("my_ebml_file.ebml")?;
/// let mut my_iterator: TagIterator<_, EmptySpec> = TagIterator::new(file, &[]);
/// for tag in my_iterator {
///   println!("{:?}", tag?);
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Errors
///
/// The `Item` type for the associated [`Iterator`] implementation is a [`Result<TSpec, TagIteratorError>`], meaning each `next()` call has the potential to fail.  This is because the source data is not parsed all at once - it is incrementally parsed as the iterator progresses.  If the iterator runs into an error (such as corrupted data or an unexpected end-of-file), it needs to be propagated to the logic trying to read the tags.  The different possible error states are enumerated in [`TagIteratorError`].
///
/// ## Panics
///
/// The iterator can panic if `<TSpec>` is an internally inconsistent specification (i.e. it claims that a specific tag id has a specific data type but fails to produce a tag variant using data of that type).  This won't happen if the specification being used was created using the [`#[ebml_specification]`](https://docs.rs/ebml-iterable-specification-derive/latest/ebml_iterable_specification_derive/attr.ebml_specification.html) attribute macro.
///
pub struct TagIterator<R: Read, TSpec>
where
    TSpec: EbmlSpecification<TSpec> + EbmlTag<TSpec> + Clone,
{
    source: R,
    tag_ids_to_buffer: HashSet<u64>,
    allowed_errors: u8,
    max_allowed_tag_size: Option<usize>,

    buffer: Box<[u8]>,
    buffer_offset: Option<usize>,
    buffered_byte_length: usize,
    internal_buffer_position: usize,
    tag_stack: Vec<ProcessingTag<TSpec>>,
    emission_queue: VecDeque<Result<(TSpec, usize), TagIteratorError>>,
    last_emitted_tag_offset: usize,
    has_determined_doc_path: bool,

    emit_master_end_when_eof: bool,
}

impl<R: Read, TSpec> TagIterator<R, TSpec>
where
    TSpec: EbmlSpecification<TSpec> + EbmlTag<TSpec> + Clone,
{
    ///
    /// Returns a new [`TagIterator<TSpec>`] instance.
    ///
    /// The `source` parameter must implement [`std::io::Read`].  The second argument, `tags_to_buffer`, specifies which "Master" tags should be read as [`Master::Full`]s rather than as [`Master::Start`] and [`Master::End`]s.  Refer to the documentation on [`TagIterator`] for more explanation of how to use the returned instance.
    ///
    pub fn new(source: R, tags_to_buffer: &[TSpec]) -> Self {
        TagIterator::with_capacity(source, tags_to_buffer, DEFAULT_BUFFER_LEN)
    }

    ///
    /// Returns a new [`TagIterator<TSpec>`] instance with the specified internal buffer capacity.
    ///
    /// This initializes the [`TagIterator`] with a specific byte capacity.  The iterator will still reallocate if necessary. (Reallocation occurs if the iterator comes across a tag that should be output as a [`Master::Full`] and its size in bytes is greater than the iterator's current buffer capacity.)
    ///
    pub fn with_capacity(source: R, tags_to_buffer: &[TSpec], capacity: usize) -> Self {
        let buffer = vec![0; capacity];

        TagIterator {
            source,
            tag_ids_to_buffer: tags_to_buffer.iter().map(|tag| tag.get_id()).collect(),
            allowed_errors: 0,
            max_allowed_tag_size: Some(4 * usize::pow(1000, 3)), // 4GB
            buffer: buffer.into_boxed_slice(),
            buffered_byte_length: 0,
            buffer_offset: None,
            internal_buffer_position: 0,
            tag_stack: Vec::new(),
            emission_queue: VecDeque::new(),
            last_emitted_tag_offset: 0,
            has_determined_doc_path: false,
            emit_master_end_when_eof: true,
        }
    }

    ///
    /// Configures how strictly the iterator abides `<TSpec>`.
    ///
    /// By default (as of v0.5.0), the iterator assumes `<TSpec>` is complete and that any tags that do not conform to `<TSpec>` are due to corrupted file data.  This method can be used to relax some of these checks so that fewer [`TagIteratorError::CorruptedFileData`] errors occur.
    ///
    /// # Important
    ///
    /// Relaxing these checks do not necessarily make the iterator more robust.  If all errors are allowed, the iterator will assume any incoming tag id and tag data size are valid, and it will produce "RawTag"s containing binary contents for any tag ids not in `<TSpec>`.  However, if the file truly has corrupted data, the "size" of these elements will likely be corrupt as well.  This can typically result in requests for massive allocations, causing delays and eventual crashing.  By eagerly returning errors (the default), applications can decide how to handle corrupted elements more quickly and efficiently.
    ///
    /// tldr; allow errors at your own risk
    ///
    /// > Note: TagIterators returned by [`Self::new()`] and [`Self::with_capacity()`] allow no errors by default.
    ///
    pub fn allow_errors(&mut self, errors: &[AllowableErrors]) {
        self.allowed_errors = errors.iter().fold(0u8, |a, c| match c {
            AllowableErrors::InvalidTagIds => a | INVALID_TAG_ID_ERROR,
            AllowableErrors::HierarchyProblems => a | INVALID_HIERARCHY_ERROR,
            AllowableErrors::OversizedTags => a | OVERSIZED_CHILD_ERROR,
        });
    }

    ///
    /// Configures the maximum size a tag is allowed to be before the iterator considers it invalid.
    ///
    /// By default (as of v0.6.1), the iterator will throw an [`CorruptedFileError::InvalidTagSize`] error if it comes across any tags that declare their data to be more than 4GB.  This method can be used to change (and optionally remove) this behavior.  Note that increasing this size can potentially result in massive allocations, causing delays and panics.
    ///
    pub fn set_max_allowable_tag_size(&mut self, size: Option<usize>) {
        self.max_allowed_tag_size = size;
    }

    ///
    /// Instructs the iterator to attempt to recover after reaching corrupted file data.
    ///
    /// This method can be used to skip over corrupted sections of a read stream without recreating a new iterator.  The iterator will seek forward from its current internal position until it reaches either a valid EBML tag id or EOF.  After recovery, [`Iterator::next()`] *should* return an [`Ok`] result.
    ///
    pub fn try_recover(&mut self) -> Result<(), TagIteratorError> {
        let original_position = self.current_offset();
        loop {
            if !self.ensure_data_read(1)? {
                return Err(TagIteratorError::UnexpectedEOF {
                    tag_start: self.current_offset(),
                    tag_id: None,
                    tag_size: None,
                    partial_data: None,
                });
            }

            self.internal_buffer_position += 1;
            if self.peek_valid_tag_header().is_ok() {
                break;
            }
        }

        // As part of recovery, update internal tag stack sizes so that we don't get "oversized children" errors after skipping corrupted data
        let diff = self.current_offset() - original_position;
        for tag in self.tag_stack.iter_mut() {
            if let EBMLSize::Known(size) = &tag.size {
                tag.size = EBMLSize::Known(size + diff);
            }
        }

        Ok(())
    }

    ///
    /// Consumes self and returns the underlying read stream.
    ///
    /// Note that any leftover tags in the internal emission queue are lost, and any data read into [`TagIterator`]'s internal buffer is dropped. Therefore, constructing a new [`TagIterator`] using the returned stream may lead to data loss unless it is rewound.
    ///
    pub fn into_inner(self) -> R {
        self.source
    }

    ///
    /// Gets a mutable reference to the underlying read stream.
    ///
    /// It is inadvisable to directly read from the underlying stream.
    ///
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.source
    }

    ///
    /// Gets a reference to the underlying read stream.
    ///
    /// It is inadvisable to directly read from the underlying stream.
    ///
    pub fn get_ref(&self) -> &R {
        &self.source
    }

    ///
    /// Returns the byte offset of the last emitted tag.
    ///
    /// This function returns a byte index specifying the start of the last emitted tag in the context of the [`TagIterator`]'s source read stream.  This value is *not guaranteed to always increase as the file is read*.  Whenever the iterator emits a [`Master::End`] variant, [`Self::last_emitted_tag_offset()`] will reflect the start index of the "Master" tag, which will be before previous values that were obtainable when any children of the master were emitted.
    ///
    pub fn last_emitted_tag_offset(&self) -> usize {
        self.last_emitted_tag_offset
    }

    ///
    /// Control whether the iterator should emit closing tags when it reaches EOF.
    ///
    /// By default, the iterator will emit [`Master::End`] items for all currently open tags when it reaches the end of the file.  You may override this behavior by passing `false` to this method.
    ///
    /// This is recommended if you supply a [`std::io::Read`] source that can supply more data after reaching EOF, as in some streaming scenarios.
    ///
    pub fn emit_master_end_when_eof(&mut self, emit: bool) {
        self.emit_master_end_when_eof = emit;
    }

    #[inline(always)]
    fn current_offset(&self) -> usize {
        self.buffer_offset.unwrap_or(0) + self.internal_buffer_position
    }

    fn private_read(&mut self, internal_buffer_start: usize) -> Result<bool, TagIteratorError> {
        let bytes_read = self
            .source
            .read(&mut self.buffer[internal_buffer_start..])
            .map_err(|source| TagIteratorError::ReadError { source })?;
        if bytes_read == 0 {
            Ok(false)
        } else {
            self.buffered_byte_length += bytes_read;
            Ok(true)
        }
    }

    fn ensure_capacity(&mut self, required_capacity: usize) {
        if required_capacity > self.buffer.len() {
            let mut new_buffer = Vec::from(&self.buffer[..]);
            new_buffer.resize(required_capacity, 0);
            self.buffer = new_buffer.into_boxed_slice();
        }
    }

    fn ensure_data_read(&mut self, length: usize) -> Result<bool, TagIteratorError> {
        if self.internal_buffer_position + length <= self.buffered_byte_length {
            return Ok(true);
        }

        if self.buffer_offset.is_none() {
            if !self.private_read(0)? {
                return Ok(false);
            }
            self.buffer_offset = Some(0);
            self.internal_buffer_position = 0;
        } else {
            while self.internal_buffer_position + length > self.buffered_byte_length {
                self.buffer
                    .copy_within(self.internal_buffer_position..self.buffered_byte_length, 0);
                self.buffered_byte_length -= self.internal_buffer_position;
                self.buffer_offset = Some(self.current_offset());
                self.internal_buffer_position = 0;
                if !self.private_read(self.buffered_byte_length)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    #[inline(always)]
    fn peek_tag_id(&mut self) -> Result<(u64, usize), TagIteratorError> {
        self.ensure_data_read(8)?;
        if self.buffer[self.internal_buffer_position] == 0 {
            return Ok((0, 1));
        }
        let length = 8 - self.buffer[self.internal_buffer_position].ilog2() as usize;
        let mut val = self.buffer[self.internal_buffer_position] as u64;
        for i in 1..length {
            val <<= 8;
            val += self.buffer[self.internal_buffer_position + i] as u64;
        }
        Ok((val, length))
    }

    #[inline]
    fn peek_valid_tag_header(&mut self) -> Result<(u64, Option<TagDataType>, EBMLSize, usize), TagIteratorError> {
        self.ensure_data_read(16)?;
        let (tag_id, id_len) = self.peek_tag_id()?;
        let spec_tag_type = <TSpec>::get_tag_data_type(tag_id);

        let (size, size_len) = tools::read_vint(&self.buffer[(self.internal_buffer_position + id_len)..])
            .or(Err(TagIteratorError::CorruptedFileData(
                CorruptedFileError::InvalidTagData {
                    tag_id,
                    position: self.current_offset(),
                },
            )))?
            .ok_or(TagIteratorError::UnexpectedEOF {
                tag_start: self.current_offset(),
                tag_id: Some(tag_id),
                tag_size: None,
                partial_data: None,
            })?;

        if self.buffered_byte_length <= id_len + size_len {
            return Err(TagIteratorError::UnexpectedEOF {
                tag_start: self.current_offset(),
                tag_id: Some(tag_id),
                tag_size: None,
                partial_data: None,
            });
        }

        if matches!(
            spec_tag_type,
            Some(TagDataType::UnsignedInt) | Some(TagDataType::Integer) | Some(TagDataType::Float)
        ) && size > 8
        {
            return Err(TagIteratorError::CorruptedFileData(
                CorruptedFileError::InvalidTagData {
                    tag_id,
                    position: self.current_offset(),
                },
            ));
        }

        let size = EBMLSize::new(size, size_len);

        let header_len = id_len + size_len;

        if (self.allowed_errors & INVALID_TAG_ID_ERROR == 0) && spec_tag_type.is_none() {
            return Err(TagIteratorError::CorruptedFileData(CorruptedFileError::InvalidTagId {
                tag_id,
                position: self.current_offset(),
            }));
        }

        if (self.allowed_errors & INVALID_HIERARCHY_ERROR == 0) && spec_tag_type.is_some() {
            // Do not run check for raw tags    ^^^^^^^^^^^^^^^^^^^^^^^
            if !self.has_determined_doc_path {
                //Trust that the first tag in the stream is valid (like if the read stream was seeked to this location)
                let path = <TSpec>::get_path_by_id(tag_id);
                if path.iter().all(|p| matches!(p, PathPart::Id(_))) {
                    //We only know the current path if we read a tag that is non-global
                    self.tag_stack = path.iter().map(|id| {
                        match id {
                            PathPart::Id(id) => {
                                ProcessingTag {
                                    tag: <TSpec>::get_master_tag(*id, Master::Start).unwrap_or_else(|| panic!("Bad specification implementation: Tag id 0x{:x?} type was in path, but could not get master tag!", id)),
                                    size: EBMLSize::Unknown,
                                    tag_start: 0,
                                    data_start: 0,
                                }
                            },
                            PathPart::Global(_) => unreachable!()
                        }
                    }).collect();
                    self.has_determined_doc_path = true;
                }
            }
            if self.has_determined_doc_path && !self.validate_tag_path(tag_id) {
                return Err(TagIteratorError::CorruptedFileData(
                    CorruptedFileError::HierarchyError {
                        found_tag_id: tag_id,
                        current_parent_id: self.tag_stack.last().map(|tag| tag.tag.get_id()),
                    },
                ));
            }
        }

        if (self.allowed_errors & OVERSIZED_CHILD_ERROR == 0)
            && size.is_known()
            && self.is_invalid_tag_size(header_len + size.value())
        {
            return Err(TagIteratorError::CorruptedFileData(
                CorruptedFileError::OversizedChildElement {
                    position: self.current_offset(),
                    tag_id,
                    size: size.value(),
                },
            ));
        }

        if let Some(max_size) = self.max_allowed_tag_size {
            if size.is_known() && size.value() > max_size {
                return Err(TagIteratorError::CorruptedFileData(
                    CorruptedFileError::InvalidTagSize {
                        position: self.current_offset(),
                        tag_id,
                        size: size.value(),
                    },
                ));
            }
        }

        Ok((tag_id, spec_tag_type, size, header_len))
    }

    #[inline(always)]
    fn read_valid_tag_header(&mut self) -> Result<(u64, Option<TagDataType>, EBMLSize), TagIteratorError> {
        let (tag_id, spec_tag_type, size, header_len) = self.peek_valid_tag_header()?;

        self.internal_buffer_position += header_len;
        Ok((tag_id, spec_tag_type, size))
    }

    fn read_tag_data(&mut self, size: usize) -> Result<Option<&[u8]>, TagIteratorError> {
        self.ensure_capacity(size);
        if !self.ensure_data_read(size)? {
            return Ok(None);
        }

        self.internal_buffer_position += size;
        Ok(Some(
            &self.buffer[(self.internal_buffer_position - size)..self.internal_buffer_position],
        ))
    }

    fn read_tag(&mut self) -> Result<ProcessingTag<TSpec>, TagIteratorError> {
        let tag_start = self.current_offset();

        let (tag_id, spec_tag_type, size) = self.read_valid_tag_header()?;

        let data_start = self.current_offset();
        let raw_data = if matches!(spec_tag_type, Some(TagDataType::Master)) {
            &[]
        } else if let Known(size) = size {
            if let Some(data) = self.read_tag_data(size)? {
                data
            } else {
                return Err(TagIteratorError::UnexpectedEOF {
                    tag_start,
                    tag_id: Some(tag_id),
                    tag_size: Some(size),
                    partial_data: Some(self.buffer[self.internal_buffer_position..].to_vec()),
                });
            }
        } else {
            return Err(TagIteratorError::CorruptedFileData(
                CorruptedFileError::InvalidTagData {
                    tag_id,
                    position: tag_start,
                },
            ));
        };

        let tag = match spec_tag_type {
            Some(TagDataType::Master) => TSpec::get_master_tag(tag_id, Master::Start).unwrap_or_else(|| {
                panic!(
                    "Bad specification implementation: Tag id 0x{:x?} type was master, but could not get tag!",
                    tag_id
                )
            }),
            Some(TagDataType::UnsignedInt) => {
                let val = tools::arr_to_u64(raw_data)
                    .map_err(|e| TagIteratorError::CorruptedTagData { tag_id, problem: e })?;
                TSpec::get_unsigned_int_tag(tag_id, val).unwrap_or_else(|| panic!("Bad specification implementation: Tag id 0x{:x?} type was unsigned int, but could not get tag!", tag_id))
            }
            Some(TagDataType::Integer) => {
                let val = tools::arr_to_i64(raw_data)
                    .map_err(|e| TagIteratorError::CorruptedTagData { tag_id, problem: e })?;
                TSpec::get_signed_int_tag(tag_id, val).unwrap_or_else(|| {
                    panic!(
                        "Bad specification implementation: Tag id 0x{:x?} type was integer, but could not get tag!",
                        tag_id
                    )
                })
            }
            Some(TagDataType::Utf8) => {
                let val = String::from_utf8(raw_data.to_vec()).map_err(|e| TagIteratorError::CorruptedTagData {
                    tag_id,
                    problem: ToolError::FromUtf8Error(raw_data.to_vec(), e),
                })?;
                TSpec::get_utf8_tag(tag_id, val).unwrap_or_else(|| {
                    panic!(
                        "Bad specification implementation: Tag id 0x{:x?} type was utf8, but could not get tag!",
                        tag_id
                    )
                })
            }
            Some(TagDataType::Binary) => TSpec::get_binary_tag(tag_id, raw_data).unwrap_or_else(|| {
                panic!(
                    "Bad specification implementation: Tag id 0x{:x?} type was binary, but could not get tag!",
                    tag_id
                )
            }),
            Some(TagDataType::Float) => {
                let val = tools::arr_to_f64(raw_data)
                    .map_err(|e| TagIteratorError::CorruptedTagData { tag_id, problem: e })?;
                TSpec::get_float_tag(tag_id, val).unwrap_or_else(|| {
                    panic!(
                        "Bad specification implementation: Tag id 0x{:x?} type was float, but could not get tag!",
                        tag_id
                    )
                })
            }
            None => TSpec::get_raw_tag(tag_id, raw_data),
        };

        Ok(ProcessingTag {
            tag,
            size,
            tag_start,
            data_start,
        })
    }

    fn read_tag_checked(&mut self) -> Option<Result<ProcessingTag<TSpec>, TagIteratorError>> {
        if self.internal_buffer_position == self.buffered_byte_length {
            //If we've already consumed the entire internal buffer
            //ensure there is nothing else in the data source before returning `None`
            let read_result = self.ensure_data_read(1);
            match read_result {
                Err(err) => return Some(Err(err)),
                Ok(data_remaining) => {
                    if !data_remaining {
                        return None;
                    }
                }
            }
        }

        if self.internal_buffer_position > self.buffered_byte_length {
            panic!("read position exceeded buffer length");
        }

        Some(self.read_tag())
    }

    fn read_next(&mut self) {
        //If we have reached the known end of any open master tags, queue that tag and all children to emit ends
        let ended_tag_index = self
            .tag_stack
            .iter()
            .position(|tag| matches!(tag.size, Known(size) if self.current_offset() >= tag.data_start + size));
        if let Some(index) = ended_tag_index {
            self.emission_queue
                .extend(self.tag_stack.drain(index..).map(|t| Ok((t.tag, t.tag_start))).rev());
        }

        if let Some(next_read) = self.read_tag_checked() {
            if let Ok(next_tag) = &next_read {
                while matches!(self.tag_stack.last(), Some(open_tag) if open_tag.size == Unknown) {
                    let open_tag = self.tag_stack.last().unwrap();
                    let previous_tag_ended = open_tag.is_ended_by(next_tag.tag.get_id());

                    if previous_tag_ended {
                        let t = self.tag_stack.pop().unwrap();
                        self.emission_queue.push_back(Ok((t.tag, t.tag_start)));
                    } else {
                        break;
                    }
                }

                if let Some(Master::Start) = next_tag.tag.as_master() {
                    let tag_id = next_tag.tag.get_id();

                    self.tag_stack.push(ProcessingTag {
                        tag: TSpec::get_master_tag(tag_id, Master::End).unwrap(),
                        size: next_tag.size,
                        tag_start: next_tag.tag_start,
                        data_start: next_tag.data_start,
                    });

                    if self.tag_ids_to_buffer.contains(&tag_id) {
                        self.buffer_master(tag_id);
                        return;
                    }
                }
            }

            self.emission_queue.push_back(next_read.map(|r| (r.tag, r.tag_start)));
        } else if self.emit_master_end_when_eof {
            while let Some(tag) = self.tag_stack.pop() {
                self.emission_queue.push_back(Ok((tag.tag, tag.tag_start)));
            }
        }
    }

    fn buffer_master(&mut self, tag_id: u64) {
        let tag_start = self.current_offset();
        let pre_queue_len = self.emission_queue.len();

        let mut position = pre_queue_len;
        'endTagSearch: loop {
            if position >= self.emission_queue.len() {
                self.read_next();

                if position >= self.emission_queue.len() {
                    self.emission_queue.push_back(Err(TagIteratorError::UnexpectedEOF {
                        tag_start,
                        tag_id: Some(tag_id),
                        tag_size: None,
                        partial_data: None,
                    }));
                    return;
                }
            }

            while position < self.emission_queue.len() {
                if let Some(r) = self.emission_queue.get(position) {
                    match r {
                        Err(_) => break 'endTagSearch,
                        Ok(t) => {
                            if t.0.get_id() == tag_id && matches!(t.0.as_master(), Some(Master::End)) {
                                break 'endTagSearch;
                            }
                        }
                    }
                }
                position += 1;
            }
        }

        let mut children = self.emission_queue.split_off(pre_queue_len);
        let split_to = position - pre_queue_len;
        if children.get(split_to).unwrap().is_ok() {
            let remaining = children.split_off(split_to).into_iter().skip(1);
            let full_tag = Self::roll_up_children(tag_id, children.into_iter().map(|c| c.unwrap().0).collect());
            self.emission_queue.push_back(Ok((full_tag, tag_start)));
            self.emission_queue.extend(remaining);
        } else {
            self.emission_queue.extend(children.drain(split_to..).take(1));
        }
    }

    fn roll_up_children(tag_id: u64, children: Vec<TSpec>) -> TSpec {
        let mut rolled_children = Vec::new();

        let mut iter = children.into_iter();
        while let Some(child) = iter.next() {
            if let Some(Master::Start) = child.as_master() {
                let child_id = child.get_id();
                let subchildren = iter
                    .by_ref()
                    .take_while(|c| !matches!(c.as_master(), Some(Master::End)) || c.get_id() != child_id)
                    .collect();
                rolled_children.push(Self::roll_up_children(child_id, subchildren));
            } else {
                rolled_children.push(child);
            }
        }

        TSpec::get_master_tag(tag_id, Master::Full(rolled_children)).unwrap_or_else(|| {
            panic!(
                "Bad specification implementation: Tag id 0x{:x?} type was master, but could not get tag!",
                tag_id
            )
        })
    }

    #[inline(always)]
    fn validate_tag_path(&self, tag_id: u64) -> bool {
        validate_tag_path::<TSpec>(tag_id, self.tag_stack.iter().map(|p| (p.tag.get_id(), p.size, 0)))
    }

    #[inline(always)]
    fn is_invalid_tag_size(&self, size: usize) -> bool {
        self.tag_stack
            .iter()
            .filter(|p| p.size.is_known())
            .any(|t| (t.data_start + t.size.value()) < (self.current_offset() + size))
    }
}

impl<R: Read, TSpec> Iterator for TagIterator<R, TSpec>
where
    TSpec: EbmlSpecification<TSpec> + EbmlTag<TSpec> + Clone,
{
    type Item = Result<TSpec, TagIteratorError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.emission_queue.is_empty() {
            self.read_next();
        }
        let next_item = self.emission_queue.pop_front();
        if let Some(Ok(ref tuple)) = next_item {
            self.last_emitted_tag_offset = tuple.1;
        }
        next_item.map(|r| r.map(|t| t.0))
    }
}
