// This decoder extends Austin Blake's MIT-licensed ebml-iterable 0.6.3.
// Gateway vendors it because growing recordings must keep partial tags across appends.

use std::collections::{HashSet, VecDeque};

use bytes::{Buf, BytesMut};

use crate::errors::tag_iterator::{CorruptedFileError, TagIteratorError};
use crate::errors::tool::ToolError;
use crate::spec_util::{is_ended_by, validate_tag_path};
use crate::specs::{EbmlSpecification, EbmlTag, Master, PathPart, TagDataType};
use crate::tag_iterator_util::EBMLSize::{Known, Unknown};
use crate::tag_iterator_util::{AllowableErrors, EBMLSize};
use crate::tools;

const INVALID_TAG_ID_ERROR: u8 = 0x01;
const INVALID_HIERARCHY_ERROR: u8 = 0x02;
const OVERSIZED_CHILD_ERROR: u8 = 0x04;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PositionedTag<TSpec> {
    pub tag: TSpec,
    pub offset: usize,
}

struct OpenTag<TSpec> {
    id: u64,
    size: EBMLSize,
    tag_start: usize,
    data_start: usize,
    capture: bool,
    children: Vec<TSpec>,
}

struct TagHeader {
    id: u64,
    data_type: Option<TagDataType>,
    size: EBMLSize,
    len: usize,
}

pub struct TagDecoder<TSpec>
where
    TSpec: EbmlSpecification<TSpec> + EbmlTag<TSpec> + Clone,
{
    tag_ids_to_buffer: HashSet<u64>,
    allowed_errors: u8,
    max_allowed_tag_size: Option<usize>,
    position: usize,
    tag_stack: Vec<OpenTag<TSpec>>,
    emission_queue: VecDeque<PositionedTag<TSpec>>,
    has_determined_doc_path: bool,
    finished: bool,
}

impl<TSpec> TagDecoder<TSpec>
where
    TSpec: EbmlSpecification<TSpec> + EbmlTag<TSpec> + Clone,
{
    pub fn new(tags_to_buffer: &[TSpec]) -> Self {
        Self {
            tag_ids_to_buffer: tags_to_buffer.iter().map(EbmlTag::get_id).collect(),
            allowed_errors: 0,
            max_allowed_tag_size: Some(4 * usize::pow(1000, 3)),
            position: 0,
            tag_stack: Vec::new(),
            emission_queue: VecDeque::new(),
            has_determined_doc_path: false,
            finished: false,
        }
    }

    pub fn allow_errors(&mut self, errors: &[AllowableErrors]) {
        self.allowed_errors = errors.iter().fold(0u8, |allowed, error| match error {
            AllowableErrors::InvalidTagIds => allowed | INVALID_TAG_ID_ERROR,
            AllowableErrors::HierarchyProblems => allowed | INVALID_HIERARCHY_ERROR,
            AllowableErrors::OversizedTags => allowed | OVERSIZED_CHILD_ERROR,
        });
    }

    pub fn set_max_allowable_tag_size(&mut self, size: Option<usize>) {
        self.max_allowed_tag_size = size;
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn decode(&mut self, input: &mut BytesMut) -> Result<Option<PositionedTag<TSpec>>, TagIteratorError> {
        assert!(
            !self.finished || input.is_empty(),
            "cannot append EBML data after end of input"
        );
        if let Some(tag) = self.emission_queue.pop_front() {
            return Ok(Some(tag));
        }
        if self.finished {
            return Ok(None);
        }

        loop {
            self.close_completed_tags()?;
            if let Some(tag) = self.emission_queue.pop_front() {
                return Ok(Some(tag));
            }

            if input.is_empty() {
                return Ok(None);
            }

            let Some(header) = self.read_header(input)? else {
                return Ok(None);
            };

            self.close_unknown_tags(header.id)?;
            if let Some(tag) = self.emission_queue.pop_front() {
                return Ok(Some(tag));
            }

            self.validate_header(&header)?;
            if matches!(header.data_type, Some(TagDataType::Master)) {
                self.open_master(input, header)?;
            } else {
                let Some(tag) = self.read_data_tag(input, &header)? else {
                    return Ok(None);
                };
                self.deliver(tag, self.position);
                self.advance(input, header.len + header.size.value());
            }

            if let Some(tag) = self.emission_queue.pop_front() {
                return Ok(Some(tag));
            }
        }
    }

    pub fn decode_eof(&mut self, input: &mut BytesMut) -> Result<Option<PositionedTag<TSpec>>, TagIteratorError> {
        if let Some(tag) = self.decode(input)? {
            return Ok(Some(tag));
        }

        if !input.is_empty() {
            return Err(self.unexpected_eof(input));
        }

        if let Some(open_tag) = self
            .tag_stack
            .iter()
            .find(|tag| matches!(tag.size, Known(size) if self.position < tag.data_start.saturating_add(size)))
        {
            return Err(TagIteratorError::UnexpectedEOF {
                tag_start: open_tag.tag_start,
                tag_id: Some(open_tag.id),
                tag_size: match open_tag.size {
                    Known(size) => Some(size),
                    Unknown => None,
                },
                partial_data: None,
            });
        }

        while !self.tag_stack.is_empty() {
            self.close_top()?;
        }
        self.finished = true;

        Ok(self.emission_queue.pop_front())
    }

    pub fn is_finished(&self) -> bool {
        self.finished && self.emission_queue.is_empty()
    }

    fn read_header(&self, input: &[u8]) -> Result<Option<TagHeader>, TagIteratorError> {
        let Some(first) = input.first().copied() else {
            return Ok(None);
        };
        let id_len = if first == 0 { 1 } else { 8 - first.ilog2() as usize };
        if input.len() < id_len {
            return Ok(None);
        }

        let id = input[..id_len]
            .iter()
            .fold(0u64, |value, byte| (value << 8) + u64::from(*byte));
        let size_start = id_len;
        let size = tools::read_vint(&input[size_start..]).map_err(|_| {
            TagIteratorError::CorruptedFileData(CorruptedFileError::InvalidTagData {
                tag_id: id,
                position: self.position,
            })
        })?;
        let Some((size, size_len)) = size else {
            return Ok(None);
        };
        let data_type = TSpec::get_tag_data_type(id);

        if matches!(
            data_type,
            Some(TagDataType::UnsignedInt | TagDataType::Integer | TagDataType::Float)
        ) && (size == 0 || size > 8)
        {
            return Err(TagIteratorError::CorruptedFileData(
                CorruptedFileError::InvalidTagData {
                    tag_id: id,
                    position: self.position,
                },
            ));
        }

        Ok(Some(TagHeader {
            id,
            data_type,
            size: EBMLSize::new(size, size_len),
            len: id_len + size_len,
        }))
    }

    fn validate_header(&mut self, header: &TagHeader) -> Result<(), TagIteratorError> {
        if self.allowed_errors & INVALID_TAG_ID_ERROR == 0 && header.data_type.is_none() {
            return Err(TagIteratorError::CorruptedFileData(CorruptedFileError::InvalidTagId {
                position: self.position,
                tag_id: header.id,
            }));
        }

        self.determine_doc_path(header.id);
        if self.allowed_errors & INVALID_HIERARCHY_ERROR == 0
            && header.data_type.is_some()
            && self.has_determined_doc_path
            && !validate_tag_path::<TSpec>(header.id, self.tag_stack.iter().map(|tag| (tag.id, tag.size, 0)))
        {
            return Err(TagIteratorError::CorruptedFileData(
                CorruptedFileError::HierarchyError {
                    found_tag_id: header.id,
                    current_parent_id: self.tag_stack.last().map(|tag| tag.id),
                },
            ));
        }

        if let Known(size) = header.size {
            let total_size = header.len.checked_add(size).ok_or({
                TagIteratorError::CorruptedFileData(CorruptedFileError::InvalidTagSize {
                    position: self.position,
                    tag_id: header.id,
                    size,
                })
            })?;
            let element_end = self.position.checked_add(total_size).ok_or({
                TagIteratorError::CorruptedFileData(CorruptedFileError::InvalidTagSize {
                    position: self.position,
                    tag_id: header.id,
                    size,
                })
            })?;

            if self.allowed_errors & OVERSIZED_CHILD_ERROR == 0
                && self.tag_stack.iter().any(|tag| {
                    matches!(tag.size, Known(parent_size) if tag.data_start.saturating_add(parent_size) < element_end)
                })
            {
                return Err(TagIteratorError::CorruptedFileData(
                    CorruptedFileError::OversizedChildElement {
                        position: self.position,
                        tag_id: header.id,
                        size,
                    },
                ));
            }

            if self.max_allowed_tag_size.is_some_and(|max_size| size > max_size) {
                return Err(TagIteratorError::CorruptedFileData(
                    CorruptedFileError::InvalidTagSize {
                        position: self.position,
                        tag_id: header.id,
                        size,
                    },
                ));
            }
        }

        Ok(())
    }

    fn determine_doc_path(&mut self, tag_id: u64) {
        if self.has_determined_doc_path {
            return;
        }

        let path = TSpec::get_path_by_id(tag_id);
        if !path.iter().all(|part| matches!(part, PathPart::Id(_))) {
            return;
        }

        self.tag_stack = path
            .iter()
            .map(|part| match part {
                PathPart::Id(id) => OpenTag {
                    id: *id,
                    size: Unknown,
                    tag_start: 0,
                    data_start: 0,
                    capture: false,
                    children: Vec::new(),
                },
                PathPart::Global(_) => unreachable!(),
            })
            .collect();
        self.has_determined_doc_path = true;
    }

    fn open_master(&mut self, input: &mut BytesMut, header: TagHeader) -> Result<(), TagIteratorError> {
        let tag_start = self.position;
        let data_start = self
            .position
            .checked_add(header.len)
            .expect("validated tag header length should fit in usize");
        let capture =
            self.tag_ids_to_buffer.contains(&header.id) || self.tag_stack.last().is_some_and(|parent| parent.capture);
        let start = TSpec::get_master_tag(header.id, Master::Start).unwrap_or_else(|| {
            panic!(
                "Bad specification implementation: Tag id 0x{:x?} type was master, but could not get tag!",
                header.id
            )
        });

        self.advance(input, header.len);
        self.tag_stack.push(OpenTag {
            id: header.id,
            size: header.size,
            tag_start,
            data_start,
            capture,
            children: Vec::new(),
        });
        if !capture {
            self.emission_queue.push_back(PositionedTag {
                tag: start,
                offset: tag_start,
            });
        }

        Ok(())
    }

    fn read_data_tag(&self, input: &[u8], header: &TagHeader) -> Result<Option<TSpec>, TagIteratorError> {
        let Known(size) = header.size else {
            return Err(TagIteratorError::CorruptedFileData(
                CorruptedFileError::InvalidTagData {
                    tag_id: header.id,
                    position: self.position,
                },
            ));
        };
        let total_size = header
            .len
            .checked_add(size)
            .expect("validated tag size should fit in usize");
        if input.len() < total_size {
            return Ok(None);
        }

        let raw_data = &input[header.len..total_size];
        let tag = match header.data_type {
            Some(TagDataType::Master) => unreachable!(),
            Some(TagDataType::UnsignedInt) => {
                let value = tools::arr_to_u64(raw_data).map_err(|problem| TagIteratorError::CorruptedTagData {
                    tag_id: header.id,
                    problem,
                })?;
                TSpec::get_unsigned_int_tag(header.id, value)
            }
            Some(TagDataType::Integer) => {
                let value = tools::arr_to_i64(raw_data).map_err(|problem| TagIteratorError::CorruptedTagData {
                    tag_id: header.id,
                    problem,
                })?;
                TSpec::get_signed_int_tag(header.id, value)
            }
            Some(TagDataType::Utf8) => {
                let value =
                    String::from_utf8(raw_data.to_vec()).map_err(|error| TagIteratorError::CorruptedTagData {
                        tag_id: header.id,
                        problem: ToolError::FromUtf8Error(raw_data.to_vec(), error),
                    })?;
                TSpec::get_utf8_tag(header.id, value)
            }
            Some(TagDataType::Binary) => TSpec::get_binary_tag(header.id, raw_data),
            Some(TagDataType::Float) => {
                let value = tools::arr_to_f64(raw_data).map_err(|problem| TagIteratorError::CorruptedTagData {
                    tag_id: header.id,
                    problem,
                })?;
                TSpec::get_float_tag(header.id, value)
            }
            None => return Ok(Some(TSpec::get_raw_tag(header.id, raw_data))),
        }
        .unwrap_or_else(|| {
            panic!(
                "Bad specification implementation: Tag id 0x{:x?} had an incompatible data type!",
                header.id
            )
        });

        Ok(Some(tag))
    }

    fn close_completed_tags(&mut self) -> Result<(), TagIteratorError> {
        let ended_index = self
            .tag_stack
            .iter()
            .position(|tag| matches!(tag.size, Known(size) if self.position >= tag.data_start.saturating_add(size)));
        if let Some(index) = ended_index {
            while self.tag_stack.len() > index {
                self.close_top()?;
            }
        }
        Ok(())
    }

    fn close_unknown_tags(&mut self, next_id: u64) -> Result<(), TagIteratorError> {
        while self
            .tag_stack
            .last()
            .is_some_and(|tag| tag.size == Unknown && is_ended_by::<TSpec>(tag.id, next_id))
        {
            self.close_top()?;
        }
        Ok(())
    }

    fn close_top(&mut self) -> Result<(), TagIteratorError> {
        let open_tag = self
            .tag_stack
            .pop()
            .expect("an open tag should exist before it is closed");
        let id = open_tag.id;
        let tag_start = open_tag.tag_start;
        let tag = if open_tag.capture {
            TSpec::get_master_tag(id, Master::Full(open_tag.children))
        } else {
            TSpec::get_master_tag(id, Master::End)
        }
        .unwrap_or_else(|| {
            panic!(
                "Bad specification implementation: Tag id 0x{:x?} type was master, but could not get tag!",
                id
            )
        });
        self.deliver(tag, tag_start);
        Ok(())
    }

    fn deliver(&mut self, tag: TSpec, offset: usize) {
        if let Some(parent) = self.tag_stack.iter_mut().rev().find(|parent| parent.capture) {
            parent.children.push(tag);
        } else {
            self.emission_queue.push_back(PositionedTag { tag, offset });
        }
    }

    fn advance(&mut self, input: &mut BytesMut, count: usize) {
        input.advance(count);
        self.position = self
            .position
            .checked_add(count)
            .expect("validated tag size should keep the decoder position in usize");
    }

    fn unexpected_eof(&self, input: &[u8]) -> TagIteratorError {
        let first = input.first().copied();
        let id_len = first.map_or(0, |byte| if byte == 0 { 1 } else { 8 - byte.ilog2() as usize });
        let tag_id = (id_len > 0 && input.len() >= id_len).then(|| {
            input[..id_len]
                .iter()
                .fold(0u64, |value, byte| (value << 8) + u64::from(*byte))
        });
        let size = tag_id.and_then(|_| {
            tools::read_vint(input.get(id_len..).unwrap_or_default())
                .ok()
                .flatten()
                .and_then(|(size, size_len)| match EBMLSize::new(size, size_len) {
                    Known(size) => Some((size, id_len + size_len)),
                    Unknown => None,
                })
        });
        let partial_data = size.map_or_else(
            || Some(input.to_vec()),
            |(_, header_len)| Some(input.get(header_len..).unwrap_or_default().to_vec()),
        );

        TagIteratorError::UnexpectedEOF {
            tag_start: self.position,
            tag_id,
            tag_size: size.map(|(size, _)| size),
            partial_data,
        }
    }
}
