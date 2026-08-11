use std::io::ErrorKind;
use std::iter::repeat;
use std::mem;
use ebml_iterable_specification::{EbmlSpecification, EbmlTag, Master, TagDataType};
use futures::{AsyncRead, AsyncReadExt, Stream};
use crate::error::{TagIteratorError, ToolError};
use crate::errors::tag_iterator::CorruptedFileError;
use crate::tag_iterator_util::{EBMLSize, ProcessingTag};
use crate::tag_iterator_util::EBMLSize::Known;
use crate::tools;

///
/// This Can be transformed into a [`Stream`] using [`into_stream`][TagIteratorAsync::into_stream], or consumed directly by calling [`.next().await`] in a loop.
///
/// The struct can be created with the [`new()`][TagIteratorAsync::new] function on any source that implements the [`futures::AsyncRead`] trait.
///
pub struct TagIteratorAsync<R: AsyncRead + Unpin, TSpec>
    where
        TSpec: EbmlSpecification<TSpec> + EbmlTag<TSpec> + Clone
{
    read: R,
    buf: Vec<u8>,
    offset: usize,
    tag_stack: Vec<ProcessingTag<TSpec>>
}

impl<R: AsyncRead + Unpin, TSpec> TagIteratorAsync<R, TSpec>
    where
        TSpec: EbmlSpecification<TSpec> + EbmlTag<TSpec> + Clone
{

    pub fn new(read: R) -> Self {
        Self {
            read,
            buf: Default::default(),
            offset: 0,
            tag_stack: Default::default()
        }
    }

    fn current_offset(&self) -> usize {
        self.offset
    }

    fn advance(&mut self, length: usize) {
        self.offset += length;
        self.buf.drain(0..length);
    }

    fn advance_get(&mut self, length: usize) -> Vec<u8> {
        self.offset += length;
        let upper = self.buf.split_off(length);
        mem::replace(&mut self.buf, upper)
    }

    async fn ensure_data_read(&mut self, len: usize) -> Result<bool, TagIteratorError> {
        let size = self.buf.len();
        if size < len {
            let remaining = len - size;
            self.buf.extend(repeat(0).take(remaining));
            if let Err(source) = self.read.read_exact(&mut self.buf[size..]).await {
                return match source.kind() {
                    ErrorKind::UnexpectedEof => {
                        Ok(false)
                    }
                    _ => Err(TagIteratorError::ReadError { source })
                }
            }
        }
        Ok(true)
    }

    async fn read_tag_id(&mut self) -> Result<u64, TagIteratorError> {
        self.ensure_data_read(8).await?;
        match tools::read_vint(&self.buf).unwrap_or(Some((0, 1))) {
            Some((value, length)) => {
                self.advance(length);
                Ok(value + (1 << (7 * length)))
            },
            None => Err(TagIteratorError::UnexpectedEOF{ tag_start: self.current_offset(), tag_id: None, tag_size: None, partial_data: None }),
        }
    }

    async fn read_tag_size(&mut self) -> Result<EBMLSize, TagIteratorError> {
        self.ensure_data_read(8).await?;
        match tools::read_vint(&self.buf).or(Err(TagIteratorError::CorruptedFileData(CorruptedFileError::InvalidTagData { tag_id: 0, position: self.current_offset() })))? {
            Some((value, length)) => {
                self.advance(length);
                Ok(EBMLSize::new(value, length))
            },
            None => Err(TagIteratorError::UnexpectedEOF{ tag_start: self.current_offset(), tag_id: None, tag_size: None, partial_data: None }),
        }
    }

    async fn read_tag_data(&mut self, size: usize) -> Result<Vec<u8>, TagIteratorError> {
        if !self.ensure_data_read(size).await? {
            return Err(TagIteratorError::UnexpectedEOF{ tag_start: self.current_offset(), tag_id: None, tag_size: None, partial_data: None });
        }
        Ok(self.advance_get(size))
    }

    async fn read_tag(&mut self) -> Result<TSpec, TagIteratorError> {
        let tag_id = self.read_tag_id().await?;
        let spec_tag_type = TSpec::get_tag_data_type(tag_id);
        let size = self.read_tag_size().await?;
        let current_offset = self.current_offset();

        let is_master = matches!(spec_tag_type, Some(TagDataType::Master));
        if is_master {
            self.tag_stack.push(ProcessingTag {
                tag: TSpec::get_master_tag(tag_id, Master::End).unwrap_or_else(|| panic!("Bad specification implementation: Tag id {} type was master, but could not get tag!", tag_id)),
                size,
                data_start: current_offset,
                tag_start: 0, //not implemented here
            });
            Ok(TSpec::get_master_tag(tag_id, Master::Start).unwrap_or_else(|| panic!("Bad specification implementation: Tag id {} type was master, but could not get tag!", tag_id)))
        } else {
            let size = if let Known(size) = size {
                size
            } else {
                return Err(TagIteratorError::CorruptedFileData(CorruptedFileError::InvalidTagData { tag_id, position: current_offset }));
            };

            let raw_data = self.read_tag_data(size).await?;
            let tag = match spec_tag_type {
                Some(TagDataType::Master) => { unreachable!("Master should have been handled before querying data") },
                Some(TagDataType::UnsignedInt) => {
                    let val = tools::arr_to_u64(&raw_data).map_err(|e| TagIteratorError::CorruptedTagData{ tag_id, problem: e })?;
                    TSpec::get_unsigned_int_tag(tag_id, val).unwrap_or_else(|| panic!("Bad specification implementation: Tag id {} type was unsigned int, but could not get tag!", tag_id))
                },
                Some(TagDataType::Integer) => {
                    let val = tools::arr_to_i64(&raw_data).map_err(|e| TagIteratorError::CorruptedTagData{ tag_id, problem: e })?;
                    TSpec::get_signed_int_tag(tag_id, val).unwrap_or_else(|| panic!("Bad specification implementation: Tag id {} type was integer, but could not get tag!", tag_id))
                },
                Some(TagDataType::Utf8) => {
                    let val = String::from_utf8(raw_data.to_vec()).map_err(|e| TagIteratorError::CorruptedTagData{ tag_id, problem: ToolError::FromUtf8Error(raw_data, e) })?;
                    TSpec::get_utf8_tag(tag_id, val).unwrap_or_else(|| panic!("Bad specification implementation: Tag id {} type was utf8, but could not get tag!", tag_id))
                },
                Some(TagDataType::Binary) | None => {
                    TSpec::get_binary_tag(tag_id, &raw_data).unwrap_or_else(|| TSpec::get_raw_tag(tag_id, &raw_data))
                },
                Some(TagDataType::Float) => {
                    let val = tools::arr_to_f64(&raw_data).map_err(|e| TagIteratorError::CorruptedTagData{ tag_id, problem: e })?;
                    TSpec::get_float_tag(tag_id, val).unwrap_or_else(|| panic!("Bad specification implementation: Tag id {} type was float, but could not get tag!", tag_id))
                },
            };

            match self.tag_stack.last() {
                None => Ok(tag),
                Some(previous_tag) => {
                    let previous_tag_ended = previous_tag.is_ended_by(tag_id);

                    if previous_tag_ended {
                        Ok(mem::replace(self.tag_stack.last_mut().unwrap(), ProcessingTag { tag, size: Known(size), data_start: current_offset, tag_start: 0 }).into_inner())
                    } else {
                        Ok(tag)
                    }
                }
            }
        }
    }

    /// can be consumed
    pub async fn next(&mut self) -> Option<Result<TSpec, TagIteratorError>> {
        if let Some(tag) = self.tag_stack.pop() {
            if let Known(size) = tag.size {
                if self.current_offset() >= tag.data_start + size {
                    return Some(Ok(tag.tag));
                }
            }
            self.tag_stack.push(tag);
        }

        match self.ensure_data_read(1).await {
            Err(err) => return Some(Err(err)),
            Ok(data_remaining) => {
                if !data_remaining {
                    return self.tag_stack.pop().map(|tag| Ok(tag.into_inner()));
                }
            }
        }
        Some(self.read_tag().await)
    }

    pub fn into_stream(self) -> impl Stream<Item=Result<TSpec, TagIteratorError>> {
        futures::stream::unfold(self, |mut read| async {
            let next = read.next().await;
            next.map(move |it| (it, read))
        })
    }
}
