use std::io::Cursor;

use ebml_iterable_specification::{EbmlSpecification, EbmlTag};
use futures::{AsyncRead, AsyncReadExt, Stream};

use crate::error::TagIteratorError;
use crate::TagIterator;

///
/// This can be transformed into a [`Stream`] using [`into_stream`][TagIteratorAsync::into_stream], or consumed directly by calling [`.next().await`] in a loop.
///
/// The struct can be created with the [`new()`][TagIteratorAsync::new] function on any source that implements the [`futures::AsyncRead`] trait.
///
pub struct TagIteratorAsync<R: AsyncRead + Unpin, TSpec>
where
    TSpec: EbmlSpecification<TSpec> + EbmlTag<TSpec> + Clone,
{
    source: R,
    buffer: Box<[u8]>,
    iterator: TagIterator<Cursor<Vec<u8>>, TSpec>,
}

impl<R: AsyncRead + Unpin, TSpec> TagIteratorAsync<R, TSpec>
where
    TSpec: EbmlSpecification<TSpec> + EbmlTag<TSpec> + Clone,
{
    pub fn new(source: R, tags_to_buffer: &[TSpec]) -> Self {
        let buffer = vec![0u8; 1024 * 64];
        Self {
            source,
            buffer: buffer.into_boxed_slice(),
            iterator: TagIterator::new(Cursor::new(Vec::new()), tags_to_buffer),
        }
    }

    pub async fn next(&mut self) -> Option<Result<TSpec, TagIteratorError>> {
        match self.source.read(&mut self.buffer).await {
            Ok(len) => {
                self.iterator
                    .get_mut()
                    .get_mut()
                    .append(&mut self.buffer[..len].to_vec());
                self.iterator.next()
            }
            Err(e) => Some(Err(TagIteratorError::ReadError { source: e })),
        }
    }

    pub fn into_stream(self) -> impl Stream<Item = Result<TSpec, TagIteratorError>> {
        futures::stream::unfold(self, |mut read| async {
            let next = read.next().await;
            next.map(move |it| (it, read))
        })
    }

    pub fn last_emitted_tag_offset(&self) -> usize {
        self.iterator.last_emitted_tag_offset()
    }
}
