use std::convert::TryInto;

use ebml_iterable_specification::{EbmlSpecification, EbmlTag};

use crate::spec_util::is_ended_by;
use crate::tag_iterator_util::EBMLSize::{Known, Unknown};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum EBMLSize {
    Known(usize),
    Unknown,
}

impl EBMLSize {
    pub fn new(size: u64, vint_length: usize) -> Self {
        match vint_length {
            1 => {
                if size == ((1 << (7)) - 1) {
                    return Unknown;
                }
            }
            2 => {
                if size == ((1 << (7 * 2)) - 1) {
                    return Unknown;
                }
            }
            3 => {
                if size == ((1 << (7 * 3)) - 1) {
                    return Unknown;
                }
            }
            4 => {
                if size == ((1 << (7 * 4)) - 1) {
                    return Unknown;
                }
            }
            5 => {
                if size == ((1 << (7 * 5)) - 1) {
                    return Unknown;
                }
            }
            6 => {
                if size == ((1 << (7 * 6)) - 1) {
                    return Unknown;
                }
            }
            7 => {
                if size == ((1 << (7 * 7)) - 1) {
                    return Unknown;
                }
            }
            8 => {
                if size == ((1 << (7 * 8)) - 1) {
                    return Unknown;
                }
            }
            _ => {}
        }

        match size.try_into() {
            Ok(value) => Known(value),
            Err(_) => Unknown,
        }
    }

    #[inline(always)]
    pub fn is_known(&self) -> bool {
        matches!(&self, &EBMLSize::Known(_))
    }

    ///
    /// # Panics
    ///
    /// Panics if the current variant is not EBMLSize::Known
    ///
    #[inline(always)]
    pub fn value(&self) -> usize {
        match &self {
            EBMLSize::Known(val) => *val,
            _ => panic!("Called EBMLSize::value() on an unknown size!"),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ProcessingTag<TSpec>
where
    TSpec: EbmlSpecification<TSpec> + EbmlTag<TSpec> + Clone,
{
    pub tag: TSpec,
    pub size: EBMLSize,
    pub tag_start: usize,
    pub data_start: usize,
}

impl<TSpec> ProcessingTag<TSpec>
where
    TSpec: EbmlSpecification<TSpec> + EbmlTag<TSpec> + Clone,
{
    pub fn is_ended_by(&self, id: u64) -> bool {
        is_ended_by::<TSpec>(self.tag.get_id(), id)
    }
}

pub const DEFAULT_BUFFER_LEN: usize = 1024 * 64;

///
/// Used to relax rules on how strictly a [`TagIterator`](crate::TagIterator) should validate the read stream.
///
pub enum AllowableErrors {
    ///
    /// Causes the [`TagIterator`](crate::TagIterator) to produce "RawTag" binary variants for any unknown tag ids rather than throwing an error.
    ///
    InvalidTagIds,

    ///
    /// Causes the [`TagIterator`](crate::TagIterator) to emit tags even if they appear outside of their defined parent element.
    ///
    HierarchyProblems,

    ///
    /// Causes the [`TagIterator`](crate::TagIterator) to emit tags even if they exceed the length of a parent element.
    ///
    OversizedTags,
}
