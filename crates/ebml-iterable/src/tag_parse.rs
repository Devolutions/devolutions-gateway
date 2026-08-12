use crate::errors::tag_iterator::{CorruptedFileError, TagIteratorError};
use crate::errors::tool::ToolError;
use crate::specs::{EbmlSpecification, EbmlTag, TagDataType};
use crate::tag_iterator_util::EBMLSize;
use crate::tools;

pub(crate) struct TagHeader {
    pub id: u64,
    pub data_type: Option<TagDataType>,
    pub size: EBMLSize,
    pub len: usize,
}

pub(crate) fn read_header<TSpec>(input: &[u8], position: usize) -> Result<Option<TagHeader>, TagIteratorError>
where
    TSpec: EbmlSpecification<TSpec> + EbmlTag<TSpec> + Clone,
{
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
    let Some((size, size_len)) = tools::read_vint(&input[id_len..]).map_err(|_| {
        TagIteratorError::CorruptedFileData(CorruptedFileError::InvalidTagData { tag_id: id, position })
    })?
    else {
        return Ok(None);
    };
    let data_type = TSpec::get_tag_data_type(id);

    if matches!(
        data_type,
        Some(TagDataType::UnsignedInt | TagDataType::Integer | TagDataType::Float)
    ) && size > 8
    {
        return Err(TagIteratorError::CorruptedFileData(
            CorruptedFileError::InvalidTagData { tag_id: id, position },
        ));
    }

    Ok(Some(TagHeader {
        id,
        data_type,
        size: EBMLSize::new(size, size_len),
        len: id_len + size_len,
    }))
}

pub(crate) fn read_data_tag<TSpec>(
    id: u64,
    data_type: Option<TagDataType>,
    raw_data: &[u8],
) -> Result<TSpec, TagIteratorError>
where
    TSpec: EbmlSpecification<TSpec> + EbmlTag<TSpec> + Clone,
{
    let tag = match data_type {
        Some(TagDataType::Master) => unreachable!(),
        Some(TagDataType::UnsignedInt) => {
            let value = if raw_data.is_empty() {
                0
            } else {
                tools::arr_to_u64(raw_data)
                    .map_err(|problem| TagIteratorError::CorruptedTagData { tag_id: id, problem })?
            };
            TSpec::get_unsigned_int_tag(id, value)
        }
        Some(TagDataType::Integer) => {
            let value = if raw_data.is_empty() {
                0
            } else {
                tools::arr_to_i64(raw_data)
                    .map_err(|problem| TagIteratorError::CorruptedTagData { tag_id: id, problem })?
            };
            TSpec::get_signed_int_tag(id, value)
        }
        Some(TagDataType::Utf8) => {
            let value = String::from_utf8(raw_data.to_vec()).map_err(|error| TagIteratorError::CorruptedTagData {
                tag_id: id,
                problem: ToolError::FromUtf8Error(raw_data.to_vec(), error),
            })?;
            TSpec::get_utf8_tag(id, value)
        }
        Some(TagDataType::Binary) => TSpec::get_binary_tag(id, raw_data),
        Some(TagDataType::Float) => {
            let value = if raw_data.is_empty() {
                0.0
            } else {
                tools::arr_to_f64(raw_data)
                    .map_err(|problem| TagIteratorError::CorruptedTagData { tag_id: id, problem })?
            };
            TSpec::get_float_tag(id, value)
        }
        None => return Ok(TSpec::get_raw_tag(id, raw_data)),
    }
    .unwrap_or_else(|| {
        panic!(
            "Bad specification implementation: Tag id 0x{:x?} had an incompatible data type!",
            id
        )
    });

    Ok(tag)
}
