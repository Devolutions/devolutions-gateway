use super::{EbmlSpecification, EbmlTag, Master, PathPart, TagDataType};

///
/// An empty specification for use with examples or testing.
///
/// This struct isn't intended for production use and should only be used for examples or PoCs. Use at your own risk - may change in the future without warning.
///
/// # NOT SUITABLE FOR PRODUCTION
///
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct EmptySpec {
    id: u64,
    children: Option<Master<EmptySpec>>,
    data: Option<Vec<u8>>,
}

impl EmptySpec {
    pub fn with_children(id: u64, children: Vec<EmptySpec>) -> Self {
        EmptySpec::get_master_tag(id, Master::Full(children)).unwrap()
    }

    pub fn with_data(id: u64, data: &[u8]) -> Self {
        EmptySpec::get_binary_tag(id, data).unwrap()
    }
}

impl EbmlSpecification<EmptySpec> for EmptySpec {
    fn get_tag_data_type(_id: u64) -> Option<TagDataType> {
        Some(TagDataType::Binary)
    }

    fn get_path_by_id(_id: u64) -> &'static [PathPart] {
        &[]
    }

    fn get_unsigned_int_tag(_id: u64, _data: u64) -> Option<EmptySpec> {
        None
    }

    fn get_signed_int_tag(_id: u64, _data: i64) -> Option<EmptySpec> {
        None
    }

    fn get_utf8_tag(_id: u64, _data: String) -> Option<EmptySpec> {
        None
    }

    fn get_binary_tag(id: u64, data: &[u8]) -> Option<EmptySpec> {
        Some(EmptySpec {
            id,
            children: None,
            data: Some(data.to_vec()),
        })
    }

    fn get_float_tag(_id: u64, _data: f64) -> Option<EmptySpec> {
        None
    }

    fn get_master_tag(id: u64, data: Master<EmptySpec>) -> Option<EmptySpec> {
        Some(EmptySpec {
            id,
            children: Some(data),
            data: None,
        })
    }

    fn get_raw_tag(id: u64, data: &[u8]) -> EmptySpec {
        EmptySpec::get_binary_tag(id, data).expect("get binary tag for EmptySpec should always return Some")
    }
}

impl EbmlTag<EmptySpec> for EmptySpec {
    fn get_id(&self) -> u64 {
        self.id
    }

    fn as_unsigned_int(&self) -> Option<&u64> {
        None
    }

    fn as_signed_int(&self) -> Option<&i64> {
        None
    }

    fn as_utf8(&self) -> Option<&str> {
        None
    }

    fn as_binary(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    fn as_float(&self) -> Option<&f64> {
        None
    }

    fn as_master(&self) -> Option<&Master<EmptySpec>> {
        match &self.children {
            Some(children) => Some(children),
            None => None,
        }
    }
}
