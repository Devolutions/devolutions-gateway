// use ebml_iterable_specification_derive::easy_ebml;
// easy_ebml!(
//     pub enum TestSpec {
//         Root             : Master = 0x81,
//         Root/Int         : UnsignedInt = 0x4101,
//         Root/String      : Utf8 = 0x4102,
//         Root/Parent      : Master = 0x4103,
//         Root/Parent/Child: UnsignedInt = 0x210301,

//         Ebml                             : Master = 0x1a45dfa3,
//         Segment                          : Master = 0x18538067,
//         Segment/TrackType                : UnsignedInt = 0x83,
//         Segment/Cluster                  : Master = 0x1F43B675,
//         Segment/Cluster/CueRefCluster    : UnsignedInt = 0x97,
//         Segment/Cluster/Count            : UnsignedInt = 0x4100,
//         Segment/Cluster/Block            : Binary = 0xa1,
//         Segment/Cluster/SimpleBlock      : Binary = 0xa3,
//     }
// )

use ebml_iterable::specs::TagDataType;

#[derive(Clone, Debug, PartialEq)]
// Recursive expansion of ebml_specification! macro
// =================================================

pub enum TestSpec {
    Root(ebml_iterable::specs::Master<TestSpec>),
    Int(u64),
    String(String),
    Parent(ebml_iterable::specs::Master<TestSpec>),
    Child(u64),
    Ebml(ebml_iterable::specs::Master<TestSpec>),
    Segment(ebml_iterable::specs::Master<TestSpec>),
    TrackType(u64),
    Cluster(ebml_iterable::specs::Master<TestSpec>),
    CueRefCluster(u64),
    Count(u64),
    Block(::std::vec::Vec<u8>),
    SimpleBlock(::std::vec::Vec<u8>),
    Crc32(::std::vec::Vec<u8>),
    Void(::std::vec::Vec<u8>),
    RawTag(u64, ::std::vec::Vec<u8>),
}
impl ebml_iterable::specs::EbmlSpecification<TestSpec> for TestSpec {
    fn get_tag_data_type(id: u64) -> Option<ebml_iterable::specs::TagDataType> {
        match id {
            129u64 => Some(TagDataType::Master),
            16641u64 => Some(TagDataType::UnsignedInt),
            16642u64 => Some(TagDataType::Utf8),
            16643u64 => Some(TagDataType::Master),
            2163457u64 => Some(TagDataType::UnsignedInt),
            440786851u64 => Some(TagDataType::Master),
            408125543u64 => Some(TagDataType::Master),
            131u64 => Some(TagDataType::UnsignedInt),
            524531317u64 => Some(TagDataType::Master),
            151u64 => Some(TagDataType::UnsignedInt),
            16640u64 => Some(TagDataType::UnsignedInt),
            161u64 => Some(TagDataType::Binary),
            163u64 => Some(TagDataType::Binary),
            191u64 => Some(ebml_iterable::specs::TagDataType::Binary),
            236u64 => Some(ebml_iterable::specs::TagDataType::Binary),
            _ => None,
        }
    }
    fn get_path_by_id(id: u64) -> &'static [ebml_iterable::specs::PathPart] {
        match id {
            16641u64 => &[ebml_iterable::specs::PathPart::Id(129u64)],
            16642u64 => &[ebml_iterable::specs::PathPart::Id(129u64)],
            16643u64 => &[ebml_iterable::specs::PathPart::Id(129u64)],
            2163457u64 => &[
                ebml_iterable::specs::PathPart::Id(129u64),
                ebml_iterable::specs::PathPart::Id(16643u64),
            ],
            131u64 => &[ebml_iterable::specs::PathPart::Id(408125543u64)],
            524531317u64 => &[ebml_iterable::specs::PathPart::Id(408125543u64)],
            151u64 => &[
                ebml_iterable::specs::PathPart::Id(408125543u64),
                ebml_iterable::specs::PathPart::Id(524531317u64),
            ],
            16640u64 => &[
                ebml_iterable::specs::PathPart::Id(408125543u64),
                ebml_iterable::specs::PathPart::Id(524531317u64),
            ],
            161u64 => &[
                ebml_iterable::specs::PathPart::Id(408125543u64),
                ebml_iterable::specs::PathPart::Id(524531317u64),
            ],
            163u64 => &[
                ebml_iterable::specs::PathPart::Id(408125543u64),
                ebml_iterable::specs::PathPart::Id(524531317u64),
            ],
            191u64 => &[ebml_iterable::specs::PathPart::Global((Some(1u64), None))],
            236u64 => &[ebml_iterable::specs::PathPart::Global((None, None))],
            _ => &[],
        }
    }
    fn get_unsigned_int_tag(id: u64, data: u64) -> Option<TestSpec> {
        match id {
            16641u64 => Some(TestSpec::Int(data)),
            2163457u64 => Some(TestSpec::Child(data)),
            131u64 => Some(TestSpec::TrackType(data)),
            151u64 => Some(TestSpec::CueRefCluster(data)),
            16640u64 => Some(TestSpec::Count(data)),
            _ => None,
        }
    }
    fn get_signed_int_tag(id: u64, _data: i64) -> Option<TestSpec> {
        match id {
            _ => None,
        }
    }
    fn get_utf8_tag(id: u64, data: String) -> Option<TestSpec> {
        match id {
            16642u64 => Some(TestSpec::String(data)),
            _ => None,
        }
    }
    fn get_binary_tag(id: u64, data: &[u8]) -> Option<TestSpec> {
        match id {
            161u64 => Some(TestSpec::Block(data.to_vec())),
            163u64 => Some(TestSpec::SimpleBlock(data.to_vec())),
            191u64 => Some(TestSpec::Crc32(data.to_vec())),
            236u64 => Some(TestSpec::Void(data.to_vec())),
            _ => None,
        }
    }
    fn get_float_tag(id: u64, _data: f64) -> Option<TestSpec> {
        match id {
            _ => None,
        }
    }
    fn get_master_tag(id: u64, data: ebml_iterable::specs::Master<TestSpec>) -> Option<TestSpec> {
        match id {
            129u64 => Some(TestSpec::Root(data)),
            16643u64 => Some(TestSpec::Parent(data)),
            440786851u64 => Some(TestSpec::Ebml(data)),
            408125543u64 => Some(TestSpec::Segment(data)),
            524531317u64 => Some(TestSpec::Cluster(data)),
            _ => None,
        }
    }
    fn get_raw_tag(id: u64, data: &[u8]) -> TestSpec {
        TestSpec::RawTag(id, data.to_vec())
    }
}
impl ebml_iterable::specs::EbmlTag<TestSpec> for TestSpec {
    fn get_id(&self) -> u64 {
        match self {
            TestSpec::Root(_) => 129u64,
            TestSpec::Int(_) => 16641u64,
            TestSpec::String(_) => 16642u64,
            TestSpec::Parent(_) => 16643u64,
            TestSpec::Child(_) => 2163457u64,
            TestSpec::Ebml(_) => 440786851u64,
            TestSpec::Segment(_) => 408125543u64,
            TestSpec::TrackType(_) => 131u64,
            TestSpec::Cluster(_) => 524531317u64,
            TestSpec::CueRefCluster(_) => 151u64,
            TestSpec::Count(_) => 16640u64,
            TestSpec::Block(_) => 161u64,
            TestSpec::SimpleBlock(_) => 163u64,
            TestSpec::Crc32(_) => 191u64,
            TestSpec::Void(_) => 236u64,
            TestSpec::RawTag(id, _data) => *id,
        }
    }
    fn as_unsigned_int(&self) -> Option<&u64> {
        match self {
            TestSpec::Int(val) => Some(val),
            TestSpec::Child(val) => Some(val),
            TestSpec::TrackType(val) => Some(val),
            TestSpec::CueRefCluster(val) => Some(val),
            TestSpec::Count(val) => Some(val),
            _ => None,
        }
    }
    fn as_signed_int(&self) -> Option<&i64> {
        match self {
            _ => None,
        }
    }
    fn as_utf8(&self) -> Option<&str> {
        match self {
            TestSpec::String(val) => Some(val),
            _ => None,
        }
    }
    fn as_binary(&self) -> Option<&[u8]> {
        match self {
            TestSpec::Block(val) => Some(val),
            TestSpec::SimpleBlock(val) => Some(val),
            TestSpec::Crc32(val) => Some(val),
            TestSpec::Void(val) => Some(val),
            TestSpec::RawTag(_id, data) => Some(data),
            _ => None,
        }
    }
    fn as_float(&self) -> Option<&f64> {
        match self {
            _ => None,
        }
    }
    fn as_master(&self) -> Option<&ebml_iterable::specs::Master<TestSpec>> {
        match self {
            TestSpec::Root(val) => Some(val),
            TestSpec::Parent(val) => Some(val),
            TestSpec::Ebml(val) => Some(val),
            TestSpec::Segment(val) => Some(val),
            TestSpec::Cluster(val) => Some(val),
            _ => None,
        }
    }
}
