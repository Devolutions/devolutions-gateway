use crate::length::Length;
use picky_asn1::tag::Tag;
use picky_asn1_der::Asn1RawDer;
use serde::de::Error;
use serde::{de, ser, Deserializer};
use std::fmt;
use std::fmt::Debug;

pub trait ApplicationTagType {
    fn tag() -> u8;
    fn from_bytes(data: &[u8]) -> Self;
    fn to_vec(&self) -> Vec<u8>;
}

#[derive(Debug)]
pub struct ApplicationTag<T: ApplicationTagType + Debug> {
    value: T,
}

impl<T: ApplicationTagType + Debug> ApplicationTag<T> {
    pub fn new(value: T) -> Self {
        Self { value }
    }
}

fn deserialize_application_tag_inner<'a, T: ApplicationTagType + Debug>(
    data: Vec<u8>,
) -> Result<ApplicationTag<T>, String> {
    struct Visitor<V: ApplicationTagType>(Option<V>);

    impl<V: ApplicationTagType> Visitor<V> {
        pub fn new() -> Self {
            Self(None)
        }
    }

    impl<'d1, V: ApplicationTagType> de::Visitor<'d1> for Visitor<V> {
        type Value = V;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("Error")
        }

        fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, <D as de::Deserializer<'d1>>::Error>
        where
            D: de::Deserializer<'d1>,
        {
            struct TVisitor<H: ApplicationTagType>(Option<H>);

            impl<H: ApplicationTagType> TVisitor<H> {
                pub fn new() -> Self {
                    Self(None)
                }
            }

            impl<'d1, H: ApplicationTagType> de::Visitor<'d1> for TVisitor<H> {
                type Value = H;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("Error")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    self.visit_byte_buf(v.to_vec())
                }

                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    Ok(H::from_bytes(&v))
                }
            }

            deserializer.deserialize_byte_buf(TVisitor::<V>::new())
        }
    }

    let mut deserializer = picky_asn1_der::Deserializer::new_from_bytes(&data);

    Ok(ApplicationTag::new(
        deserializer
            .deserialize_newtype_struct("HeaderOnly", Visitor::<T>::new())
            .map_err(|e| format!("Error: {:?}", e))?,
    ))
}

impl<'de, T: ApplicationTagType + de::Deserialize<'de> + Debug> de::Deserialize<'de> for ApplicationTag<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        let mut data = Asn1RawDer::deserialize(deserializer)?.0;
        let tag = Tag::from(data[0]);

        if !tag.is_application() {
            return Err(<D as de::Deserializer<'de>>::Error::custom(format!(
                "Expected Application class tag but got: {:?}",
                tag.class()
            )));
        }

        if tag.number() != T::tag() {
            return Err(<D as de::Deserializer<'de>>::Error::custom(format!(
                "Expected Application number tag {} but got: {}",
                T::tag(),
                tag.number()
            )));
        }

        data[0] = 0x04; // OCTET_STRING TAG
        Ok(deserialize_application_tag_inner(data).map_err(|e| <D as de::Deserializer<'de>>::Error::custom(e))?)
    }
}

impl<T: ApplicationTagType + Debug> ser::Serialize for ApplicationTag<T> {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        let buff = self.value.to_vec();
        let mut res = vec![Tag::application_constructed(T::tag()).inner()];
        Length::serialize(buff.len(), &mut res).unwrap();
        res.extend_from_slice(&buff);
        Asn1RawDer(res).serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use crate::application_tag::ApplicationTag;
    use crate::messages::AsReq;

    #[test]
    fn test_application_tag() {
        let expected = vec![
            0x6a, 0x81, 0xb5, 0x30, 0x81, 0xb2, 0xa1, 0x03, 0x02, 0x01, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x0a, 0xa3, 0x1a,
            0x30, 0x18, 0x30, 0x0a, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x96, 0xa2, 0x02, 0x04, 0x00, 0x30, 0x0a, 0xa1, 0x04,
            0x02, 0x02, 0x00, 0x95, 0xa2, 0x02, 0x04, 0x00, 0xa4, 0x81, 0x89, 0x30, 0x81, 0x86, 0xa0, 0x07, 0x03, 0x05,
            0x00, 0x00, 0x00, 0x00, 0x10, 0xa1, 0x13, 0x30, 0x11, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x0a, 0x30, 0x08,
            0x1b, 0x06, 0x6d, 0x79, 0x75, 0x73, 0x65, 0x72, 0xa2, 0x0d, 0x1b, 0x0b, 0x45, 0x58, 0x41, 0x4d, 0x50, 0x4c,
            0x45, 0x2e, 0x43, 0x4f, 0x4d, 0xa3, 0x20, 0x30, 0x1e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x17, 0x30, 0x15,
            0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x0b, 0x45, 0x58, 0x41, 0x4d, 0x50, 0x4c, 0x45, 0x2e,
            0x43, 0x4f, 0x4d, 0xa5, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x31, 0x31, 0x32, 0x31, 0x36, 0x31, 0x38, 0x35,
            0x35, 0x31, 0x30, 0x5a, 0xa7, 0x06, 0x02, 0x04, 0x22, 0x33, 0xc9, 0xe9, 0xa8, 0x1a, 0x30, 0x18, 0x02, 0x01,
            0x12, 0x02, 0x01, 0x11, 0x02, 0x01, 0x14, 0x02, 0x01, 0x13, 0x02, 0x01, 0x10, 0x02, 0x01, 0x17, 0x02, 0x01,
            0x19, 0x02, 0x01, 0x1a,
        ];

        let app_10: ApplicationTag<AsReq> = picky_asn1_der::from_bytes(&expected).unwrap();

        let app_10_raw = picky_asn1_der::to_vec(&app_10).unwrap();

        assert_eq!(expected, app_10_raw);
    }
}
