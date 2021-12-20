use crate::application_tag::ApplicationTagType;
use crate::data_types::{
    EncryptedData, HostAddress, KerberosFlags, KerberosStringAsn1, KerberosTime, PaData, PrincipalName, Realm, Ticket,
};
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag10, ExplicitContextTag11,
    ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6,
    ExplicitContextTag7, ExplicitContextTag8, ExplicitContextTag9, IntegerAsn1, OctetStringAsn1, Optional,
};
use serde::de::Error;
use serde::{de, Deserialize, Serialize};
use std::fmt;

/// [2.2.2 KDC_PROXY_MESSAGE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5778aff5-b182-4b97-a970-29c7f911eef2)
///
/// ```not_rust
/// KDC-PROXY-MESSAGE::= SEQUENCE {
///     kerb-message           [0] OCTET STRING,
///     target-domain          [1] KERB-REALM OPTIONAL,
///     dclocator-hint         [2] INTEGER OPTIONAL
/// }
/// ```
#[derive(Debug, Serialize)]
pub struct KdcProxyMessage {
    pub kerb_message: ExplicitContextTag0<OctetStringAsn1>,
    pub target_domain: Optional<Option<ExplicitContextTag1<KerberosStringAsn1>>>,
    pub dclocator_hint: Optional<Option<ExplicitContextTag2<IntegerAsn1>>>,
}

impl<'de> de::Deserialize<'de> for KdcProxyMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = KdcProxyMessage;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid KdcProxyMessage with at least kerb_message field")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let kerb_message: Option<ExplicitContextTag0<OctetStringAsn1>> = seq.next_element()?;
                let kerb_message = if kerb_message.is_none() {
                    return Err(A::Error::custom("kerb_message field must present in KdcProxyMessage"));
                } else {
                    kerb_message.unwrap()
                };

                let target_domain = seq.next_element()?.unwrap_or(Optional::from(None));

                let dclocator_hint = seq.next_element()?.unwrap_or(Optional::from(None));

                Ok(KdcProxyMessage {
                    kerb_message,
                    target_domain,
                    dclocator_hint,
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

impl KdcProxyMessage {
    pub fn from_raw<R: ?Sized + AsRef<[u8]>>(raw: &R) -> Result<KdcProxyMessage, ()> {
        let mut de = picky_asn1_der::Deserializer::new_from_bytes(raw.as_ref());
        Ok(KdcProxyMessage::deserialize(&mut de).map_err(|_| ())?)
    }

    pub fn from_raw_kerb_message<R: ?Sized + AsRef<[u8]>>(raw_kerb_message: &R) -> Result<KdcProxyMessage, ()> {
        Ok(KdcProxyMessage {
            kerb_message: ExplicitContextTag0::from(OctetStringAsn1(raw_kerb_message.as_ref().to_vec())),
            target_domain: Optional::from(None),
            dclocator_hint: Optional::from(None),
        })
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, ()> {
        Ok(picky_asn1_der::to_vec(self).map_err(|_| ())?)
    }
}

/// [RFC 4120 5.4.1](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// KDCOptions      ::= KerberosFlags
/// KDC-REQ-BODY    ::= SEQUENCE {
///         kdc-options             [0] KDCOptions,
///         cname                   [1] PrincipalName OPTIONAL
///                                     -- Used only in AS-REQ --,
///         realm                   [2] Realm
///                                     -- Server's realm
///                                     -- Also client's in AS-REQ --,
///         sname                   [3] PrincipalName OPTIONAL,
///         from                    [4] KerberosTime OPTIONAL,
///         till                    [5] KerberosTime,
///         rtime                   [6] KerberosTime OPTIONAL,
///         nonce                   [7] UInt32,
///         etype                   [8] SEQUENCE OF Int32 -- EncryptionType
///                                     -- in preference order --,
///         addresses               [9] HostAddresses OPTIONAL,
///         enc-authorization-data  [10] EncryptedData OPTIONAL
///                                     -- AuthorizationData --,
///         additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
///                                        -- NOTE: not empty
/// }
/// ```
#[derive(Debug, Serialize)]
pub struct KdcReqBody {
    kdc_options: ExplicitContextTag0<KerberosFlags>,
    cname: Optional<Option<ExplicitContextTag1<PrincipalName>>>,
    realm: ExplicitContextTag2<Realm>,
    sname: Optional<Option<ExplicitContextTag3<PrincipalName>>>,
    from: Optional<Option<ExplicitContextTag4<KerberosTime>>>,
    till: ExplicitContextTag5<KerberosTime>,
    rtime: Optional<Option<ExplicitContextTag6<KerberosTime>>>,
    nonce: ExplicitContextTag7<IntegerAsn1>,
    etype: ExplicitContextTag8<Asn1SequenceOf<IntegerAsn1>>,
    addresses: Optional<Option<ExplicitContextTag9<HostAddress>>>,
    enc_authorization_data: Optional<Option<ExplicitContextTag10<EncryptedData>>>,
    additional_tickets: Optional<Option<ExplicitContextTag11<Asn1SequenceOf<Ticket>>>>,
}

impl<'de> de::Deserialize<'de> for KdcReqBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = KdcReqBody;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid KdcReqBody")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let err = |msg| A::Error::custom(msg);

                Ok(KdcReqBody {
                    kdc_options: seq.next_element()?.ok_or(err("kdc_options must present"))?,
                    cname: seq.next_element()?.unwrap_or(Optional::from(None)),
                    realm: seq.next_element()?.ok_or(err("reaml must present"))?,
                    sname: seq.next_element()?.unwrap_or(Optional::from(None)),
                    from: seq.next_element()?.unwrap_or(Optional::from(None)),
                    till: seq.next_element()?.ok_or(err("till must present"))?,
                    rtime: seq.next_element()?.unwrap_or(Optional::from(None)),
                    nonce: seq.next_element()?.ok_or(err("nonce must present"))?,
                    etype: seq.next_element()?.ok_or(err("etype must present"))?,
                    addresses: seq.next_element()?.unwrap_or(Optional::from(None)),
                    enc_authorization_data: seq.next_element()?.unwrap_or(Optional::from(None)),
                    additional_tickets: seq.next_element()?.unwrap_or(Optional::from(None)),
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

/// [RFC 4120 5.4.1](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// KDC-REQ         ::= SEQUENCE {
///         pvno            [1] INTEGER (5) ,
///         msg-type        [2] INTEGER,
///         padata          [3] SEQUENCE OF PA-DATA OPTIONAL,
///                             -- NOTE: not empty --,
///         req-body        [4] KDC-REQ-BODY,
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct KdcReq {
    pvno: ExplicitContextTag1<IntegerAsn1>,
    msg_type: ExplicitContextTag2<IntegerAsn1>,
    padata: Optional<ExplicitContextTag3<Asn1SequenceOf<PaData>>>,
    req_body: ExplicitContextTag4<KdcReqBody>,
}

/// [RFC 4120 5.4.2](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// AS-REQ          ::= [APPLICATION 10] KDC-REQ
/// ```
#[derive(Debug, Deserialize, Serialize)]
pub struct AsReq(KdcReq);

impl ApplicationTagType for AsReq {
    fn tag() -> u8 {
        10
    }

    fn from_bytes(data: &[u8]) -> Self {
        Self(picky_asn1_der::from_bytes(data).unwrap())
    }

    fn to_vec(&self) -> Vec<u8> {
        picky_asn1_der::to_vec(&self.0).unwrap()
    }
}

/// [RFC 4120 5.4.2](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// TGS-REQ         ::= [APPLICATION 12] KDC-REQ
/// ```
#[derive(Debug, Deserialize, Serialize)]
pub struct TgsReq(KdcReq);

impl ApplicationTagType for TgsReq {
    fn tag() -> u8 {
        12
    }

    fn from_bytes(data: &[u8]) -> Self {
        Self(picky_asn1_der::from_bytes(data).unwrap())
    }

    fn to_vec(&self) -> Vec<u8> {
        picky_asn1_der::to_vec(&self.0).unwrap()
    }
}

/// [RFC 4120 5.4.2](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// KDC-REP         ::= SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
///         padata          [2] SEQUENCE OF PA-DATA OPTIONAL
///                                 -- NOTE: not empty --,
///         crealm          [3] Realm,
///         cname           [4] PrincipalName,
///         ticket          [5] Ticket,
///         enc-part        [6] EncryptedData
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct KdcRep {
    pvno: ExplicitContextTag0<IntegerAsn1>,
    msg_type: ExplicitContextTag1<IntegerAsn1>,
    padata: Optional<Option<ExplicitContextTag2<Asn1SequenceOf<PaData>>>>,
    crealm: ExplicitContextTag3<Realm>,
    cname: ExplicitContextTag4<PrincipalName>,
    ticket: ExplicitContextTag5<Ticket>,
    enc_part: ExplicitContextTag6<EncryptedData>,
}

/// [RFC 4120 5.4.1](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// AS-REQ          ::= [APPLICATION 10] KDC-REQ
/// TGS-REQ         ::= [APPLICATION 12] KDC-REQ
/// ```
/// [RFC 4120 5.4.2](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// AS-REP          ::= [APPLICATION 11] KDC-REP
/// TGS-REP         ::= [APPLICATION 13] KDC-REP
/// ```

#[cfg(test)]
mod tests {
    use crate::messages::{KdcProxyMessage, KdcRep, KdcReq};

    #[test]
    fn test_kdc_proxy_message() {
        let expected = [
            0x30, 0x81, 0xd1, 0xa0, 0x81, 0xbf, 0x04, 0x81, 0xbc, 0x00, 0x00, 0x00, 0xb8, 0x6a, 0x81, 0xb5, 0x30, 0x81,
            0xb2, 0xa1, 0x03, 0x02, 0x01, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x0a, 0xa3, 0x1a, 0x30, 0x18, 0x30, 0x0a, 0xa1,
            0x04, 0x02, 0x02, 0x00, 0x96, 0xa2, 0x02, 0x04, 0x00, 0x30, 0x0a, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x95, 0xa2,
            0x02, 0x04, 0x00, 0xa4, 0x81, 0x89, 0x30, 0x81, 0x86, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10,
            0xa1, 0x13, 0x30, 0x11, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x0a, 0x30, 0x08, 0x1b, 0x06, 0x6d, 0x79, 0x75,
            0x73, 0x65, 0x72, 0xa2, 0x0d, 0x1b, 0x0b, 0x45, 0x58, 0x41, 0x4d, 0x50, 0x4c, 0x45, 0x2e, 0x43, 0x4f, 0x4d,
            0xa3, 0x20, 0x30, 0x1e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x17, 0x30, 0x15, 0x1b, 0x06, 0x6b, 0x72, 0x62,
            0x74, 0x67, 0x74, 0x1b, 0x0b, 0x45, 0x58, 0x41, 0x4d, 0x50, 0x4c, 0x45, 0x2e, 0x43, 0x4f, 0x4d, 0xa5, 0x11,
            0x18, 0x0f, 0x32, 0x30, 0x32, 0x31, 0x31, 0x32, 0x31, 0x36, 0x31, 0x38, 0x35, 0x35, 0x31, 0x30, 0x5a, 0xa7,
            0x06, 0x02, 0x04, 0x22, 0x33, 0xc9, 0xe9, 0xa8, 0x1a, 0x30, 0x18, 0x02, 0x01, 0x12, 0x02, 0x01, 0x11, 0x02,
            0x01, 0x14, 0x02, 0x01, 0x13, 0x02, 0x01, 0x10, 0x02, 0x01, 0x17, 0x02, 0x01, 0x19, 0x02, 0x01, 0x1a, 0xa1,
            0x0d, 0x1b, 0x0b, 0x45, 0x58, 0x41, 0x4d, 0x50, 0x4c, 0x45, 0x2e, 0x43, 0x4f, 0x4d,
        ];

        let message: KdcProxyMessage = picky_asn1_der::from_bytes(&expected).unwrap();
        let data = picky_asn1_der::to_vec(&message).unwrap();

        assert_eq!(data, expected);
    }

    #[test]
    fn test_kdc_req() {
        let expected = vec![
            0x30, 0x81, 0xb2, 0xa1, 0x03, 0x02, 0x01, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x0a, 0xa3, 0x1a, 0x30, 0x18, 0x30,
            0x0a, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x96, 0xa2, 0x02, 0x04, 0x00, 0x30, 0x0a, 0xa1, 0x04, 0x02, 0x02, 0x00,
            0x95, 0xa2, 0x02, 0x04, 0x00, 0xa4, 0x81, 0x89, 0x30, 0x81, 0x86, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x00, 0x00,
            0x00, 0x10, 0xa1, 0x13, 0x30, 0x11, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x0a, 0x30, 0x08, 0x1b, 0x06, 0x6d,
            0x79, 0x75, 0x73, 0x65, 0x72, 0xa2, 0x0d, 0x1b, 0x0b, 0x45, 0x58, 0x41, 0x4d, 0x50, 0x4c, 0x45, 0x2e, 0x43,
            0x4f, 0x4d, 0xa3, 0x20, 0x30, 0x1e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x17, 0x30, 0x15, 0x1b, 0x06, 0x6b,
            0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x0b, 0x45, 0x58, 0x41, 0x4d, 0x50, 0x4c, 0x45, 0x2e, 0x43, 0x4f, 0x4d,
            0xa5, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x31, 0x31, 0x32, 0x31, 0x36, 0x31, 0x38, 0x35, 0x35, 0x31, 0x30,
            0x5a, 0xa7, 0x06, 0x02, 0x04, 0x22, 0x33, 0xc9, 0xe9, 0xa8, 0x1a, 0x30, 0x18, 0x02, 0x01, 0x12, 0x02, 0x01,
            0x11, 0x02, 0x01, 0x14, 0x02, 0x01, 0x13, 0x02, 0x01, 0x10, 0x02, 0x01, 0x17, 0x02, 0x01, 0x19, 0x02, 0x01,
            0x1a,
        ];

        let kdc_req: KdcReq = picky_asn1_der::from_bytes(&expected).unwrap();

        let kdc_req_raw = picky_asn1_der::to_vec(&kdc_req).unwrap();

        assert_eq!(expected, kdc_req_raw);
    }

    #[test]
    fn test_kdc_rep() {
        let expected = vec![
            48, 130, 2, 188, 160, 3, 2, 1, 5, 161, 3, 2, 1, 11, 162, 43, 48, 41, 48, 39, 161, 3, 2, 1, 19, 162, 32, 4,
            30, 48, 28, 48, 26, 160, 3, 2, 1, 18, 161, 19, 27, 17, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 109,
            121, 117, 115, 101, 114, 163, 13, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 164, 19, 48, 17, 160,
            3, 2, 1, 1, 161, 10, 48, 8, 27, 6, 109, 121, 117, 115, 101, 114, 165, 130, 1, 64, 97, 130, 1, 60, 48, 130,
            1, 56, 160, 3, 2, 1, 5, 161, 13, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 162, 32, 48, 30, 160,
            3, 2, 1, 2, 161, 23, 48, 21, 27, 6, 107, 114, 98, 116, 103, 116, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46,
            67, 79, 77, 163, 129, 255, 48, 129, 252, 160, 3, 2, 1, 18, 161, 3, 2, 1, 1, 162, 129, 239, 4, 129, 236,
            166, 11, 233, 202, 198, 160, 29, 10, 87, 131, 189, 15, 170, 61, 216, 210, 116, 104, 91, 174, 27, 255, 246,
            126, 9, 92, 141, 206, 172, 100, 96, 56, 84, 172, 9, 156, 37, 4, 92, 135, 41, 130, 246, 8, 54, 42, 41, 176,
            92, 106, 237, 35, 183, 179, 141, 35, 17, 246, 38, 42, 131, 226, 151, 25, 155, 134, 251, 197, 4, 209, 223,
            122, 135, 145, 113, 169, 139, 100, 130, 4, 142, 227, 213, 137, 187, 187, 116, 173, 88, 35, 219, 206, 106,
            232, 35, 124, 199, 228, 153, 170, 194, 86, 183, 67, 40, 142, 56, 178, 201, 25, 33, 213, 76, 70, 189, 240,
            217, 22, 78, 147, 70, 0, 176, 78, 67, 33, 216, 37, 52, 200, 21, 104, 186, 190, 171, 60, 13, 250, 138, 135,
            27, 159, 235, 29, 163, 193, 2, 67, 193, 141, 29, 199, 166, 251, 18, 114, 237, 192, 174, 207, 150, 33, 219,
            215, 79, 157, 85, 132, 250, 159, 108, 151, 54, 134, 207, 119, 91, 132, 123, 47, 36, 56, 24, 110, 26, 7,
            182, 219, 17, 220, 11, 44, 181, 227, 25, 25, 244, 14, 56, 130, 82, 227, 114, 54, 167, 75, 202, 140, 245,
            136, 61, 29, 22, 247, 154, 5, 33, 161, 145, 60, 203, 132, 37, 17, 134, 162, 141, 159, 46, 146, 88, 115,
            114, 245, 76, 57, 166, 130, 1, 25, 48, 130, 1, 21, 160, 3, 2, 1, 18, 162, 130, 1, 12, 4, 130, 1, 8, 198,
            68, 255, 54, 137, 75, 224, 202, 101, 33, 67, 17, 110, 98, 71, 39, 211, 155, 248, 29, 67, 235, 64, 135, 38,
            247, 252, 121, 38, 244, 112, 7, 92, 223, 58, 122, 21, 75, 1, 183, 126, 177, 187, 35, 220, 164, 120, 191,
            136, 112, 166, 111, 34, 115, 221, 212, 207, 236, 145, 74, 218, 228, 6, 251, 150, 88, 5, 199, 157, 87, 69,
            191, 129, 114, 240, 96, 216, 115, 34, 43, 124, 147, 144, 154, 148, 221, 49, 107, 4, 38, 242, 48, 80, 144,
            188, 74, 23, 0, 113, 223, 172, 60, 185, 84, 71, 18, 174, 116, 47, 53, 194, 8, 111, 184, 62, 178, 21, 231,
            245, 102, 113, 15, 224, 32, 92, 108, 177, 22, 114, 31, 14, 147, 34, 77, 69, 90, 30, 77, 83, 75, 223, 245,
            140, 148, 243, 39, 224, 51, 228, 101, 36, 221, 5, 255, 184, 46, 254, 218, 229, 175, 41, 207, 229, 107, 247,
            160, 6, 83, 91, 1, 77, 195, 201, 148, 27, 184, 197, 93, 255, 58, 101, 70, 225, 253, 247, 20, 247, 1, 31,
            209, 47, 198, 35, 201, 28, 24, 188, 189, 177, 198, 141, 65, 249, 178, 224, 27, 79, 183, 238, 206, 181, 94,
            0, 116, 114, 244, 155, 83, 88, 3, 10, 223, 2, 215, 133, 201, 99, 136, 211, 56, 105, 144, 140, 196, 232,
            216, 54, 173, 195, 10, 92, 161, 233, 13, 170, 136, 25, 162, 203, 75, 83, 149, 180, 47, 66, 147, 10, 206,
            211, 146, 253, 18, 212, 17,
        ];

        let kdc_rep: KdcRep = picky_asn1_der::from_bytes(&expected).unwrap();

        let kdc_rep_raw = picky_asn1_der::to_vec(&kdc_rep).unwrap();
        println!("{:?}", kdc_rep_raw);

        assert_eq!(expected, kdc_rep_raw);
    }
}
