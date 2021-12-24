use crate::data_types::{
    EncryptedData, EncryptionKey, HostAddress, KerberosFlags, KerberosStringAsn1, KerberosTime, LastReq, Microseconds,
    PaData, PrincipalName, Realm, Ticket,
};
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag10, ExplicitContextTag11,
    ExplicitContextTag12, ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5,
    ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag8, ExplicitContextTag9, IntegerAsn1, OctetStringAsn1,
    Optional,
};
use picky_asn1_der::application_tag::ApplicationTag;
use picky_asn1_der::Asn1DerError;
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
#[derive(Debug, Serialize, PartialEq)]
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
                let kerb_message = if let Some(kerb_message) = kerb_message {
                    kerb_message
                } else {
                    return Err(A::Error::custom("kerb_message field must present in KdcProxyMessage"));
                };

                let target_domain = seq.next_element()?.unwrap_or_else(|| Optional::from(None));

                let dclocator_hint = seq.next_element()?.unwrap_or_else(|| Optional::from(None));

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
    pub fn from_raw<R: ?Sized + AsRef<[u8]>>(raw: &R) -> Result<KdcProxyMessage, Asn1DerError> {
        let mut deserializer = picky_asn1_der::Deserializer::new_from_bytes(raw.as_ref());
        KdcProxyMessage::deserialize(&mut deserializer)
    }

    pub fn from_raw_kerb_message<R: ?Sized + AsRef<[u8]>>(
        raw_kerb_message: &R,
    ) -> Result<KdcProxyMessage, Asn1DerError> {
        Ok(KdcProxyMessage {
            kerb_message: ExplicitContextTag0::from(OctetStringAsn1(raw_kerb_message.as_ref().to_vec())),
            target_domain: Optional::from(None),
            dclocator_hint: Optional::from(None),
        })
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, Asn1DerError> {
        picky_asn1_der::to_vec(self)
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
#[derive(Debug, Serialize, PartialEq)]
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
    addresses: Optional<Option<ExplicitContextTag9<Asn1SequenceOf<HostAddress>>>>,
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
                Ok(KdcReqBody {
                    kdc_options: seq
                        .next_element()?
                        .ok_or_else(|| A::Error::missing_field("kdc_options"))?,
                    cname: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    realm: seq.next_element()?.ok_or_else(|| A::Error::missing_field("reaml"))?,
                    sname: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    from: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    till: seq.next_element()?.ok_or_else(|| A::Error::missing_field("till"))?,
                    rtime: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    nonce: seq.next_element()?.ok_or_else(|| A::Error::missing_field("nonce"))?,
                    etype: seq.next_element()?.ok_or_else(|| A::Error::missing_field("etype"))?,
                    addresses: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    enc_authorization_data: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    additional_tickets: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
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
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct KdcReq {
    pvno: ExplicitContextTag1<IntegerAsn1>,
    msg_type: ExplicitContextTag2<IntegerAsn1>,
    padata: Optional<Option<ExplicitContextTag3<Asn1SequenceOf<PaData>>>>,
    req_body: ExplicitContextTag4<KdcReqBody>,
}

/// [RFC 4120 5.4.2](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// AS-REQ          ::= [APPLICATION 10] KDC-REQ
/// ```
pub type AsReq = ApplicationTag<KdcReq, 10>;

/// [RFC 4120 5.4.2](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// TGS-REQ         ::= [APPLICATION 12] KDC-REQ
/// ```
pub type TgsReq = ApplicationTag<KdcReq, 12>;

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
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct KdcRep {
    pvno: ExplicitContextTag0<IntegerAsn1>,
    msg_type: ExplicitContextTag1<IntegerAsn1>,
    padata: Optional<Option<ExplicitContextTag2<Asn1SequenceOf<PaData>>>>,
    crealm: ExplicitContextTag3<Realm>,
    cname: ExplicitContextTag4<PrincipalName>,
    ticket: ExplicitContextTag5<Ticket>,
    enc_part: ExplicitContextTag6<EncryptedData>,
}

/// [RFC 4120 5.4.2](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// AS-REP          ::= [APPLICATION 11] KDC-REP
/// ```
pub type AsRep = ApplicationTag<KdcRep, 11>;

/// [RFC 4120 5.4.2](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// TGS-REP         ::= [APPLICATION 13] KDC-REP
/// ```
pub type TgsRep = ApplicationTag<KdcRep, 13>;

/// [RFC 4120 5.9.1](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (30),
///         ctime           [2] KerberosTime OPTIONAL,
///         cusec           [3] Microseconds OPTIONAL,
///         stime           [4] KerberosTime,
///         susec           [5] Microseconds,
///         error-code      [6] Int32,
///         crealm          [7] Realm OPTIONAL,
///         cname           [8] PrincipalName OPTIONAL,
///         realm           [9] Realm -- service realm --,
///         sname           [10] PrincipalName -- service name --,
///         e-text          [11] KerberosString OPTIONAL,
///         e-data          [12] OCTET STRING OPTIONAL
/// }
/// ```
#[derive(Debug, Serialize, PartialEq)]
pub struct KrbErrorInner {
    pvno: ExplicitContextTag0<IntegerAsn1>,
    msg_type: ExplicitContextTag1<IntegerAsn1>,
    ctime: Optional<Option<ExplicitContextTag2<KerberosTime>>>,
    cusec: Optional<Option<ExplicitContextTag3<KerberosTime>>>,
    stime: ExplicitContextTag4<KerberosTime>,
    susec: ExplicitContextTag5<Microseconds>,
    error_code: ExplicitContextTag6<IntegerAsn1>,
    crealm: Optional<Option<ExplicitContextTag7<Realm>>>,
    cname: Optional<Option<ExplicitContextTag8<PrincipalName>>>,
    realm: ExplicitContextTag9<Realm>,
    sname: ExplicitContextTag10<PrincipalName>,
    e_text: Optional<Option<ExplicitContextTag11<KerberosStringAsn1>>>,
    e_data: Optional<Option<ExplicitContextTag12<OctetStringAsn1>>>,
}
pub type KrbError = ApplicationTag<KrbErrorInner, 30>;

impl<'de> de::Deserialize<'de> for KrbErrorInner {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = KrbErrorInner;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid KrbErrorInner")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                Ok(KrbErrorInner {
                    pvno: seq.next_element()?.ok_or_else(|| A::Error::missing_field("pvno"))?,
                    msg_type: seq.next_element()?.ok_or_else(|| A::Error::missing_field("msg_type"))?,
                    ctime: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    cusec: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    stime: seq.next_element()?.ok_or_else(|| A::Error::missing_field("stime"))?,
                    susec: seq.next_element()?.ok_or_else(|| A::Error::missing_field("susec"))?,
                    error_code: seq
                        .next_element()?
                        .ok_or_else(|| A::Error::missing_field("error_code"))?,
                    crealm: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    cname: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    realm: seq.next_element()?.ok_or_else(|| A::Error::missing_field("realm"))?,
                    sname: seq.next_element()?.ok_or_else(|| A::Error::missing_field("sname"))?,
                    e_text: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    e_data: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

/// [RFC 4120 5.4.2](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// EncKDCRepPart   ::= SEQUENCE {
///         key             [0] EncryptionKey,
///         last-req        [1] LastReq,
///         nonce           [2] UInt32,
///         key-expiration  [3] KerberosTime OPTIONAL,
///         flags           [4] TicketFlags,
///         authtime        [5] KerberosTime,
///         starttime       [6] KerberosTime OPTIONAL,
///         endtime         [7] KerberosTime,
///         renew-till      [8] KerberosTime OPTIONAL,
///         srealm          [9] Realm,
///         sname           [10] PrincipalName,
///         caddr           [11] HostAddresses OPTIONAL
/// }
/// ```
#[derive(Debug, Serialize, PartialEq)]
pub struct EncKdcRepPart {
    key: ExplicitContextTag0<EncryptionKey>,
    last_req: ExplicitContextTag1<LastReq>,
    nonce: ExplicitContextTag2<IntegerAsn1>,
    key_expiration: Optional<Option<ExplicitContextTag3<KerberosTime>>>,
    flags: ExplicitContextTag4<KerberosFlags>,
    auth_time: ExplicitContextTag5<KerberosTime>,
    start_time: Optional<Option<ExplicitContextTag6<KerberosTime>>>,
    end_time: ExplicitContextTag7<KerberosTime>,
    renew_till: Optional<Option<ExplicitContextTag8<KerberosTime>>>,
    srealm: ExplicitContextTag9<Realm>,
    sname: ExplicitContextTag10<PrincipalName>,
    caadr: Optional<Option<ExplicitContextTag11<HostAddress>>>,
    // this field is not specified in RFC but present in real tickets
    encrypted_pa_data: Optional<Option<ExplicitContextTag12<Asn1SequenceOf<PaData>>>>,
}

impl<'de> de::Deserialize<'de> for EncKdcRepPart {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = EncKdcRepPart;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid EncKdcRepPart")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                Ok(EncKdcRepPart {
                    key: seq.next_element()?.ok_or_else(|| A::Error::missing_field("key"))?,
                    last_req: seq.next_element()?.ok_or_else(|| A::Error::missing_field("last_req"))?,
                    nonce: seq.next_element()?.ok_or_else(|| A::Error::missing_field("nonce"))?,
                    key_expiration: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    flags: seq.next_element()?.ok_or_else(|| A::Error::missing_field("flags"))?,
                    auth_time: seq
                        .next_element()?
                        .ok_or_else(|| A::Error::missing_field("auth_time"))?,
                    start_time: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    end_time: seq.next_element()?.ok_or_else(|| A::Error::missing_field("end_time"))?,
                    renew_till: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    srealm: seq.next_element()?.ok_or_else(|| A::Error::missing_field("srealm"))?,
                    sname: seq.next_element()?.ok_or_else(|| A::Error::missing_field("sname"))?,
                    caadr: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                    encrypted_pa_data: seq.next_element()?.unwrap_or_else(|| Optional::from(None)),
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

/// [RFC 4120 5.4.2](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// EncASRepPart    ::= [APPLICATION 25] EncKDCRepPart
/// ```
pub type EncAsRepPart = ApplicationTag<EncKdcRepPart, 25>;

/// [RFC 4120 5.4.2](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// EncTGSRepPart   ::= [APPLICATION 26] EncKDCRepPart
/// ```
pub type EncTgsRepPart = ApplicationTag<EncKdcRepPart, 26>;

#[cfg(test)]
mod tests {
    use crate::data_types::{KerberosStringAsn1, KerberosTime, PaData, PrincipalName};
    use crate::messages::{AsRep, AsReq, KdcProxyMessage, KdcRep, KdcReq, KdcReqBody, KrbError, KrbErrorInner};
    use picky_asn1::bit_string::BitString;
    use picky_asn1::date::Date;
    use picky_asn1::restricted_string::IA5String;
    use picky_asn1::wrapper::{
        Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag10,
        ExplicitContextTag11, ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5,
        ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag8, ExplicitContextTag9, GeneralStringAsn1,
        GeneralizedTimeAsn1, IntegerAsn1, OctetStringAsn1, Optional,
    };

    #[test]
    fn test_kdc_proxy_message() {
        let expected_raw = [
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
        let expected = KdcProxyMessage {
            kerb_message: ExplicitContextTag0::from(OctetStringAsn1::from(vec![
                0, 0, 0, 184, 106, 129, 181, 48, 129, 178, 161, 3, 2, 1, 5, 162, 3, 2, 1, 10, 163, 26, 48, 24, 48, 10,
                161, 4, 2, 2, 0, 150, 162, 2, 4, 0, 48, 10, 161, 4, 2, 2, 0, 149, 162, 2, 4, 0, 164, 129, 137, 48, 129,
                134, 160, 7, 3, 5, 0, 0, 0, 0, 16, 161, 19, 48, 17, 160, 3, 2, 1, 1, 161, 10, 48, 8, 27, 6, 109, 121,
                117, 115, 101, 114, 162, 13, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 163, 32, 48, 30, 160,
                3, 2, 1, 2, 161, 23, 48, 21, 27, 6, 107, 114, 98, 116, 103, 116, 27, 11, 69, 88, 65, 77, 80, 76, 69,
                46, 67, 79, 77, 165, 17, 24, 15, 50, 48, 50, 49, 49, 50, 49, 54, 49, 56, 53, 53, 49, 48, 90, 167, 6, 2,
                4, 34, 51, 201, 233, 168, 26, 48, 24, 2, 1, 18, 2, 1, 17, 2, 1, 20, 2, 1, 19, 2, 1, 16, 2, 1, 23, 2, 1,
                25, 2, 1, 26,
            ])),
            target_domain: Optional::from(Some(ExplicitContextTag1::from(GeneralStringAsn1::from(
                IA5String::from_string("EXAMPLE.COM".to_owned()).unwrap(),
            )))),
            dclocator_hint: Optional::from(None),
        };

        let message: KdcProxyMessage = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let message_raw = picky_asn1_der::to_vec(&message).unwrap();

        assert_eq!(message, expected);
        assert_eq!(message_raw, expected_raw);
    }

    #[test]
    fn test_kdc_req_2() {
        let expected_raw = vec![
            48, 129, 178, 161, 3, 2, 1, 5, 162, 3, 2, 1, 10, 163, 26, 48, 24, 48, 10, 161, 4, 2, 2, 0, 150, 162, 2, 4,
            0, 48, 10, 161, 4, 2, 2, 0, 149, 162, 2, 4, 0, 164, 129, 137, 48, 129, 134, 160, 7, 3, 5, 0, 0, 0, 0, 16,
            161, 19, 48, 17, 160, 3, 2, 1, 1, 161, 10, 48, 8, 27, 6, 109, 121, 117, 115, 101, 114, 162, 13, 27, 11, 69,
            88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 163, 32, 48, 30, 160, 3, 2, 1, 2, 161, 23, 48, 21, 27, 6, 107, 114,
            98, 116, 103, 116, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 165, 17, 24, 15, 50, 48, 50, 49, 49,
            50, 50, 52, 50, 49, 49, 55, 51, 51, 90, 167, 6, 2, 4, 73, 141, 213, 43, 168, 26, 48, 24, 2, 1, 18, 2, 1,
            17, 2, 1, 20, 2, 1, 19, 2, 1, 16, 2, 1, 23, 2, 1, 25, 2, 1, 26,
        ];
        let expected = KdcReq {
            pvno: ExplicitContextTag1::from(IntegerAsn1(vec![5])),
            msg_type: ExplicitContextTag2::from(IntegerAsn1(vec![10])),
            padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf(vec![
                PaData {
                    padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![0, 150])),
                    padata_data: ExplicitContextTag2::from(OctetStringAsn1(Vec::new())),
                },
                PaData {
                    padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![0, 149])),
                    padata_data: ExplicitContextTag2::from(OctetStringAsn1(Vec::new())),
                },
            ])))),
            req_body: ExplicitContextTag4::from(KdcReqBody {
                kdc_options: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes(vec![0, 0, 0, 16]))),
                cname: Optional::from(Some(ExplicitContextTag1::from(PrincipalName {
                    name_type: ExplicitContextTag0::from(IntegerAsn1(vec![1])),
                    name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![GeneralStringAsn1::from(
                        IA5String::from_string("myuser".to_owned()).unwrap(),
                    )])),
                }))),
                realm: ExplicitContextTag2::from(GeneralStringAsn1::from(
                    IA5String::from_string("EXAMPLE.COM".to_owned()).unwrap(),
                )),
                sname: Optional::from(Some(ExplicitContextTag3::from(PrincipalName {
                    name_type: ExplicitContextTag0::from(IntegerAsn1(vec![2])),
                    name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                        KerberosStringAsn1::from(IA5String::from_string("krbtgt".to_owned()).unwrap()),
                        KerberosStringAsn1::from(IA5String::from_string("EXAMPLE.COM".to_owned()).unwrap()),
                    ])),
                }))),
                from: Optional::from(None),
                till: ExplicitContextTag5::from(KerberosTime::from(Date::new(2021, 12, 24, 21, 17, 33).unwrap())),
                rtime: Optional::from(None),
                nonce: ExplicitContextTag7::from(IntegerAsn1(vec![73, 141, 213, 43])),
                etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
                    IntegerAsn1(vec![18]),
                    IntegerAsn1(vec![17]),
                    IntegerAsn1(vec![20]),
                    IntegerAsn1(vec![19]),
                    IntegerAsn1(vec![16]),
                    IntegerAsn1(vec![23]),
                    IntegerAsn1(vec![25]),
                    IntegerAsn1(vec![26]),
                ])),
                addresses: Optional::from(None),
                enc_authorization_data: Optional::from(None),
                additional_tickets: Optional::from(None),
            }),
        };

        let kdc_req: KdcReq = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let kdc_req_raw = picky_asn1_der::to_vec(&kdc_req).unwrap();

        assert_eq!(expected, kdc_req);
        assert_eq!(expected_raw, kdc_req_raw);
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
    fn test_as_req() {
        let expected_raw = vec![
            106, 129, 181, 48, 129, 178, 161, 3, 2, 1, 5, 162, 3, 2, 1, 10, 163, 26, 48, 24, 48, 10, 161, 4, 2, 2, 0,
            150, 162, 2, 4, 0, 48, 10, 161, 4, 2, 2, 0, 149, 162, 2, 4, 0, 164, 129, 137, 48, 129, 134, 160, 7, 3, 5,
            0, 0, 0, 0, 16, 161, 19, 48, 17, 160, 3, 2, 1, 1, 161, 10, 48, 8, 27, 6, 109, 121, 117, 115, 101, 114, 162,
            13, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 163, 32, 48, 30, 160, 3, 2, 1, 2, 161, 23, 48, 21,
            27, 6, 107, 114, 98, 116, 103, 116, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 165, 17, 24, 15,
            50, 48, 50, 49, 49, 50, 50, 57, 49, 48, 51, 54, 48, 54, 90, 167, 6, 2, 4, 29, 32, 235, 11, 168, 26, 48, 24,
            2, 1, 18, 2, 1, 17, 2, 1, 20, 2, 1, 19, 2, 1, 16, 2, 1, 23, 2, 1, 25, 2, 1, 26,
        ];
        let expected = AsReq::from(KdcReq {
            pvno: ExplicitContextTag1::from(IntegerAsn1(vec![5])),
            msg_type: ExplicitContextTag2::from(IntegerAsn1(vec![10])),
            padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
                PaData {
                    padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![0, 150])),
                    padata_data: ExplicitContextTag2::from(OctetStringAsn1(Vec::new())),
                },
                PaData {
                    padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![0, 149])),
                    padata_data: ExplicitContextTag2::from(OctetStringAsn1(Vec::new())),
                },
            ])))),
            req_body: ExplicitContextTag4::from(KdcReqBody {
                kdc_options: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes(vec![0, 0, 0, 16]))),
                cname: Optional::from(Some(ExplicitContextTag1::from(PrincipalName {
                    name_type: ExplicitContextTag0::from(IntegerAsn1(vec![1])),
                    name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![GeneralStringAsn1::from(
                        IA5String::from_string("myuser".to_owned()).unwrap(),
                    )])),
                }))),
                realm: ExplicitContextTag2::from(GeneralStringAsn1::from(
                    IA5String::from_string("EXAMPLE.COM".to_owned()).unwrap(),
                )),
                sname: Optional::from(Some(ExplicitContextTag3::from(PrincipalName {
                    name_type: ExplicitContextTag0::from(IntegerAsn1(vec![2])),
                    name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                        KerberosStringAsn1::from(IA5String::from_string("krbtgt".to_owned()).unwrap()),
                        KerberosStringAsn1::from(IA5String::from_string("EXAMPLE.COM".to_owned()).unwrap()),
                    ])),
                }))),
                from: Optional::from(None),
                till: ExplicitContextTag5::from(KerberosTime::from(Date::new(2021, 12, 29, 10, 36, 6).unwrap())),
                rtime: Optional::from(None),
                nonce: ExplicitContextTag7::from(IntegerAsn1(vec![29, 32, 235, 11])),
                etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
                    IntegerAsn1(vec![18]),
                    IntegerAsn1(vec![17]),
                    IntegerAsn1(vec![20]),
                    IntegerAsn1(vec![19]),
                    IntegerAsn1(vec![16]),
                    IntegerAsn1(vec![23]),
                    IntegerAsn1(vec![25]),
                    IntegerAsn1(vec![26]),
                ])),
                addresses: Optional::from(None),
                enc_authorization_data: Optional::from(None),
                additional_tickets: Optional::from(None),
            }),
        });

        let as_req: AsReq = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let as_req_raw = picky_asn1_der::to_vec(&as_req).unwrap();

        assert_eq!(expected, as_req);
        assert_eq!(expected_raw, as_req_raw);
    }

    #[test]
    fn test_as_rep() {
        let expected_raw = vec![
            107, 130, 2, 192, 48, 130, 2, 188, 160, 3, 2, 1, 5, 161, 3, 2, 1, 11, 162, 43, 48, 41, 48, 39, 161, 3, 2,
            1, 19, 162, 32, 4, 30, 48, 28, 48, 26, 160, 3, 2, 1, 18, 161, 19, 27, 17, 69, 88, 65, 77, 80, 76, 69, 46,
            67, 79, 77, 109, 121, 117, 115, 101, 114, 163, 13, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 164,
            19, 48, 17, 160, 3, 2, 1, 1, 161, 10, 48, 8, 27, 6, 109, 121, 117, 115, 101, 114, 165, 130, 1, 64, 97, 130,
            1, 60, 48, 130, 1, 56, 160, 3, 2, 1, 5, 161, 13, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 162,
            32, 48, 30, 160, 3, 2, 1, 2, 161, 23, 48, 21, 27, 6, 107, 114, 98, 116, 103, 116, 27, 11, 69, 88, 65, 77,
            80, 76, 69, 46, 67, 79, 77, 163, 129, 255, 48, 129, 252, 160, 3, 2, 1, 18, 161, 3, 2, 1, 1, 162, 129, 239,
            4, 129, 236, 229, 108, 127, 175, 235, 22, 11, 195, 254, 62, 101, 153, 38, 64, 83, 27, 109, 35, 253, 196,
            59, 21, 69, 124, 36, 145, 117, 98, 146, 80, 179, 3, 37, 191, 32, 69, 182, 19, 45, 245, 225, 205, 40, 33,
            245, 64, 96, 250, 167, 233, 4, 72, 222, 172, 23, 0, 66, 223, 108, 229, 56, 177, 9, 85, 252, 15, 249, 242,
            189, 240, 4, 45, 235, 72, 169, 207, 81, 60, 129, 61, 66, 191, 142, 254, 11, 231, 111, 219, 21, 155, 126,
            70, 20, 99, 169, 235, 134, 171, 70, 71, 238, 136, 156, 165, 46, 170, 53, 25, 233, 107, 78, 36, 141, 183,
            78, 123, 45, 239, 14, 239, 119, 178, 115, 146, 115, 93, 240, 130, 198, 225, 13, 175, 99, 71, 193, 252, 183,
            41, 77, 109, 158, 237, 159, 185, 164, 103, 132, 248, 223, 55, 201, 44, 74, 25, 130, 188, 76, 255, 128, 199,
            71, 137, 1, 154, 144, 17, 237, 167, 157, 123, 253, 150, 129, 189, 10, 121, 148, 70, 137, 249, 133, 43, 223,
            160, 250, 202, 175, 15, 6, 199, 177, 181, 237, 224, 226, 26, 230, 123, 219, 223, 164, 249, 206, 41, 40, 32,
            190, 14, 3, 196, 163, 41, 56, 118, 157, 114, 87, 233, 89, 178, 246, 74, 224, 43, 207, 53, 131, 32, 78, 111,
            114, 246, 153, 100, 110, 7, 166, 130, 1, 25, 48, 130, 1, 21, 160, 3, 2, 1, 18, 162, 130, 1, 12, 4, 130, 1,
            8, 14, 180, 181, 83, 180, 223, 85, 143, 123, 246, 189, 59, 97, 51, 73, 198, 5, 147, 87, 42, 240, 94, 250,
            203, 240, 45, 46, 190, 32, 135, 13, 24, 123, 127, 223, 30, 53, 200, 226, 164, 80, 207, 227, 34, 63, 139, 3,
            129, 240, 10, 193, 222, 123, 0, 64, 28, 232, 140, 63, 22, 143, 211, 114, 182, 138, 233, 103, 39, 233, 158,
            119, 215, 73, 227, 197, 80, 98, 48, 60, 62, 71, 207, 233, 144, 160, 28, 203, 79, 242, 40, 197, 224, 246,
            84, 9, 184, 188, 250, 231, 190, 97, 255, 41, 234, 238, 213, 203, 3, 192, 160, 220, 78, 78, 197, 45, 255,
            176, 13, 190, 245, 35, 208, 12, 80, 93, 81, 65, 252, 199, 184, 202, 197, 95, 49, 179, 237, 64, 116, 52,
            220, 109, 123, 202, 78, 63, 146, 121, 178, 168, 157, 84, 80, 246, 250, 75, 69, 93, 184, 48, 115, 32, 139,
            4, 90, 164, 30, 208, 100, 37, 220, 168, 165, 2, 224, 124, 102, 164, 130, 34, 66, 134, 131, 16, 7, 206, 32,
            138, 30, 217, 225, 125, 69, 82, 78, 127, 73, 216, 235, 130, 159, 41, 23, 28, 197, 19, 39, 207, 144, 160,
            197, 11, 85, 39, 102, 167, 237, 83, 132, 78, 165, 215, 173, 61, 90, 113, 215, 201, 213, 158, 19, 190, 68,
            135, 94, 136, 63, 105, 119, 225, 127, 193, 148, 33, 74, 41, 154, 68, 104, 52, 227, 188, 19, 62, 26, 55, 15,
            20, 53, 221, 200, 137, 197, 2, 243,
        ];
        //ApplicationTag(KdcRep { pvno: ExplicitContextTag0(IntegerAsn1([5])), msg_type: ExplicitContextTag1(IntegerAsn1([11])), padata: Optional(Some(ExplicitContextTag2(Asn1SequenceOf([PaData { padata_type: ExplicitContextTag1(IntegerAsn1([19])), padata_data: ExplicitContextTag2(OctetStringAsn1([48, 28, 48, 26, 160, 3, 2, 1, 18, 161, 19, 27, 17, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 109, 121, 117, 115, 101, 114])) }])))), crealm: ExplicitContextTag3(GeneralStringAsn1(RestrictedString { data: [69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77], marker: PhantomData })), cname: ExplicitContextTag4(PrincipalName { name_type: ExplicitContextTag0(IntegerAsn1([1])), name_string: ExplicitContextTag1(Asn1SequenceOf([GeneralStringAsn1(RestrictedString { data: [109, 121, 117, 115, 101, 114], marker: PhantomData })])) }), ticket: ExplicitContextTag5(ApplicationTag(TicketInner { tkt_vno: ExplicitContextTag0(IntegerAsn1([5])), realm: ExplicitContextTag1(GeneralStringAsn1(RestrictedString { data: [69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77], marker: PhantomData })), sname: ExplicitContextTag2(PrincipalName { name_type: ExplicitContextTag0(IntegerAsn1([2])), name_string: ExplicitContextTag1(Asn1SequenceOf([GeneralStringAsn1(RestrictedString { data: [107, 114, 98, 116, 103, 116], marker: PhantomData }), GeneralStringAsn1(RestrictedString { data: [69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77], marker: PhantomData })])) }), enc_part: ExplicitContextTag3(EncryptedData { etype: ExplicitContextTag0(IntegerAsn1([18])), kvno: Optional(Some(ExplicitContextTag1(IntegerAsn1([1])))), cipher: ExplicitContextTag2(OctetStringAsn1([229, 108, 127, 175, 235, 22, 11, 195, 254, 62, 101, 153, 38, 64, 83, 27, 109, 35, 253, 196, 59, 21, 69, 124, 36, 145, 117, 98, 146, 80, 179, 3, 37, 191, 32, 69, 182, 19, 45, 245, 225, 205, 40, 33, 245, 64, 96, 250, 167, 233, 4, 72, 222, 172, 23, 0, 66, 223, 108, 229, 56, 177, 9, 85, 252, 15, 249, 242, 189, 240, 4, 45, 235, 72, 169, 207, 81, 60, 129, 61, 66, 191, 142, 254, 11, 231, 111, 219, 21, 155, 126, 70, 20, 99, 169, 235, 134, 171, 70, 71, 238, 136, 156, 165, 46, 170, 53, 25, 233, 107, 78, 36, 141, 183, 78, 123, 45, 239, 14, 239, 119, 178, 115, 146, 115, 93, 240, 130, 198, 225, 13, 175, 99, 71, 193, 252, 183, 41, 77, 109, 158, 237, 159, 185, 164, 103, 132, 248, 223, 55, 201, 44, 74, 25, 130, 188, 76, 255, 128, 199, 71, 137, 1, 154, 144, 17, 237, 167, 157, 123, 253, 150, 129, 189, 10, 121, 148, 70, 137, 249, 133, 43, 223, 160, 250, 202, 175, 15, 6, 199, 177, 181, 237, 224, 226, 26, 230, 123, 219, 223, 164, 249, 206, 41, 40, 32, 190, 14, 3, 196, 163, 41, 56, 118, 157, 114, 87, 233, 89, 178, 246, 74, 224, 43, 207, 53, 131, 32, 78, 111, 114, 246, 153, 100, 110, 7])) }) })), enc_part: ExplicitContextTag6(EncryptedData { etype: ExplicitContextTag0(IntegerAsn1([18])), kvno: Optional(None), cipher: ExplicitContextTag2(OctetStringAsn1([14, 180, 181, 83, 180, 223, 85, 143, 123, 246, 189, 59, 97, 51, 73, 198, 5, 147, 87, 42, 240, 94, 250, 203, 240, 45, 46, 190, 32, 135, 13, 24, 123, 127, 223, 30, 53, 200, 226, 164, 80, 207, 227, 34, 63, 139, 3, 129, 240, 10, 193, 222, 123, 0, 64, 28, 232, 140, 63, 22, 143, 211, 114, 182, 138, 233, 103, 39, 233, 158, 119, 215, 73, 227, 197, 80, 98, 48, 60, 62, 71, 207, 233, 144, 160, 28, 203, 79, 242, 40, 197, 224, 246, 84, 9, 184, 188, 250, 231, 190, 97, 255, 41, 234, 238, 213, 203, 3, 192, 160, 220, 78, 78, 197, 45, 255, 176, 13, 190, 245, 35, 208, 12, 80, 93, 81, 65, 252, 199, 184, 202, 197, 95, 49, 179, 237, 64, 116, 52, 220, 109, 123, 202, 78, 63, 146, 121, 178, 168, 157, 84, 80, 246, 250, 75, 69, 93, 184, 48, 115, 32, 139, 4, 90, 164, 30, 208, 100, 37, 220, 168, 165, 2, 224, 124, 102, 164, 130, 34, 66, 134, 131, 16, 7, 206, 32, 138, 30, 217, 225, 125, 69, 82, 78, 127, 73, 216, 235, 130, 159, 41, 23, 28, 197, 19, 39, 207, 144, 160, 197, 11, 85, 39, 102, 167, 237, 83, 132, 78, 165, 215, 173, 61, 90, 113, 215, 201, 213, 158, 19, 190, 68, 135, 94, 136, 63, 105, 119, 225, 127, 193, 148, 33, 74, 41, 154, 68, 104, 52, 227, 188, 19, 62, 26, 55, 15, 20, 53, 221, 200, 137, 197, 2, 243])) }) })

        let as_rep: AsRep = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let as_rep_raw = picky_asn1_der::to_vec(&as_rep).unwrap();

        assert_eq!(expected_raw, as_rep_raw);
    }

    #[test]
    fn test_krb_error() {
        let expected_raw = vec![
            126, 129, 151, 48, 129, 148, 160, 3, 2, 1, 5, 161, 3, 2, 1, 30, 164, 17, 24, 15, 50, 48, 50, 49, 49, 50,
            50, 56, 49, 51, 52, 48, 49, 49, 90, 165, 5, 2, 3, 12, 139, 242, 166, 3, 2, 1, 6, 167, 13, 27, 11, 69, 88,
            65, 77, 80, 76, 69, 46, 67, 79, 77, 168, 21, 48, 19, 160, 3, 2, 1, 1, 161, 12, 48, 10, 27, 8, 98, 97, 100,
            95, 117, 115, 101, 114, 169, 13, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 170, 32, 48, 30, 160,
            3, 2, 1, 2, 161, 23, 48, 21, 27, 6, 107, 114, 98, 116, 103, 116, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46,
            67, 79, 77, 171, 18, 27, 16, 67, 76, 73, 69, 78, 84, 95, 78, 79, 84, 95, 70, 79, 85, 78, 68,
        ];
        let expected = KrbError::from(KrbErrorInner {
            pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![30])),
            ctime: Optional::from(None),
            cusec: Optional::from(None),
            stime: ExplicitContextTag4::from(GeneralizedTimeAsn1::from(Date::new(2021, 12, 28, 13, 40, 11).unwrap())),
            susec: ExplicitContextTag5::from(IntegerAsn1(vec![12, 139, 242])),
            error_code: ExplicitContextTag6::from(IntegerAsn1(vec![6])),
            crealm: Optional::from(Some(ExplicitContextTag7::from(GeneralStringAsn1::from(
                IA5String::from_string("EXAMPLE.COM".to_owned()).unwrap(),
            )))),
            cname: Optional::from(Some(ExplicitContextTag8::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1(vec![1])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![GeneralStringAsn1::from(
                    IA5String::from_string("bad_user".to_owned()).unwrap(),
                )])),
            }))),
            realm: ExplicitContextTag9::from(GeneralStringAsn1::from(
                IA5String::from_string("EXAMPLE.COM".to_owned()).unwrap(),
            )),
            sname: ExplicitContextTag10::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1(vec![2])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string("krbtgt".to_owned()).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_string("EXAMPLE.COM".to_owned()).unwrap()),
                ])),
            }),
            e_text: Optional::from(Some(ExplicitContextTag11::from(GeneralStringAsn1::from(
                IA5String::from_string("CLIENT_NOT_FOUND".to_owned()).unwrap(),
            )))),
            e_data: Optional::from(None),
        });

        let krb_error: KrbError = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let krb_error_raw = picky_asn1_der::to_vec(&krb_error).unwrap();

        assert_eq!(expected, krb_error);
        assert_eq!(expected_raw, krb_error_raw);
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
            226, 9, 247, 154, 170, 151, 225, 115, 60, 143, 251, 162, 121, 123, 166, 225, 47, 244, 163, 193, 142, 110,
            30, 167, 79, 26, 144, 189, 225, 246, 144, 146, 54, 147, 23, 99, 110, 14, 52, 197, 161, 18, 253, 104, 216,
            156, 180, 185, 9, 176, 1, 17, 197, 203, 233, 220, 62, 43, 239, 66, 206, 175, 99, 181, 45, 136, 100, 218,
            61, 85, 44, 135, 75, 178, 163, 83, 237, 193, 198, 214, 48, 54, 216, 2, 114, 57, 232, 87, 13, 206, 232, 148,
            19, 71, 56, 15, 193, 117, 253, 46, 65, 130, 51, 152, 244, 138, 4, 39, 160, 69, 128, 85, 230, 89, 127, 218,
            237, 198, 220, 129, 24, 215, 165, 225, 135, 143, 150, 209, 131, 247, 96, 148, 64, 215, 71, 106, 23, 143,
            133, 250, 96, 170, 96, 85, 51, 233, 95, 207, 118, 171, 149, 218, 78, 12, 240, 153, 227, 192, 65, 250, 213,
            159, 112, 66, 137, 246, 177, 138, 133, 32, 149, 127, 195, 128, 213, 213, 32, 58, 229, 208, 38, 173, 176,
            90, 80, 146, 215, 130, 238, 52, 232, 70, 102, 169, 173, 208, 72, 29, 227, 62, 96, 228, 121, 81, 171, 193,
            208, 102, 197, 113, 147, 38, 219, 254, 62, 229, 208, 161, 10, 56, 246, 94, 216, 226, 173, 112, 158, 40,
            204, 198, 231, 187, 254, 172, 124, 173, 166, 130, 1, 25, 48, 130, 1, 21, 160, 3, 2, 1, 18, 162, 130, 1, 12,
            4, 130, 1, 8, 172, 99, 222, 84, 103, 109, 25, 54, 34, 172, 215, 90, 39, 249, 56, 208, 90, 230, 140, 201,
            206, 244, 224, 126, 242, 157, 235, 182, 235, 252, 171, 98, 175, 199, 140, 164, 134, 29, 85, 209, 178, 34,
            121, 64, 141, 8, 191, 219, 101, 232, 17, 226, 31, 78, 200, 164, 160, 113, 154, 81, 206, 170, 212, 226, 68,
            129, 86, 67, 167, 116, 154, 25, 245, 244, 167, 82, 59, 172, 129, 85, 0, 234, 76, 129, 31, 78, 212, 252, 67,
            161, 116, 16, 4, 21, 114, 112, 215, 224, 6, 99, 179, 3, 86, 81, 164, 195, 126, 184, 164, 135, 89, 56, 211,
            177, 239, 253, 151, 138, 57, 151, 244, 202, 23, 158, 16, 182, 200, 247, 94, 33, 67, 138, 35, 44, 200, 101,
            169, 89, 233, 201, 179, 250, 51, 114, 158, 125, 231, 26, 17, 104, 126, 31, 210, 248, 46, 223, 100, 240,
            109, 180, 35, 217, 17, 53, 119, 225, 155, 25, 176, 147, 132, 106, 115, 213, 126, 111, 129, 190, 196, 240,
            180, 101, 19, 184, 16, 255, 85, 68, 212, 213, 22, 110, 200, 74, 200, 165, 160, 78, 231, 211, 84, 186, 211,
            124, 237, 90, 24, 59, 43, 135, 70, 204, 208, 213, 248, 72, 187, 82, 10, 15, 15, 44, 210, 162, 3, 67, 75,
            21, 83, 131, 154, 30, 70, 173, 9, 99, 144, 69, 244, 35, 104, 151, 195, 22, 92, 43, 93, 116, 61, 33, 210,
            240, 139, 90, 180, 114, 156, 240, 2, 134, 182, 216, 237, 102,
        ];
        //KdcRep { pvno: ExplicitContextTag0(IntegerAsn1([5])), msg_type: ExplicitContextTag1(IntegerAsn1([11])), padata: Optional(Some(ExplicitContextTag2(Asn1SequenceOf([PaData { padata_type: ExplicitContextTag1(IntegerAsn1([19])), padata_data: ExplicitContextTag2(OctetStringAsn1([48, 28, 48, 26, 160, 3, 2, 1, 18, 161, 19, 27, 17, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 109, 121, 117, 115, 101, 114])) }])))), crealm: ExplicitContextTag3(GeneralStringAsn1(RestrictedString { data: [69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77], marker: PhantomData })), cname: ExplicitContextTag4(PrincipalName { name_type: ExplicitContextTag0(IntegerAsn1([1])), name_string: ExplicitContextTag1(Asn1SequenceOf([GeneralStringAsn1(RestrictedString { data: [109, 121, 117, 115, 101, 114], marker: PhantomData })])) }), ticket: ExplicitContextTag5(ApplicationTag(TicketInner { tkt_vno: ExplicitContextTag0(IntegerAsn1([5])), realm: ExplicitContextTag1(GeneralStringAsn1(RestrictedString { data: [69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77], marker: PhantomData })), sname: ExplicitContextTag2(PrincipalName { name_type: ExplicitContextTag0(IntegerAsn1([2])), name_string: ExplicitContextTag1(Asn1SequenceOf([GeneralStringAsn1(RestrictedString { data: [107, 114, 98, 116, 103, 116], marker: PhantomData }), GeneralStringAsn1(RestrictedString { data: [69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77], marker: PhantomData })])) }), enc_part: ExplicitContextTag3(EncryptedData { etype: ExplicitContextTag0(IntegerAsn1([18])), kvno: Optional(Some(ExplicitContextTag1(IntegerAsn1([1])))), cipher: ExplicitContextTag2(OctetStringAsn1([226, 9, 247, 154, 170, 151, 225, 115, 60, 143, 251, 162, 121, 123, 166, 225, 47, 244, 163, 193, 142, 110, 30, 167, 79, 26, 144, 189, 225, 246, 144, 146, 54, 147, 23, 99, 110, 14, 52, 197, 161, 18, 253, 104, 216, 156, 180, 185, 9, 176, 1, 17, 197, 203, 233, 220, 62, 43, 239, 66, 206, 175, 99, 181, 45, 136, 100, 218, 61, 85, 44, 135, 75, 178, 163, 83, 237, 193, 198, 214, 48, 54, 216, 2, 114, 57, 232, 87, 13, 206, 232, 148, 19, 71, 56, 15, 193, 117, 253, 46, 65, 130, 51, 152, 244, 138, 4, 39, 160, 69, 128, 85, 230, 89, 127, 218, 237, 198, 220, 129, 24, 215, 165, 225, 135, 143, 150, 209, 131, 247, 96, 148, 64, 215, 71, 106, 23, 143, 133, 250, 96, 170, 96, 85, 51, 233, 95, 207, 118, 171, 149, 218, 78, 12, 240, 153, 227, 192, 65, 250, 213, 159, 112, 66, 137, 246, 177, 138, 133, 32, 149, 127, 195, 128, 213, 213, 32, 58, 229, 208, 38, 173, 176, 90, 80, 146, 215, 130, 238, 52, 232, 70, 102, 169, 173, 208, 72, 29, 227, 62, 96, 228, 121, 81, 171, 193, 208, 102, 197, 113, 147, 38, 219, 254, 62, 229, 208, 161, 10, 56, 246, 94, 216, 226, 173, 112, 158, 40, 204, 198, 231, 187, 254, 172, 124, 173])) }) })), enc_part: ExplicitContextTag6(EncryptedData { etype: ExplicitContextTag0(IntegerAsn1([18])), kvno: Optional(None), cipher: ExplicitContextTag2(OctetStringAsn1([172, 99, 222, 84, 103, 109, 25, 54, 34, 172, 215, 90, 39, 249, 56, 208, 90, 230, 140, 201, 206, 244, 224, 126, 242, 157, 235, 182, 235, 252, 171, 98, 175, 199, 140, 164, 134, 29, 85, 209, 178, 34, 121, 64, 141, 8, 191, 219, 101, 232, 17, 226, 31, 78, 200, 164, 160, 113, 154, 81, 206, 170, 212, 226, 68, 129, 86, 67, 167, 116, 154, 25, 245, 244, 167, 82, 59, 172, 129, 85, 0, 234, 76, 129, 31, 78, 212, 252, 67, 161, 116, 16, 4, 21, 114, 112, 215, 224, 6, 99, 179, 3, 86, 81, 164, 195, 126, 184, 164, 135, 89, 56, 211, 177, 239, 253, 151, 138, 57, 151, 244, 202, 23, 158, 16, 182, 200, 247, 94, 33, 67, 138, 35, 44, 200, 101, 169, 89, 233, 201, 179, 250, 51, 114, 158, 125, 231, 26, 17, 104, 126, 31, 210, 248, 46, 223, 100, 240, 109, 180, 35, 217, 17, 53, 119, 225, 155, 25, 176, 147, 132, 106, 115, 213, 126, 111, 129, 190, 196, 240, 180, 101, 19, 184, 16, 255, 85, 68, 212, 213, 22, 110, 200, 74, 200, 165, 160, 78, 231, 211, 84, 186, 211, 124, 237, 90, 24, 59, 43, 135, 70, 204, 208, 213, 248, 72, 187, 82, 10, 15, 15, 44, 210, 162, 3, 67, 75, 21, 83, 131, 154, 30, 70, 173, 9, 99, 144, 69, 244, 35, 104, 151, 195, 22, 92, 43, 93, 116, 61, 33, 210, 240, 139, 90, 180, 114, 156, 240, 2, 134, 182, 216, 237, 102])) }) }

        let kdc_rep: KdcRep = picky_asn1_der::from_bytes(&expected).unwrap();
        let kdc_rep_raw = picky_asn1_der::to_vec(&kdc_rep).unwrap();

        assert_eq!(expected, kdc_rep_raw);
    }
}
