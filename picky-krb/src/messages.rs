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

