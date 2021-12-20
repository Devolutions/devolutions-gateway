use picky_asn1::wrapper::{Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3, GeneralizedTimeAsn1, GeneralStringAsn1, IntegerAsn1, OctetStringAsn1, Optional};
use serde::{Deserialize, Serialize};
use crate::application_tag::{ApplicationTag, ApplicationTagType};

/// [RFC 4120 5.2.1](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not-rust
/// KerberosString  ::= GeneralString (IA5String)
/// ```
pub type KerberosStringAsn1 = GeneralStringAsn1;

/// [2.2.2 KDC_PROXY_MESSAGE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5778aff5-b182-4b97-a970-29c7f911eef2)
pub type Realm = KerberosStringAsn1;

/// [RFC 4120 5.2.2](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// PrincipalName   ::= SEQUENCE {
///         name-type       [0] Int32,
///         name-string     [1] SEQUENCE OF KerberosString
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct PrincipalName {
    name_type: ExplicitContextTag0<IntegerAsn1>,
    name_string: ExplicitContextTag1<Asn1SequenceOf<KerberosStringAsn1>>,
}

/// [RFC 4120 1.1](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// KerberosTime    ::= GeneralizedTime -- with no fractional seconds
/// ```
pub type KerberosTime = GeneralizedTimeAsn1;

/// [RFC 4120 5.2.5](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// HostAddress   ::= SEQUENCE {
///         addr-type       [0] Int32,
///         address         [1] OCTET STRING
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct HostAddress {
    addr_type: ExplicitContextTag0<IntegerAsn1>,
    address: ExplicitContextTag1<OctetStringAsn1>,
}

/// [RFC 4120 5.2.6](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// AuthorizationData       ::= SEQUENCE OF SEQUENCE {
///         ad-type         [0] Int32,
///         ad-data         [1] OCTET STRING
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationData {
    ad_type: ExplicitContextTag0<IntegerAsn1>,
    ad_data: ExplicitContextTag1<OctetStringAsn1>,
}

/// [RFC 4120 5.2.7](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// PA-DATA         ::= SEQUENCE {
///         padata-type     [1] Int32,
///         padata-value    [2] OCTET STRING
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct PaData {
    padata_type: ExplicitContextTag1<IntegerAsn1>,
    padata_data: ExplicitContextTag2<OctetStringAsn1>,
}

/// [RFC 4120 5.2.8](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
/// ```
pub type KerberosFlags = BitStringAsn1;

/// [RFC 4120 5.2.9](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// EncryptedData   ::= SEQUENCE {
///         etype   [0] Int32 -- EncryptionType --,
///         kvno    [1] UInt32 OPTIONAL,
///         cipher  [2] OCTET STRING -- ciphertext
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedData {
    etype: ExplicitContextTag0<IntegerAsn1>,
    kvno: Optional<Option<ExplicitContextTag1<IntegerAsn1>>>,
    cipher: ExplicitContextTag2<OctetStringAsn1>,
}

/// [RFC 4120 5.2.9](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// EncryptionKey   ::= SEQUENCE {
///         keytype         [0] Int32 -- actually encryption type --,
///         keyvalue        [1] OCTET STRING
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionKey {
    key_type: ExplicitContextTag0<IntegerAsn1>,
    key_value: ExplicitContextTag1<OctetStringAsn1>,
}

/// [RFC 4120 5.3](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// Ticket          ::= [APPLICATION 1] SEQUENCE {
///         tkt-vno         [0] INTEGER (5),
///         realm           [1] Realm,
///         sname           [2] PrincipalName,
///         enc-part        [3] EncryptedData
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct TicketInner {
    tkt_vno: ExplicitContextTag0<IntegerAsn1>,
    realm: ExplicitContextTag1<Realm>,
    sname: ExplicitContextTag2<PrincipalName>,
    enc_part: ExplicitContextTag3<EncryptedData>,
}

impl ApplicationTagType for TicketInner {
    fn tag() -> u8 {
        1
    }

    fn from_bytes(data: &[u8]) -> Self {
        picky_asn1_der::from_bytes(data).unwrap()
    }

    fn to_vec(&self) -> Vec<u8> {
        picky_asn1_der::to_vec(&self).unwrap()
    }
}

pub type Ticket = ApplicationTag<TicketInner>;

/// [RFC 4120 5.4.2](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// LastReq         ::=     SEQUENCE OF SEQUENCE {
///         lr-type         [0] Int32,
///         lr-value        [1] KerberosTime
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct LastReqInner {
    lr_type: ExplicitContextTag0<IntegerAsn1>,
    lr_value: ExplicitContextTag1<KerberosTime>,
}
pub type LastReq = Asn1SequenceOf<LastReqInner>;

#[cfg(test)]
mod tests {
    use crate::data_types::KerberosStringAsn1;

    #[test]
    fn test_general_string() {
        // EXAMPLE.COM
        let expected = [27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77];

        let s: KerberosStringAsn1 = picky_asn1_der::from_bytes(&expected).unwrap();
        let data = picky_asn1_der::to_vec(&s).unwrap();

        assert_eq!(data, expected);
    }
}
