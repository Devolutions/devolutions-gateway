use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    GeneralStringAsn1, GeneralizedTimeAsn1, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::application_tag::ApplicationTag;
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PrincipalName {
    pub(crate) name_type: ExplicitContextTag0<IntegerAsn1>,
    pub(crate) name_string: ExplicitContextTag1<Asn1SequenceOf<KerberosStringAsn1>>,
}

/// [RFC 4120 5.2.3](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// KerberosTime    ::= GeneralizedTime -- with no fractional seconds
/// ```
pub type KerberosTime = GeneralizedTimeAsn1;

/// [RFC 4120 5.2.4](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// Microseconds    ::= INTEGER (0..999999)
/// ```
pub type Microseconds = IntegerAsn1;

/// [RFC 4120 5.2.5](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// HostAddress   ::= SEQUENCE {
///         addr-type       [0] Int32,
///         address         [1] OCTET STRING
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq)]
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
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationDataInner {
    ad_type: ExplicitContextTag0<IntegerAsn1>,
    ad_data: ExplicitContextTag1<OctetStringAsn1>,
}

pub type AuthorizationData = Asn1SequenceOf<AuthorizationDataInner>;

/// [RFC 4120 5.2.7](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// PA-DATA         ::= SEQUENCE {
///         padata-type     [1] Int32,
///         padata-value    [2] OCTET STRING
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PaData {
    pub(crate) padata_type: ExplicitContextTag1<IntegerAsn1>,
    pub(crate) padata_data: ExplicitContextTag2<OctetStringAsn1>,
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
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct EncryptedData {
    pub(crate) etype: ExplicitContextTag0<IntegerAsn1>,
    pub(crate) kvno: Optional<Option<ExplicitContextTag1<IntegerAsn1>>>,
    pub(crate) cipher: ExplicitContextTag2<OctetStringAsn1>,
}

/// [RFC 4120 5.2.9](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// EncryptionKey   ::= SEQUENCE {
///         keytype         [0] Int32 -- actually encryption type --,
///         keyvalue        [1] OCTET STRING
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq)]
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
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TicketInner {
    pub(crate) tkt_vno: ExplicitContextTag0<IntegerAsn1>,
    pub(crate) realm: ExplicitContextTag1<Realm>,
    pub(crate) sname: ExplicitContextTag2<PrincipalName>,
    pub(crate) enc_part: ExplicitContextTag3<EncryptedData>,
}

pub type Ticket = ApplicationTag<TicketInner, 1>;

/// [RFC 4120 5.4.2](https://www.rfc-editor.org/rfc/rfc4120.txt)
///
/// ```not_rust
/// LastReq         ::=     SEQUENCE OF SEQUENCE {
///         lr-type         [0] Int32,
///         lr-value        [1] KerberosTime
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct LastReqInner {
    lr_type: ExplicitContextTag0<IntegerAsn1>,
    lr_value: ExplicitContextTag1<KerberosTime>,
}
pub type LastReq = Asn1SequenceOf<LastReqInner>;

#[cfg(test)]
mod tests {
    use crate::data_types::{
        EncryptedData, EncryptionKey, HostAddress, KerberosStringAsn1, KerberosTime, LastReqInner, PaData,
        PrincipalName,
    };
    use picky_asn1::date::Date;
    use picky_asn1::restricted_string::IA5String;
    use picky_asn1::wrapper::{
        Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, GeneralStringAsn1, IntegerAsn1,
        OctetStringAsn1, Optional,
    };

    #[test]
    fn test_kerberos_string() {
        // EXAMPLE.COM
        let expected = [27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77];

        let s: KerberosStringAsn1 = picky_asn1_der::from_bytes(&expected).unwrap();
        let data = picky_asn1_der::to_vec(&s).unwrap();

        assert_eq!(data, expected);
    }

    #[test]
    fn test_pa_data() {
        let expected_raw = [
            48, 39, 161, 3, 2, 1, 19, 162, 32, 4, 30, 48, 28, 48, 26, 160, 3, 2, 1, 18, 161, 19, 27, 17, 69, 88, 65,
            77, 80, 76, 69, 46, 67, 79, 77, 109, 121, 117, 115, 101, 114,
        ];
        let expected = PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![19])),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(vec![
                48, 28, 48, 26, 160, 3, 2, 1, 18, 161, 19, 27, 17, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 109,
                121, 117, 115, 101, 114,
            ])),
        };

        let pa_data: PaData = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let pa_data_raw = picky_asn1_der::to_vec(&pa_data).unwrap();

        assert_eq!(pa_data, expected);
        assert_eq!(pa_data_raw, expected_raw);
    }

    #[test]
    fn test_simple_principal_name() {
        let expected_raw = [
            48, 17, 160, 3, 2, 1, 1, 161, 10, 48, 8, 27, 6, 109, 121, 117, 115, 101, 114,
        ];
        let expected = PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1(vec![1])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![GeneralStringAsn1::from(
                IA5String::from_string("myuser".to_owned()).unwrap(),
            )])),
        };

        let principal_name: PrincipalName = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let principal_name_raw = picky_asn1_der::to_vec(&principal_name).unwrap();

        assert_eq!(principal_name, expected);
        assert_eq!(principal_name_raw, expected_raw);
    }

    #[test]
    fn test_principal_name_with_two_names() {
        let expected_raw = [
            48, 30, 160, 3, 2, 1, 2, 161, 23, 48, 21, 27, 6, 107, 114, 98, 116, 103, 116, 27, 11, 69, 88, 65, 77, 80,
            76, 69, 46, 67, 79, 77,
        ];
        let expected = PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1(vec![2])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                GeneralStringAsn1::from(IA5String::from_string("krbtgt".to_owned()).unwrap()),
                GeneralStringAsn1::from(IA5String::from_string("EXAMPLE.COM".to_owned()).unwrap()),
            ])),
        };

        let principal_name: PrincipalName = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let principal_name_raw = picky_asn1_der::to_vec(&principal_name).unwrap();

        assert_eq!(principal_name, expected);
        assert_eq!(principal_name_raw, expected_raw);
    }

    #[test]
    fn test_encrypted_data() {
        let expected_raw = [
            48, 129, 252, 160, 3, 2, 1, 18, 161, 3, 2, 1, 1, 162, 129, 239, 4, 129, 236, 166, 11, 233, 202, 198, 160,
            29, 10, 87, 131, 189, 15, 170, 61, 216, 210, 116, 104, 91, 174, 27, 255, 246, 126, 9, 92, 141, 206, 172,
            100, 96, 56, 84, 172, 9, 156, 37, 4, 92, 135, 41, 130, 246, 8, 54, 42, 41, 176, 92, 106, 237, 35, 183, 179,
            141, 35, 17, 246, 38, 42, 131, 226, 151, 25, 155, 134, 251, 197, 4, 209, 223, 122, 135, 145, 113, 169, 139,
            100, 130, 4, 142, 227, 213, 137, 187, 187, 116, 173, 88, 35, 219, 206, 106, 232, 35, 124, 199, 228, 153,
            170, 194, 86, 183, 67, 40, 142, 56, 178, 201, 25, 33, 213, 76, 70, 189, 240, 217, 22, 78, 147, 70, 0, 176,
            78, 67, 33, 216, 37, 52, 200, 21, 104, 186, 190, 171, 60, 13, 250, 138, 135, 27, 159, 235, 29, 163, 193, 2,
            67, 193, 141, 29, 199, 166, 251, 18, 114, 237, 192, 174, 207, 150, 33, 219, 215, 79, 157, 85, 132, 250,
            159, 108, 151, 54, 134, 207, 119, 91, 132, 123, 47, 36, 56, 24, 110, 26, 7, 182, 219, 17, 220, 11, 44, 181,
            227, 25, 25, 244, 14, 56, 130, 82, 227, 114, 54, 167, 75, 202, 140, 245, 136, 61, 29, 22, 247, 154, 5, 33,
            161, 145, 60, 203, 132, 37, 17, 134, 162, 141, 159, 46, 146, 88, 115, 114, 245, 76, 57,
        ];
        let expected = EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1(vec![18])),
            kvno: Optional::from(Option::Some(ExplicitContextTag1::from(IntegerAsn1(vec![1])))),
            cipher: ExplicitContextTag2::from(OctetStringAsn1(vec![
                166, 11, 233, 202, 198, 160, 29, 10, 87, 131, 189, 15, 170, 61, 216, 210, 116, 104, 91, 174, 27, 255,
                246, 126, 9, 92, 141, 206, 172, 100, 96, 56, 84, 172, 9, 156, 37, 4, 92, 135, 41, 130, 246, 8, 54, 42,
                41, 176, 92, 106, 237, 35, 183, 179, 141, 35, 17, 246, 38, 42, 131, 226, 151, 25, 155, 134, 251, 197,
                4, 209, 223, 122, 135, 145, 113, 169, 139, 100, 130, 4, 142, 227, 213, 137, 187, 187, 116, 173, 88, 35,
                219, 206, 106, 232, 35, 124, 199, 228, 153, 170, 194, 86, 183, 67, 40, 142, 56, 178, 201, 25, 33, 213,
                76, 70, 189, 240, 217, 22, 78, 147, 70, 0, 176, 78, 67, 33, 216, 37, 52, 200, 21, 104, 186, 190, 171,
                60, 13, 250, 138, 135, 27, 159, 235, 29, 163, 193, 2, 67, 193, 141, 29, 199, 166, 251, 18, 114, 237,
                192, 174, 207, 150, 33, 219, 215, 79, 157, 85, 132, 250, 159, 108, 151, 54, 134, 207, 119, 91, 132,
                123, 47, 36, 56, 24, 110, 26, 7, 182, 219, 17, 220, 11, 44, 181, 227, 25, 25, 244, 14, 56, 130, 82,
                227, 114, 54, 167, 75, 202, 140, 245, 136, 61, 29, 22, 247, 154, 5, 33, 161, 145, 60, 203, 132, 37, 17,
                134, 162, 141, 159, 46, 146, 88, 115, 114, 245, 76, 57,
            ])),
        };

        let encrypted_data: EncryptedData = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let encrypted_data_raw = picky_asn1_der::to_vec(&encrypted_data).unwrap();

        assert_eq!(encrypted_data, expected);
        assert_eq!(encrypted_data_raw, expected_raw);
    }

    #[test]
    fn test_encrypted_data_without_kvno() {
        let expected_raw = [
            48, 130, 1, 21, 160, 3, 2, 1, 18, 162, 130, 1, 12, 4, 130, 1, 8, 198, 68, 255, 54, 137, 75, 224, 202, 101,
            33, 67, 17, 110, 98, 71, 39, 211, 155, 248, 29, 67, 235, 64, 135, 38, 247, 252, 121, 38, 244, 112, 7, 92,
            223, 58, 122, 21, 75, 1, 183, 126, 177, 187, 35, 220, 164, 120, 191, 136, 112, 166, 111, 34, 115, 221, 212,
            207, 236, 145, 74, 218, 228, 6, 251, 150, 88, 5, 199, 157, 87, 69, 191, 129, 114, 240, 96, 216, 115, 34,
            43, 124, 147, 144, 154, 148, 221, 49, 107, 4, 38, 242, 48, 80, 144, 188, 74, 23, 0, 113, 223, 172, 60, 185,
            84, 71, 18, 174, 116, 47, 53, 194, 8, 111, 184, 62, 178, 21, 231, 245, 102, 113, 15, 224, 32, 92, 108, 177,
            22, 114, 31, 14, 147, 34, 77, 69, 90, 30, 77, 83, 75, 223, 245, 140, 148, 243, 39, 224, 51, 228, 101, 36,
            221, 5, 255, 184, 46, 254, 218, 229, 175, 41, 207, 229, 107, 247, 160, 6, 83, 91, 1, 77, 195, 201, 148, 27,
            184, 197, 93, 255, 58, 101, 70, 225, 253, 247, 20, 247, 1, 31, 209, 47, 198, 35, 201, 28, 24, 188, 189,
            177, 198, 141, 65, 249, 178, 224, 27, 79, 183, 238, 206, 181, 94, 0, 116, 114, 244, 155, 83, 88, 3, 10,
            223, 2, 215, 133, 201, 99, 136, 211, 56, 105, 144, 140, 196, 232, 216, 54, 173, 195, 10, 92, 161, 233, 13,
            170, 136, 25, 162, 203, 75, 83, 149, 180, 47, 66, 147, 10, 206, 211, 146, 253, 18, 212, 17,
        ];
        let expected = EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1(vec![18])),
            kvno: Optional::from(Option::None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1(vec![
                198, 68, 255, 54, 137, 75, 224, 202, 101, 33, 67, 17, 110, 98, 71, 39, 211, 155, 248, 29, 67, 235, 64,
                135, 38, 247, 252, 121, 38, 244, 112, 7, 92, 223, 58, 122, 21, 75, 1, 183, 126, 177, 187, 35, 220, 164,
                120, 191, 136, 112, 166, 111, 34, 115, 221, 212, 207, 236, 145, 74, 218, 228, 6, 251, 150, 88, 5, 199,
                157, 87, 69, 191, 129, 114, 240, 96, 216, 115, 34, 43, 124, 147, 144, 154, 148, 221, 49, 107, 4, 38,
                242, 48, 80, 144, 188, 74, 23, 0, 113, 223, 172, 60, 185, 84, 71, 18, 174, 116, 47, 53, 194, 8, 111,
                184, 62, 178, 21, 231, 245, 102, 113, 15, 224, 32, 92, 108, 177, 22, 114, 31, 14, 147, 34, 77, 69, 90,
                30, 77, 83, 75, 223, 245, 140, 148, 243, 39, 224, 51, 228, 101, 36, 221, 5, 255, 184, 46, 254, 218,
                229, 175, 41, 207, 229, 107, 247, 160, 6, 83, 91, 1, 77, 195, 201, 148, 27, 184, 197, 93, 255, 58, 101,
                70, 225, 253, 247, 20, 247, 1, 31, 209, 47, 198, 35, 201, 28, 24, 188, 189, 177, 198, 141, 65, 249,
                178, 224, 27, 79, 183, 238, 206, 181, 94, 0, 116, 114, 244, 155, 83, 88, 3, 10, 223, 2, 215, 133, 201,
                99, 136, 211, 56, 105, 144, 140, 196, 232, 216, 54, 173, 195, 10, 92, 161, 233, 13, 170, 136, 25, 162,
                203, 75, 83, 149, 180, 47, 66, 147, 10, 206, 211, 146, 253, 18, 212, 17,
            ])),
        };

        let encrypted_data: EncryptedData = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let encrypted_data_raw = picky_asn1_der::to_vec(&encrypted_data).unwrap();

        assert_eq!(encrypted_data, expected);
        assert_eq!(encrypted_data_raw, expected_raw);
    }

    #[test]
    fn test_host_address() {
        let expected_raw = [
            0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x14, 0xa1, 0x12, 0x04, 0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x42,
            0x41, 0x53, 0x54, 0x49, 0x4f, 0x4e, 0x20, 0x20, 0x20,
        ];
        let expected = HostAddress {
            addr_type: ExplicitContextTag0::from(IntegerAsn1(vec![20])),
            address: ExplicitContextTag1::from(OctetStringAsn1(vec![
                72, 79, 76, 76, 79, 87, 66, 65, 83, 84, 73, 79, 78, 32, 32, 32,
            ])),
        };

        let host_address: HostAddress = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let host_address_raw = picky_asn1_der::to_vec(&host_address).unwrap();

        assert_eq!(host_address, expected);
        assert_eq!(host_address_raw, expected_raw);
    }

    #[test]
    fn test_encryption_key() {
        let expected_raw = [
            48, 41, 160, 3, 2, 1, 18, 161, 34, 4, 32, 23, 138, 210, 243, 7, 121, 117, 180, 99, 86, 230, 62, 222, 63,
            251, 46, 242, 161, 37, 67, 254, 103, 199, 93, 74, 174, 166, 64, 17, 198, 242, 144,
        ];
        let expected = EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1(vec![18])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1(vec![
                23, 138, 210, 243, 7, 121, 117, 180, 99, 86, 230, 62, 222, 63, 251, 46, 242, 161, 37, 67, 254, 103,
                199, 93, 74, 174, 166, 64, 17, 198, 242, 144,
            ])),
        };

        let encryption_key: EncryptionKey = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let encryption_key_raw = picky_asn1_der::to_vec(&encryption_key).unwrap();

        assert_eq!(encryption_key, expected);
        assert_eq!(encryption_key_raw, expected_raw);
    }

    #[test]
    fn test_last_req_inner() {
        let expected_raw = [
            48, 24, 160, 3, 2, 1, 0, 161, 17, 24, 15, 49, 57, 55, 48, 48, 49, 48, 49, 48, 48, 48, 48, 48, 48, 90,
        ];
        let expected = LastReqInner {
            lr_type: ExplicitContextTag0::from(IntegerAsn1(vec![0])),
            lr_value: ExplicitContextTag1::from(KerberosTime::from(Date::new(1970, 1, 1, 0, 0, 0).unwrap())),
        };

        let last_req_inner: LastReqInner = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let last_req_inner_raw = picky_asn1_der::to_vec(&last_req_inner).unwrap();

        assert_eq!(last_req_inner, expected);
        assert_eq!(last_req_inner_raw, expected_raw);
    }

    #[test]
    fn test_authorization_data() {}
}
