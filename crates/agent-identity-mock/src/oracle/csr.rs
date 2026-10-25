//! PKCS#10 CSR checking per CONTRACT.agent-identity.md §4: uncompressed P-256 key required, self-signature verified, enrollment URL extension read, subject and other attributes ignored.
//! X.509 and DER provide CSR types; the signature is checked with P-256.

use der::asn1::{AnyRef, BitStringRef, ObjectIdentifier};
use der::{Decode as _, Reader as _, SliceReader, Tag, TagNumber, Tagged as _};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use x509_cert::request::Version;
use x509_cert::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

/// id-ecPublicKey (RFC 5480).
const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// secp256r1 / P-256 (RFC 5480).
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// extensionRequest (RFC 2985 §5.4.2).
const EXTENSION_REQUEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");
/// ecdsa-with-SHA256 (RFC 5758).
const ECDSA_WITH_SHA_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// The enrollment URL extension, as CONTRACT.agent-identity.md §4 names it.
pub(crate) const ENROLLMENT_URL_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.1.1");

/// A CSR that passed [`check_csr`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CheckedCsr {
    pub(crate) public_key: VerifyingKey,
    /// The value of the enrollment URL extension the CSR requests, if any.
    pub(crate) enrollment_url: Option<String>,
}

/// Parses a PKCS#10 CSR (DER), requires a P-256 subject key and verifies the self-signature.
/// Returns the subject public key and the requested enrollment URL, or `None` for any §5.4 `invalid_request` case.
pub(crate) fn check_csr(der_bytes: &[u8]) -> Option<CheckedCsr> {
    let (info, algorithm, signature) = AnyRef::from_der(der_bytes)
        .and_then(|req| {
            req.sequence(|reader| {
                Ok((
                    reader.tlv_bytes()?,
                    AlgorithmIdentifierRef::decode(reader)?,
                    BitStringRef::decode(reader)?,
                ))
            })
        })
        .ok()?;

    // RFC 5758 §3.2: the ecdsa-with-SHA256 encoding "MUST omit the parameters field".
    if !(algorithm.oid == ECDSA_WITH_SHA_256 && algorithm.parameters.is_none()) {
        return None;
    }

    let (spki, attributes) = AnyRef::from_der(info).and_then(|info| info.sequence(read_info)).ok()?;
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return None;
    }
    let params_oid = spki.algorithm.parameters?.decode_as::<ObjectIdentifier>().ok()?;
    if params_oid != SECP256R1 {
        return None;
    }
    // Only the uncompressed form (0x04 ‖ X ‖ Y), so that each key has exactly one SPKI SHA-256.
    let point = spki.subject_public_key.as_bytes()?;
    if point.len() != 65 || point[0] != 0x04 {
        return None;
    }
    let key = VerifyingKey::from_sec1_bytes(point).ok()?;

    // The signature covers `info` as received, never a re-encoding, which could differ in the subject or attributes.
    // `as_bytes` rejects unused bits, since the BIT STRING holds the DER `Ecdsa-Sig-Value` (RFC 3279 §2.2.3), a whole number of octets.
    let signature = Signature::from_der(signature.as_bytes()?).ok()?;
    key.verify(info, &signature).ok()?;

    return Some(CheckedCsr {
        public_key: key,
        enrollment_url: requested_enrollment_url(attributes),
    });

    /// Reads a `CertificationRequestInfo` ([RFC 2986 §4, "Certification request syntax"][rfc]) and returns its `subjectPKInfo` and the contents of its attributes.
    /// Of the subject and attributes, only the tags are checked: the server ignores all but the enrollment URL extension and doesn't require their contents in canonical DER (CONTRACT.agent-identity.md §4).
    ///
    /// [rfc]: https://www.rfc-editor.org/rfc/rfc2986#section-4
    fn read_info<'a>(reader: &mut SliceReader<'a>) -> der::Result<(SubjectPublicKeyInfoRef<'a>, &'a [u8])> {
        Version::decode(reader)?;
        AnyRef::decode(reader)?.tag().assert_eq(Tag::Sequence)?;
        let spki = SubjectPublicKeyInfoRef::decode(reader)?;
        let attributes = AnyRef::decode(reader)?;
        attributes.tag().assert_eq(TagNumber(0).context_specific(true))?;
        Ok((spki, attributes.value()))
    }
}

/// Returns the value of the enrollment URL extension (CONTRACT.agent-identity.md §4) that a CSR's attributes request in an `extensionRequest` ([RFC 2985 §5.4.2, "Extension request"][rfc]), if any.
/// `attributes` is the contents of the `[0]` attribute set; the attributes and extensions around the one read are skipped without requiring canonical DER.
///
/// [rfc]: https://www.rfc-editor.org/rfc/rfc2985#section-5.4.2
fn requested_enrollment_url(attributes: &[u8]) -> Option<String> {
    const OCTET_STRING: u8 = 0x04;
    const OBJECT_IDENTIFIER: u8 = 0x06;
    const IA5_STRING: u8 = 0x16;
    const SEQUENCE: u8 = 0x30;
    const SET: u8 = 0x31;

    tlvs(attributes)
        .filter(|(tag, _)| *tag == SEQUENCE)
        .filter_map(|(_, attribute)| {
            let mut fields = tlvs(attribute);
            if fields.next()? != (OBJECT_IDENTIFIER, EXTENSION_REQUEST.as_bytes()) {
                return None;
            }
            fields.next()
        })
        .filter(|(tag, _)| *tag == SET)
        .flat_map(|(_, values)| tlvs(values))
        .filter(|(tag, _)| *tag == SEQUENCE)
        .flat_map(|(_, extensions)| tlvs(extensions))
        .filter(|(tag, _)| *tag == SEQUENCE)
        .find_map(|(_, extension)| {
            let mut fields = tlvs(extension);
            if fields.next()? != (OBJECT_IDENTIFIER, ENROLLMENT_URL_EXTENSION.as_bytes()) {
                return None;
            }
            // `critical` is optional (`DEFAULT FALSE`), so `extnValue` is the first OCTET STRING.
            let (_, value) = fields.find(|(tag, _)| *tag == OCTET_STRING)?;
            let (tag, url, rest) = split_tlv(value)?;
            let url = std::str::from_utf8(url).ok()?;
            (tag == IA5_STRING && rest.is_empty() && url.is_ascii()).then(|| url.to_owned())
        })
}

/// Iterates over the TLVs of `contents`, stopping at the first one [`split_tlv`] cannot read.
fn tlvs(mut contents: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    std::iter::from_fn(move || {
        let (tag, value, rest) = split_tlv(contents)?;
        contents = rest;
        Some((tag, value))
    })
}

/// Splits the first TLV off `input` and returns its tag, its contents and the rest of `input`.
/// The tag is one byte and the length is definite, in the short form or in a long form of up to 4 bytes, minimal or not, as BER allows (X.690 §8.1.3).
fn split_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        // `0x80` alone is the indefinite form, which only constructed encodings may use and a CSR never needs.
        let (length_bytes, rest) = rest.split_at_checked(usize::from(first & 0x7F))?;
        if !(1..=4).contains(&length_bytes.len()) {
            return None;
        }
        let length = length_bytes
            .iter()
            .fold(0usize, |length, byte| (length << 8) | usize::from(*byte));
        (length, rest)
    };
    let (value, rest) = rest.split_at_checked(length)?;
    Some((tag, value, rest))
}

#[cfg(test)]
mod tests {
    use der::asn1::{Any, BitString, ObjectIdentifier};
    use der::{Encode as _, Length};
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{DerSignature, SigningKey};
    use rstest::rstest;
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

    use super::{ECDSA_WITH_SHA_256, ENROLLMENT_URL_EXTENSION, ID_EC_PUBLIC_KEY, SECP256R1, check_csr};

    /// extensionRequest (RFC 2985 §5.4.2).
    const EXTENSION_REQUEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");
    /// id-ce-subjectAltName (RFC 5280 §4.2.1.6).
    const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

    const URL: &str = "https://host.example/dvls";

    /// secp384r1 (RFC 5480).
    const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
    /// id-ecDH (RFC 5480): an EC key restricted to key agreement.
    const ID_EC_DH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.12");
    /// ecdsa-with-SHA384 (RFC 5758).
    const ECDSA_WITH_SHA_384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

    /// One RDN holding O=a before CN=z, while DER sorts CN (type OID ending `03`) before O (ending `0A`).
    const UNSORTED_RDN: &[u8] = &[
        0x30, 0x16, // RDNSequence
        0x31, 0x14, // RelativeDistinguishedName
        0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x01, b'a', // O=a
        0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, b'z', // CN=z
    ];

    /// `UNSORTED_RDN` in DER order, as a re-encoding emits it.
    const SORTED_RDN: &[u8] = &[
        0x30, 0x16, // RDNSequence
        0x31, 0x14, // RelativeDistinguishedName
        0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, b'z', // CN=z
        0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x01, b'a', // O=a
    ];

    /// CN=z with the long-form string length `81 01`, which DER forbids.
    const NON_MINIMAL_LENGTH_RDN: &[u8] = &[
        0x30, 0x0D, // RDNSequence
        0x31, 0x0B, // RelativeDistinguishedName
        0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x81, 0x01, b'z', // CN=z
    ];

    /// challengePassword before unstructuredName, while DER sorts unstructuredName (type OID ending `02`) first.
    const UNSORTED_ATTRIBUTES: &[u8] = &[
        0xA0, 0x24, // [0] Attributes
        0x30, 0x10, // Attribute
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07, // challengePassword
        0x31, 0x03, 0x0C, 0x01, b'x', // {"x"}
        0x30, 0x10, // Attribute
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x02, // unstructuredName
        0x31, 0x03, 0x0C, 0x01, b'x', // {"x"}
    ];

    /// One attribute whose values hold "b" before "a", while DER sorts "a" first.
    const UNSORTED_ATTRIBUTE_VALUES: &[u8] = &[
        0xA0, 0x15, // [0] Attributes
        0x30, 0x13, // Attribute
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x02, // unstructuredName
        0x31, 0x06, 0x0C, 0x01, b'b', 0x0C, 0x01, b'a', // {"b", "a"}
    ];

    /// The fields of a PKCS#10 CSR ([RFC 2986 §4, "Certification request syntax"][rfc]) as encoded bytes, so that a test can break any one of them.
    ///
    /// [rfc]: https://www.rfc-editor.org/rfc/rfc2986#section-4
    struct Csr {
        version: Vec<u8>,
        subject: Vec<u8>,
        public_key: Vec<u8>,
        attributes: Vec<u8>,
        signature_algorithm: Vec<u8>,
        signer: SigningKey,
        /// Unused-bit count of the signature BIT STRING.
        signature_unused_bits: u8,
        trailing: Vec<u8>,
    }

    impl Csr {
        /// A CSR for `signer()`'s key with an empty subject and attribute set, as the agent sends it
        /// (CONTRACT.agent-identity.md §4).
        fn valid() -> Self {
            Self {
                version: vec![0x02, 0x01, 0x00],
                subject: vec![0x30, 0x00],
                public_key: public_key(ID_EC_PUBLIC_KEY, SECP256R1, false),
                attributes: vec![0xA0, 0x00],
                signature_algorithm: algorithm(ECDSA_WITH_SHA_256, &[]),
                signer: signer(),
                signature_unused_bits: 0,
                trailing: Vec::new(),
            }
        }

        /// `CertificationRequestInfo`, built from the field bytes without re-encoding them.
        fn info(&self) -> Vec<u8> {
            tlv(
                0x30,
                &[&self.version, &self.subject, &self.public_key, &self.attributes],
            )
        }

        /// `signer`'s signature over exactly `info()`.
        fn signature(&self) -> DerSignature {
            self.signer.try_sign(&self.info()).expect("signing succeeds")
        }

        fn encode(&self) -> Vec<u8> {
            self.encode_with(&self.signature())
        }

        fn encode_with(&self, signature: &DerSignature) -> Vec<u8> {
            let signature = tlv(0x03, &[&[self.signature_unused_bits], signature.as_bytes()]);
            [
                tlv(0x30, &[&self.info(), &self.signature_algorithm, &signature]),
                self.trailing.clone(),
            ]
            .concat()
        }
    }

    fn signer() -> SigningKey {
        SigningKey::from_slice(&[1; 32]).expect("valid P-256 scalar")
    }

    /// `AlgorithmIdentifier` with the encoded `parameters`, absent when empty.
    fn algorithm(oid: ObjectIdentifier, parameters: &[u8]) -> Vec<u8> {
        tlv(0x30, &[&oid.to_der().expect("encodable OID"), parameters])
    }

    /// `SubjectPublicKeyInfo` holding `signer()`'s point.
    fn public_key(algorithm: ObjectIdentifier, curve: ObjectIdentifier, compress: bool) -> Vec<u8> {
        let point = signer().verifying_key().to_sec1_point(compress);
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: algorithm,
                parameters: Some(Any::encode_from(&curve).expect("encodable OID")),
            },
            subject_public_key: BitString::from_bytes(point.as_bytes()).expect("valid bit string"),
        }
        .to_der()
        .expect("encodable public key")
    }

    /// Encodes a DER TLV around the concatenated `contents`.
    fn tlv(tag: u8, contents: &[&[u8]]) -> Vec<u8> {
        let contents = contents.concat();
        let length = Length::try_from(contents.len())
            .and_then(|length| length.to_der())
            .expect("encodable length");
        [&[tag], length.as_slice(), &contents].concat()
    }

    /// `[0] Attributes` holding the encoded `attributes` in the order given.
    fn attributes(attributes: &[&[u8]]) -> Vec<u8> {
        tlv(0xA0, attributes)
    }

    /// An `extensionRequest` attribute (RFC 2985 §5.4.2) holding one `Extensions` of the encoded `extensions`.
    fn extension_request(extensions: &[&[u8]]) -> Vec<u8> {
        let oid = EXTENSION_REQUEST.to_der().expect("encodable OID");
        tlv(0x30, &[&oid, &tlv(0x31, &[&tlv(0x30, extensions)])])
    }

    /// An `Extension` (RFC 5280 §4.1) for `oid`, with the encoded `critical` flag (empty for the default) and `extnValue`
    /// holding `value`.
    fn extension(oid: ObjectIdentifier, critical: &[u8], value: &[u8]) -> Vec<u8> {
        let oid = oid.to_der().expect("encodable OID");
        tlv(0x30, &[&oid, critical, &tlv(0x04, &[value])])
    }

    /// The enrollment URL extension naming `url` as an `IA5String` (CONTRACT.agent-identity.md §4).
    fn enrollment_url(url: &str) -> Vec<u8> {
        extension(ENROLLMENT_URL_EXTENSION, &[], &tlv(0x16, &[url.as_bytes()]))
    }

    /// Rewrites a TLV's short-form length in the long form `81 nn`, which DER forbids.
    fn with_long_form_length(tlv: &[u8]) -> Vec<u8> {
        assert!(tlv[1] < 0x80, "short-form length");
        [&[tlv[0], 0x81], &tlv[1..]].concat()
    }

    /// CONTRACT.agent-identity.md §4: the CSR public key must be "an uncompressed P-256 point [...], else
    /// `invalid_request`".
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[rstest]
    #[case::uncompressed(false, true)]
    #[case::compressed(true, false)]
    fn csr_key_must_be_an_uncompressed_point(#[case] compress: bool, #[case] accepted: bool) {
        let csr = Csr {
            public_key: public_key(ID_EC_PUBLIC_KEY, SECP256R1, compress),
            ..Csr::valid()
        };
        assert_eq!(check_csr(&csr.encode()).is_some(), accepted);
    }

    /// CONTRACT.agent-identity.md §4: the server ignores the CSR's subject and attributes and "does not require their contents in canonical DER form, such as a sorted `SET OF`".
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[rstest]
    #[case::unsorted_rdn(Csr { subject: UNSORTED_RDN.to_vec(), ..Csr::valid() })]
    #[case::non_minimal_length_in_subject(Csr { subject: NON_MINIMAL_LENGTH_RDN.to_vec(), ..Csr::valid() })]
    #[case::unsorted_attributes(Csr { attributes: UNSORTED_ATTRIBUTES.to_vec(), ..Csr::valid() })]
    #[case::unsorted_attribute_values(Csr { attributes: UNSORTED_ATTRIBUTE_VALUES.to_vec(), ..Csr::valid() })]
    fn ignored_csr_parts_need_not_be_canonical_der(#[case] csr: Csr) {
        assert_eq!(
            check_csr(&csr.encode()).map(|checked| checked.public_key).as_ref(),
            Some(signer().verifying_key())
        );
    }

    /// CONTRACT.agent-identity.md §4: the server "verifies the CSR self-signature", which covers the request as
    /// received.
    /// This CSR carries `UNSORTED_RDN` but is signed over its re-encoding, so only a check that re-encoded the request would accept it.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[test]
    fn csr_signed_over_a_reencoded_request_is_invalid_request() {
        let received = Csr {
            subject: UNSORTED_RDN.to_vec(),
            ..Csr::valid()
        };
        let reencoded = Csr {
            subject: SORTED_RDN.to_vec(),
            ..Csr::valid()
        };
        assert_eq!(check_csr(&received.encode_with(&reencoded.signature())), None);
    }

    /// Each case breaks one rule of a valid CSR, which is then `invalid_request`: the key, self-signature and signature algorithm rules of CONTRACT.agent-identity.md §4, and the DER PKCS#10 structure (CONTRACT.agent-identity.md §1, RFC 2986 §4) outside the ignored subject and attributes.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    // oracle: spec RFC 2986 §4
    #[rstest]
    #[case::wrong_curve(Csr { public_key: public_key(ID_EC_PUBLIC_KEY, SECP384R1, false), ..Csr::valid() })]
    #[case::wrong_key_algorithm(Csr { public_key: public_key(ID_EC_DH, SECP256R1, false), ..Csr::valid() })]
    #[case::bad_self_signature(Csr { signer: SigningKey::from_slice(&[2; 32]).expect("valid P-256 scalar"), ..Csr::valid() })]
    // Signed with SHA-256, so that only the algorithm identifier is wrong.
    #[case::signature_algorithm_not_ecdsa_with_sha256(Csr { signature_algorithm: algorithm(ECDSA_WITH_SHA_384, &[]), ..Csr::valid() })]
    // RFC 5758 §3.2: the ecdsa-with-SHA256 encoding "MUST omit the parameters field"; here they are NULL.
    // oracle: spec RFC 5758 §3.2
    #[case::signature_algorithm_with_parameters(Csr { signature_algorithm: algorithm(ECDSA_WITH_SHA_256, &[0x05, 0x00]), ..Csr::valid() })]
    // RFC 3279 §2.2.3: the BIT STRING holds the DER `Ecdsa-Sig-Value`, a whole number of octets.
    // oracle: spec RFC 3279 §2.2.3
    #[case::signature_not_octet_aligned(Csr { signature_unused_bits: 1, ..Csr::valid() })]
    #[case::version_2(Csr { version: vec![0x02, 0x01, 0x01], ..Csr::valid() })]
    #[case::non_minimal_length_in_public_key(Csr { public_key: with_long_form_length(&public_key(ID_EC_PUBLIC_KEY, SECP256R1, false)), ..Csr::valid() })]
    #[case::subject_not_a_name(Csr { subject: vec![0x31, 0x00], ..Csr::valid() })]
    #[case::attributes_not_tagged_0(Csr { attributes: vec![0xA1, 0x00], ..Csr::valid() })]
    #[case::trailing_data(Csr { trailing: vec![0x00], ..Csr::valid() })]
    fn csr_breaking_a_rule_is_invalid_request(#[case] csr: Csr) {
        assert_eq!(check_csr(&csr.encode()), None);
    }

    /// CONTRACT.agent-identity.md §4: the server "reads the enrollment URL extension from its `extensionRequest`" and
    /// ignores "every other attribute or requested extension", whose contents need not be canonical DER.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[rstest]
    #[case::built_by_rustcrypto(crate::test_x509::csr_naming(&signer(), URL))]
    #[case::alone(Csr { attributes: attributes(&[&extension_request(&[&enrollment_url(URL)])]), ..Csr::valid() }.encode())]
    #[case::explicitly_non_critical(Csr { attributes: attributes(&[&extension_request(&[&extension(ENROLLMENT_URL_EXTENSION, &[0x01, 0x01, 0x00], &tlv(0x16, &[URL.as_bytes()]))])]), ..Csr::valid() }.encode())]
    #[case::after_another_requested_extension(Csr { attributes: attributes(&[&extension_request(&[&extension(SUBJECT_ALT_NAME, &[], &[0x30, 0x00]), &enrollment_url(URL)])]), ..Csr::valid() }.encode())]
    #[case::after_unsorted_attributes(Csr { attributes: attributes(&[&UNSORTED_ATTRIBUTES[2..], &extension_request(&[&enrollment_url(URL)])]), ..Csr::valid() }.encode())]
    #[case::after_an_attribute_with_a_long_form_length(Csr { attributes: attributes(&[&with_long_form_length(&UNSORTED_ATTRIBUTE_VALUES[2..]), &extension_request(&[&enrollment_url(URL)])]), ..Csr::valid() }.encode())]
    fn requested_enrollment_url_is_read(#[case] csr: Vec<u8>) {
        assert_eq!(
            check_csr(&csr).and_then(|checked| checked.enrollment_url).as_deref(),
            Some(URL)
        );
    }

    /// CONTRACT.agent-identity.md §4: the enrollment URL extension holds the URL "as an `IA5String`" and is read from
    /// the `extensionRequest`; a CSR without it is still a valid CSR, since renewal ignores the value.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[rstest]
    #[case::no_attributes(Csr::valid())]
    #[case::empty_extension_request(Csr { attributes: attributes(&[&extension_request(&[])]), ..Csr::valid() })]
    #[case::other_extension_only(Csr { attributes: attributes(&[&extension_request(&[&extension(SUBJECT_ALT_NAME, &[], &tlv(0x16, &[URL.as_bytes()]))])]), ..Csr::valid() })]
    #[case::utf8_string_value(Csr { attributes: attributes(&[&extension_request(&[&extension(ENROLLMENT_URL_EXTENSION, &[], &tlv(0x0C, &[URL.as_bytes()]))])]), ..Csr::valid() })]
    fn csr_without_an_ia5_enrollment_url_has_none(#[case] csr: Csr) {
        let checked = check_csr(&csr.encode()).expect("valid CSR");
        assert_eq!(checked.enrollment_url, None);
    }

    /// CONTRACT.agent-identity.md §4: the server reads the enrollment URL extension and ignores the other attributes,
    /// so an attribute it cannot read leaves a valid CSR without a URL: the reader stops there rather than guess where
    /// the next attribute starts.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[rstest]
    #[case::length_reaching_into_the_next_attribute(&[0x30, 0x05, 0x06])]
    #[case::indefinite_length(&[0x30, 0x80])]
    #[case::five_byte_long_form_length(&[0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00])]
    #[case::length_past_the_end(&[0x30, 0x81, 0xFF])]
    fn unreadable_attribute_before_the_extension_request_leaves_no_url(#[case] unreadable: &[u8]) {
        let csr = Csr {
            attributes: attributes(&[unreadable, &extension_request(&[&enrollment_url(URL)])]),
            ..Csr::valid()
        };

        let checked = check_csr(&csr.encode()).expect("valid CSR");

        assert_eq!(checked.enrollment_url, None);
    }
}
