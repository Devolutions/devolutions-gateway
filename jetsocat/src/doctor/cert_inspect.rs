//! Minimal DER walker for X.509 certificate extension inspection.
//!
//! Navigates the ASN.1 DER structure of an X.509 certificate to check
//! for the presence of specific extensions (SAN, EKU) without requiring
//! a full X.509 parsing library.
//!
//! # Design rationale
//!
//! We intentionally use a hand-written DER walker instead of pulling in a crate
//! such as `x509-cert` or `x509-parser`.
//! Jetsocat is meant to stay lean: adding an X.509 crate would pull a transitive
//! dependency tree (`der`, `spki`, `const-oid`, … or `asn1-rs`, `nom`, `oid-registry`, …),
//! increasing compile times and binary size for what amounts to two boolean questions
//! ("does the cert have a SAN extension?" and "does the EKU contain serverAuth?").
//!
//! Because the X.509 structure and the OIDs we inspect are standardised and frozen,
//! this code carries virtually no maintenance burden.

/// OID for Subject Alternative Name (2.5.29.17).
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];

/// OID for Extended Key Usage (2.5.29.37).
const OID_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];

/// OID for id-kp-serverAuth (1.3.6.1.5.5.7.3.1).
const OID_KP_SERVER_AUTH: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

/// Checks if a DER-encoded X.509 certificate has the Subject Alternative Name extension.
pub(super) fn cert_has_san_extension(cert_der: &[u8]) -> anyhow::Result<bool> {
    cert_has_extension(cert_der, OID_SUBJECT_ALT_NAME)
}

/// Checks if a DER-encoded X.509 certificate includes the serverAuth Extended Key Usage.
pub(super) fn cert_has_server_auth_eku(cert_der: &[u8]) -> anyhow::Result<bool> {
    let Some(eku_value) = cert_find_extension_value(cert_der, OID_EXTENDED_KEY_USAGE)? else {
        return Ok(false);
    };

    // EKU value is a SEQUENCE of KeyPurposeId OIDs.
    let (tag, content, _) = der_read_tlv(eku_value)?;
    anyhow::ensure!(tag == 0x30, "expected EKU SEQUENCE, got tag {tag:#04X}");

    let mut pos = 0;
    while pos < content.len() {
        let (tag, oid_bytes, consumed) = der_read_tlv(&content[pos..])?;
        anyhow::ensure!(tag == 0x06, "expected OID in EKU SEQUENCE, got tag {tag:#04X}");
        if oid_bytes == OID_KP_SERVER_AUTH {
            return Ok(true);
        }
        pos += consumed;
    }

    Ok(false)
}

fn cert_has_extension(cert_der: &[u8], target_oid: &[u8]) -> anyhow::Result<bool> {
    Ok(cert_find_extension_value(cert_der, target_oid)?.is_some())
}

/// Finds an extension by OID and returns the content of its `extnValue` OCTET STRING.
fn cert_find_extension_value<'a>(cert_der: &'a [u8], target_oid: &[u8]) -> anyhow::Result<Option<&'a [u8]>> {
    let Some(extensions) = cert_find_extensions(cert_der)? else {
        return Ok(None);
    };

    // Extensions is a SEQUENCE of Extension.
    let (tag, exts_content, _) = der_read_tlv(extensions)?;
    anyhow::ensure!(tag == 0x30, "expected Extensions SEQUENCE, got tag {tag:#04X}");

    let mut pos = 0;
    while pos < exts_content.len() {
        let (tag, ext_bytes, consumed) = der_read_tlv(&exts_content[pos..])?;
        anyhow::ensure!(tag == 0x30, "expected Extension SEQUENCE, got tag {tag:#04X}");

        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
        let (oid_tag, oid_bytes, mut inner_pos) = der_read_tlv(ext_bytes)?;
        anyhow::ensure!(oid_tag == 0x06, "expected extension OID, got tag {oid_tag:#04X}");

        if oid_bytes == target_oid {
            // Walk remaining fields to find the OCTET STRING value.
            while inner_pos < ext_bytes.len() {
                let (inner_tag, inner_bytes, next_inner) = der_read_tlv(&ext_bytes[inner_pos..])?;
                if inner_tag == 0x04 {
                    return Ok(Some(inner_bytes));
                }
                inner_pos += next_inner;
            }
        }

        pos += consumed;
    }

    Ok(None)
}

/// Locates the extensions block in a DER-encoded X.509 certificate.
///
/// Returns the raw bytes of the `[3] EXPLICIT` wrapper content (which contains
/// the Extensions SEQUENCE), or `None` if extensions are absent.
fn cert_find_extensions(cert_der: &[u8]) -> anyhow::Result<Option<&[u8]>> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (tag, cert_content, _) = der_read_tlv(cert_der)?;
    anyhow::ensure!(tag == 0x30, "expected Certificate SEQUENCE, got tag {tag:#04X}");

    // TBSCertificate ::= SEQUENCE { version, serial, sig, issuer, validity, subject, spki, ... }
    let (tag, tbs_content, _) = der_read_tlv(cert_content)?;
    anyhow::ensure!(tag == 0x30, "expected TBSCertificate SEQUENCE, got tag {tag:#04X}");

    let mut pos = 0;

    // version [0] EXPLICIT (optional)
    if pos < tbs_content.len() && tbs_content[pos] == 0xA0 {
        let (_, _, consumed) = der_read_tlv(&tbs_content[pos..])?;
        pos += consumed;
    }

    // Skip fixed fields: serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo.
    for field_name in [
        "serialNumber",
        "signature",
        "issuer",
        "validity",
        "subject",
        "subjectPublicKeyInfo",
    ] {
        anyhow::ensure!(
            pos < tbs_content.len(),
            "unexpected end of TBSCertificate before {field_name}"
        );
        let (_, _, consumed) = der_read_tlv(&tbs_content[pos..])?;
        pos += consumed;
    }

    // issuerUniqueID [1] IMPLICIT (optional)
    if pos < tbs_content.len() && tbs_content[pos] == 0x81 {
        let (_, _, consumed) = der_read_tlv(&tbs_content[pos..])?;
        pos += consumed;
    }

    // subjectUniqueID [2] IMPLICIT (optional)
    if pos < tbs_content.len() && tbs_content[pos] == 0x82 {
        let (_, _, consumed) = der_read_tlv(&tbs_content[pos..])?;
        pos += consumed;
    }

    // extensions [3] EXPLICIT (optional)
    if pos < tbs_content.len() && tbs_content[pos] == 0xA3 {
        let (_, exts_wrapper, _) = der_read_tlv(&tbs_content[pos..])?;
        return Ok(Some(exts_wrapper));
    }

    Ok(None)
}

/// Reads a DER TLV (Tag-Length-Value) at the start of `data`.
///
/// Returns `(tag, value_bytes, total_bytes_consumed)`.
fn der_read_tlv(data: &[u8]) -> anyhow::Result<(u8, &[u8], usize)> {
    anyhow::ensure!(!data.is_empty(), "unexpected end of DER data");

    let tag = data[0];
    let (length, length_size) = der_read_length(&data[1..])?;
    let header_size = 1 + length_size;
    let end = header_size + length;

    anyhow::ensure!(end <= data.len(), "DER value extends beyond available data");

    Ok((tag, &data[header_size..end], end))
}

/// Decodes a DER length field. Returns `(length_value, bytes_consumed)`.
fn der_read_length(data: &[u8]) -> anyhow::Result<(usize, usize)> {
    anyhow::ensure!(!data.is_empty(), "unexpected end of DER data reading length");

    let first = data[0];

    if first < 0x80 {
        // Short form.
        Ok((first as usize, 1))
    } else if first == 0x80 {
        anyhow::bail!("indefinite-length encoding is not valid DER");
    } else {
        // Long form.
        let num_bytes = (first & 0x7F) as usize;
        anyhow::ensure!(num_bytes <= 4 && num_bytes < data.len(), "invalid DER length encoding");
        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | data[1 + i] as usize;
        }
        Ok((length, 1 + num_bytes))
    }
}

struct TbsFields<'a> {
    issuer_tlv: &'a [u8],
    subject_tlv: &'a [u8],
}

/// Extracts the Issuer and Subject TLV (Tag-Length-Value) slices from a DER-encoded X.509 certificate.
fn cert_tbs_fields(cert_der: &[u8]) -> anyhow::Result<TbsFields<'_>> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (tag, cert_content, _) = der_read_tlv(cert_der)?;
    anyhow::ensure!(tag == 0x30, "expected Certificate SEQUENCE, got tag {tag:#04X}");

    // TBSCertificate ::= SEQUENCE { version?, serial, signature, issuer, validity, subject, ... }
    let (tag, tbs_content, _) = der_read_tlv(cert_content)?;
    anyhow::ensure!(tag == 0x30, "expected TBSCertificate SEQUENCE, got tag {tag:#04X}");

    let mut pos = 0;

    // version [0] EXPLICIT (optional)
    if pos < tbs_content.len() && tbs_content[pos] == 0xA0 {
        let (_, _, consumed) = der_read_tlv(&tbs_content[pos..])?;
        pos += consumed;
    }

    // Skip serialNumber (field 0)
    anyhow::ensure!(pos < tbs_content.len(), "unexpected end before serialNumber");
    let (_, _, consumed) = der_read_tlv(&tbs_content[pos..])?;
    pos += consumed;

    // Skip signature AlgorithmIdentifier (field 1)
    anyhow::ensure!(pos < tbs_content.len(), "unexpected end before signature");
    let (_, _, consumed) = der_read_tlv(&tbs_content[pos..])?;
    pos += consumed;

    // Read issuer (field 2) — full TLV
    anyhow::ensure!(pos < tbs_content.len(), "unexpected end before issuer");
    let issuer_start = pos;
    let (_, _, consumed) = der_read_tlv(&tbs_content[pos..])?;
    let issuer_tlv = &tbs_content[issuer_start..issuer_start + consumed];
    pos += consumed;

    // Skip validity (field 3)
    anyhow::ensure!(pos < tbs_content.len(), "unexpected end before validity");
    let (_, _, consumed) = der_read_tlv(&tbs_content[pos..])?;
    pos += consumed;

    // Read subject (field 4) — full TLV
    anyhow::ensure!(pos < tbs_content.len(), "unexpected end before subject");
    let subject_start = pos;
    let (_, _, consumed) = der_read_tlv(&tbs_content[pos..])?;
    let subject_tlv = &tbs_content[subject_start..subject_start + consumed];

    Ok(TbsFields {
        issuer_tlv,
        subject_tlv,
    })
}

/// Returns true if the chain is likely missing an intermediate certificate.
///
/// Operates purely on the presented bytes — no trust store is consulted.
///
/// The result is a best-effort hint, not a definitive verdict. Callers should
/// use it to select a more specific diagnostic message but must not rely on it
/// for security decisions.
///
/// DER parse errors return `false` (i.e. "chain assumed complete"), which
/// avoids false-positive warnings. Any underlying malformation should be caught
/// independently by a proper certificate verifier.
pub(super) fn chain_likely_missing_intermediate<I>(certs_der: I) -> bool
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    let mut iter = certs_der.into_iter();

    // Assume the first certificate is the leaf.
    let Some(leaf) = iter.next() else {
        return false; // empty chain
    };

    // A parse failure on the leaf is treated as "chain assumed complete" (no false positive).
    let Ok(leaf_fields) = cert_tbs_fields(leaf.as_ref()) else {
        return false;
    };

    // A self-signed certificate is its own issuer; no intermediate is expected.
    if leaf_fields.issuer_tlv == leaf_fields.subject_tlv {
        return false;
    }

    let leaf_issuer = leaf_fields.issuer_tlv;

    // If any subsequent cert's subject matches the leaf's issuer, the chain appears complete.
    // A parse failure is treated as "chain assumed complete" (no false positive): the cert may
    // well be the missing intermediate, we just can't verify it.
    for cert in iter {
        match cert_tbs_fields(cert.as_ref()) {
            Ok(fields) if fields.subject_tlv == leaf_issuer => return false, // issuer found → chain appears complete
            Ok(_) => {}                                                      // not a match, keep looking
            Err(_) => return false, // unreadable cert → assume complete to avoid false positive
        }
    }

    true // no issuer found → likely missing intermediate
}
