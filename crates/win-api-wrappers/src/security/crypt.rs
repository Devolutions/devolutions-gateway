use std::fmt::Debug;
use std::fs::File;
use std::mem::{self};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::slice;

use anyhow::{anyhow, bail, Result};

use crate::error::Error;
use crate::utils::{SafeWindowsString, WideString};
use windows::core::{HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    CRYPT_E_BAD_MSG, ERROR_INCORRECT_SIZE, ERROR_INVALID_VARIANT, HANDLE, HWND, INVALID_HANDLE_VALUE, NTE_BAD_ALGID,
    S_OK, TRUST_E_BAD_DIGEST, TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN,
};
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash,
    CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows::Win32::Security::Cryptography::{
    CertGetEnhancedKeyUsage, CertNameToStrW, BCRYPT_SHA256_ALGORITHM, CERT_CONTEXT, CERT_EXTENSION, CERT_INFO,
    CERT_QUERY_ENCODING_TYPE, CERT_SIMPLE_NAME_STR, CERT_STRING_TYPE, CERT_V1, CERT_V2, CERT_V3, CMSG_SIGNER_INFO,
    CRYPT_ATTRIBUTE, CRYPT_INTEGER_BLOB, CTL_USAGE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows::Win32::Security::WinTrust::{
    WTHelperProvDataFromStateData, WinVerifyTrustEx, CRYPT_PROVIDER_CERT, CRYPT_PROVIDER_DATA, CRYPT_PROVIDER_SGNR,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOKE_WHOLECHAIN,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_USE_DEFAULT_OSVER_CHECK,
};

pub struct CatalogInfo {
    pub path: PathBuf,
    pub hash: Vec<u8>,
}

impl CatalogInfo {
    pub fn try_from_file(path: &Path) -> Result<Option<Self>> {
        let admin_ctx = CatalogAdminContext::try_new()?;

        let hash = admin_ctx.hash_file(path)?;

        let catalog_path = admin_ctx.catalogs_for_hash(&hash).next();

        Ok(catalog_path.map(|catalog_path| Self {
            hash,
            path: catalog_path,
        }))
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
/// https://stackoverflow.com/questions/68215779/getting-winverifytrust-to-work-with-catalog-signed-files-such-as-cmd-exe
/// https://github.com/dragokas/Verify-Signature-Cpp/blob/master/verify.cpp#L140
/// https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Security/CodeSigning/cpp/codesigning.cpp
pub fn win_verify_trust(path: &Path, catalog_info: Option<CatalogInfo>) -> Result<WinVerifyTrustResult> {
    let path = WideString::from(path);
    let catalog_info = catalog_info.map(|c| {
        (
            WideString::from(&c.path),
            WideString::from(base16ct::upper::encode_string(&c.hash)),
        )
    });

    #[derive(Debug)]
    enum WintrustInfo {
        Catalog(WINTRUST_CATALOG_INFO),
        File(WINTRUST_FILE_INFO),
    }

    let mut wintrust_info = match &catalog_info {
        Some((catalog_info_path, catalog_info_member)) => WintrustInfo::Catalog(WINTRUST_CATALOG_INFO {
            cbStruct: mem::size_of::<WINTRUST_CATALOG_INFO>() as _,
            pcwszCatalogFilePath: catalog_info_path.as_pcwstr(),
            pcwszMemberFilePath: path.as_pcwstr(),
            pcwszMemberTag: catalog_info_member.as_pcwstr(),
            ..Default::default()
        }),
        None => WintrustInfo::File(WINTRUST_FILE_INFO {
            cbStruct: mem::size_of::<WINTRUST_FILE_INFO>() as _,
            pcwszFilePath: path.as_pcwstr(),
            ..Default::default()
        }),
    };

    let mut win_trust_data = WINTRUST_DATA {
        cbStruct: mem::size_of::<WINTRUST_DATA>() as _,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: match &wintrust_info {
            WintrustInfo::Catalog(_) => WTD_CHOICE_CATALOG,
            WintrustInfo::File(_) => WTD_CHOICE_FILE,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        Anonymous: match &mut wintrust_info {
            WintrustInfo::Catalog(x) => WINTRUST_DATA_0 { pCatalog: x },
            WintrustInfo::File(x) => WINTRUST_DATA_0 { pFile: x },
        },
        dwProvFlags: WTD_USE_DEFAULT_OSVER_CHECK | WTD_DISABLE_MD2_MD4 | WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };

    let mut guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let status = unsafe { WinVerifyTrustEx(HWND(INVALID_HANDLE_VALUE.0), &mut guid, &mut win_trust_data) };

    let result = AuthenticodeSignatureStatus::try_from(HRESULT(status));
    let provider = if win_trust_data.hWVTStateData.is_invalid() {
        None
    } else {
        unsafe {
            WTHelperProvDataFromStateData(win_trust_data.hWVTStateData)
                .as_ref()
                .map(CryptProviderData::try_from)
        }
    };

    win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;

    unsafe { WinVerifyTrustEx(HWND(INVALID_HANDLE_VALUE.0), &mut guid, &mut win_trust_data) };
    Ok(WinVerifyTrustResult {
        provider: provider.transpose()?,
        status: result.map_err(|x| x.ok().unwrap_err())?,
    })
}

#[derive(Debug)]
pub struct WinVerifyTrustResult {
    pub provider: Option<CryptProviderData>,
    pub status: AuthenticodeSignatureStatus,
}

pub fn authenticode_status(path: &Path) -> Result<WinVerifyTrustResult> {
    let catalog_info = CatalogInfo::try_from_file(path)?;

    win_verify_trust(path, catalog_info)
}

pub struct CatalogAdminContext {
    pub handle: HANDLE,
}

impl CatalogAdminContext {
    pub fn try_new() -> Result<Self> {
        let mut handle = HANDLE::default();

        // TODO add arguments
        unsafe { CryptCATAdminAcquireContext2(&mut handle.0 as *mut _ as _, None, BCRYPT_SHA256_ALGORITHM, None, 0) }?;

        Ok(Self { handle })
    }

    pub fn hash_file(&self, path: &Path) -> Result<Vec<u8>> {
        let file = File::open(path)?;
        let mut required_size = 0u32;

        unsafe {
            let _ = CryptCATAdminCalcHashFromFileHandle2(
                self.handle.0 as _,
                HANDLE(file.as_raw_handle() as _),
                &mut required_size,
                None,
                0,
            );

            let mut hash = Vec::with_capacity(required_size as _);

            CryptCATAdminCalcHashFromFileHandle2(
                self.handle.0 as _,
                HANDLE(file.as_raw_handle() as _),
                &mut required_size,
                Some(hash.as_mut_ptr()),
                0,
            )?;

            hash.set_len(required_size as _);

            Ok(hash)
        }
    }

    pub fn catalogs_for_hash<'a>(&'a self, hash: &'a [u8]) -> CatalogIterator<'a> {
        CatalogIterator::new(self, hash)
    }
}

impl Drop for CatalogAdminContext {
    fn drop(&mut self) {
        let _ = unsafe { CryptCATAdminReleaseContext(self.handle.0 as _, 0) };
    }
}

pub struct CatalogIterator<'a> {
    admin_ctx: &'a CatalogAdminContext,
    cur: Option<HANDLE>,
    hash: &'a [u8],
}

impl<'a> CatalogIterator<'a> {
    pub fn new(admin_ctx: &'a CatalogAdminContext, hash: &'a [u8]) -> Self {
        Self {
            admin_ctx,
            cur: None,
            hash,
        }
    }
}

impl Iterator for CatalogIterator<'_> {
    type Item = PathBuf;

    fn next(&mut self) -> Option<Self::Item> {
        let new_ctx = unsafe {
            CryptCATAdminEnumCatalogFromHash(
                self.admin_ctx.handle.0 as _,
                &self.hash,
                0,
                self.cur.map(|mut x| &mut x.0 as *mut _ as _),
            )
        };

        if new_ctx == 0 {
            None
        } else {
            self.cur = Some(HANDLE(new_ctx as _));

            let mut info = CATALOG_INFO {
                cbStruct: mem::size_of::<CATALOG_INFO>() as _,
                ..Default::default()
            };

            unsafe { CryptCATCatalogInfoFromContext(new_ctx, &mut info, 0) }.ok()?;

            PCWSTR(info.wszCatalogFile.as_ptr()).to_path_safe().ok()
        }
    }
}

impl Drop for CatalogIterator<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.cur {
            let _ = unsafe { CryptCATAdminReleaseCatalogContext(self.admin_ctx.handle.0 as _, handle.0 as _, 0) };
        }
    }
}

/// https://github.com/PowerShell/PowerShell/blob/2018c16df04af03a8f1805849820b65f41eb7e29/src/System.Management.Automation/security/MshSignature.cs#L282
#[derive(Debug)]
pub enum AuthenticodeSignatureStatus {
    Valid,
    Incompatible,
    NotSigned,
    HashMismatch,
    NotSupportedFileFormat,
    NotTrusted,
}

impl TryFrom<HRESULT> for AuthenticodeSignatureStatus {
    type Error = HRESULT;

    fn try_from(value: HRESULT) -> std::prelude::v1::Result<Self, Self::Error> {
        match value {
            S_OK => Ok(Self::Valid),
            NTE_BAD_ALGID => Ok(Self::Incompatible),
            TRUST_E_NOSIGNATURE => Ok(Self::NotSigned),
            TRUST_E_BAD_DIGEST | CRYPT_E_BAD_MSG => Ok(Self::HashMismatch),
            TRUST_E_PROVIDER_UNKNOWN => Ok(Self::NotSupportedFileFormat),
            TRUST_E_EXPLICIT_DISTRUST => Ok(Self::NotTrusted),
            err => Err(err),
        }
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_attribute
#[derive(Debug)]
pub struct CryptAttribute {
    pub oid: String,
    pub data: Vec<Vec<u8>>,
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_signer_info
#[derive(Debug)]
pub struct SignerInfo {
    pub issuer: String,
    pub serial_number: Vec<u8>,
    pub authenticated_attributes: Vec<CryptAttribute>,
    pub unauthenticated_attributes: Vec<CryptAttribute>,
}

#[derive(Debug)]
pub enum CertificateEncodingType {
    X509Asn,
    Pkcs7Asn,
}

#[derive(Debug)]
pub enum CertificateVersion {
    V1,
    V2,
    V3,
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_extension
#[derive(Debug)]
pub struct CertificateExtension {
    pub oid: String,
    pub critical: bool,
    pub data: Vec<u8>,
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_info
#[derive(Debug)]
pub struct CertificateInfo {
    pub version: CertificateVersion,
    pub serial_number: Vec<u8>,
    pub issuer: String,
    pub subject: String,
    pub extensions: Vec<CertificateExtension>,
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_context
#[derive(Debug)]
pub struct CertificateContext {
    pub encoding_type: CertificateEncodingType,
    pub encoded: Vec<u8>,
    pub info: CertificateInfo,
    pub eku: Vec<String>,
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_cert
#[derive(Debug)]
pub struct CryptProviderCertificate {
    pub cert: CertificateContext,
    pub commercial: bool,
    pub trusted_root: bool,
    pub self_signed: bool,
    pub test_cert: bool,
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_sgnr
#[derive(Debug)]
pub struct CryptProviderSigner {
    pub signer: SignerInfo,
    pub cert_chain: Vec<CryptProviderCertificate>,
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_data
#[derive(Debug)]
pub struct CryptProviderData {
    pub signers: Vec<CryptProviderSigner>,
}

impl TryFrom<&CRYPT_ATTRIBUTE> for CryptAttribute {
    type Error = anyhow::Error;

    fn try_from(value: &CRYPT_ATTRIBUTE) -> Result<Self, Self::Error> {
        Ok(Self {
            oid: value.pszObjId.to_string_safe()?,
            data: unsafe {
                slice::from_raw_parts(value.rgValue, value.cValue as _)
                    .iter()
                    .map(|rg| slice::from_raw_parts(rg.pbData, rg.cbData as _).to_vec())
                    .collect()
            },
        })
    }
}

impl TryFrom<&CMSG_SIGNER_INFO> for SignerInfo {
    type Error = anyhow::Error;

    fn try_from(value: &CMSG_SIGNER_INFO) -> Result<Self, Self::Error> {
        Ok(Self {
            issuer: cert_name_blob_to_str(X509_ASN_ENCODING, &value.Issuer, CERT_SIMPLE_NAME_STR)?,
            serial_number: unsafe { slice::from_raw_parts(value.SerialNumber.pbData, value.SerialNumber.cbData as _) }
                .to_vec(),
            authenticated_attributes: unsafe {
                slice::from_raw_parts(value.AuthAttrs.rgAttr, value.AuthAttrs.cAttr as _)
                    .iter()
                    .map(CryptAttribute::try_from)
                    .collect::<Result<_>>()?
            },
            unauthenticated_attributes: unsafe {
                slice::from_raw_parts(value.UnauthAttrs.rgAttr, value.UnauthAttrs.cAttr as _)
                    .iter()
                    .map(CryptAttribute::try_from)
                    .collect::<Result<_>>()?
            },
        })
    }
}

impl TryFrom<&CERT_EXTENSION> for CertificateExtension {
    type Error = anyhow::Error;

    fn try_from(value: &CERT_EXTENSION) -> Result<Self, Self::Error> {
        Ok(Self {
            oid: value.pszObjId.to_string_safe()?,
            critical: value.fCritical.as_bool(),
            data: unsafe { slice::from_raw_parts(value.Value.pbData, value.Value.cbData as _) }.to_vec(),
        })
    }
}

impl TryFrom<&CERT_INFO> for CertificateInfo {
    type Error = anyhow::Error;

    fn try_from(value: &CERT_INFO) -> Result<Self, Self::Error> {
        Ok(Self {
            version: match value.dwVersion {
                CERT_V1 => Ok(CertificateVersion::V1),
                CERT_V2 => Ok(CertificateVersion::V2),
                CERT_V3 => Ok(CertificateVersion::V3),
                _ => Err(anyhow!(Error::from_win32(ERROR_INVALID_VARIANT))),
            }?,
            serial_number: unsafe {
                slice::from_raw_parts(value.SerialNumber.pbData, value.SerialNumber.cbData as _).to_vec()
            },
            issuer: cert_name_blob_to_str(X509_ASN_ENCODING, &value.Issuer, CERT_SIMPLE_NAME_STR)?,
            subject: cert_name_blob_to_str(X509_ASN_ENCODING, &value.Subject, CERT_SIMPLE_NAME_STR)?,
            extensions: unsafe { slice::from_raw_parts(value.rgExtension, value.cExtension as _) }
                .iter()
                .map(CertificateExtension::try_from)
                .collect::<Result<_>>()?,
        })
    }
}

impl TryFrom<&CERT_CONTEXT> for CertificateContext {
    type Error = anyhow::Error;

    fn try_from(value: &CERT_CONTEXT) -> Result<Self, Self::Error> {
        Ok(Self {
            encoding_type: match value.dwCertEncodingType {
                X509_ASN_ENCODING => Ok(CertificateEncodingType::X509Asn),
                PKCS_7_ASN_ENCODING => Ok(CertificateEncodingType::Pkcs7Asn),
                _ => Err(anyhow!(Error::from_win32(ERROR_INVALID_VARIANT))),
            }?,
            encoded: unsafe { slice::from_raw_parts(value.pbCertEncoded, value.cbCertEncoded as _).to_vec() },
            info: unsafe { value.pCertInfo.as_ref() }.map_or_else(
                || bail!(Error::NullPointer("pCertInfo")),
                |x| CertificateInfo::try_from(x),
            )?,
            eku: cert_ctx_eku(value)?,
        })
    }
}

impl TryFrom<&CRYPT_PROVIDER_CERT> for CryptProviderCertificate {
    type Error = anyhow::Error;

    fn try_from(value: &CRYPT_PROVIDER_CERT) -> Result<Self, Self::Error> {
        Ok(Self {
            cert: unsafe { value.pCert.as_ref() }
                .ok_or_else(|| Error::NullPointer("pCert"))?
                .try_into()?,
            commercial: value.fCommercial.as_bool(),
            trusted_root: value.fTrustedRoot.as_bool(),
            self_signed: value.fSelfSigned.as_bool(),
            test_cert: value.fTestCert.as_bool(),
        })
    }
}

impl TryFrom<&CRYPT_PROVIDER_SGNR> for CryptProviderSigner {
    type Error = anyhow::Error;

    fn try_from(value: &CRYPT_PROVIDER_SGNR) -> Result<Self, Self::Error> {
        Ok(Self {
            signer: unsafe { value.psSigner.as_ref() }
                .map_or_else(|| bail!(Error::NullPointer("psSigner")), |x| SignerInfo::try_from(x))?,
            cert_chain: unsafe {
                slice::from_raw_parts(value.pasCertChain, value.csCertChain as _)
                    .iter()
                    .map(CryptProviderCertificate::try_from)
                    .collect::<Result<_>>()?
            },
        })
    }
}

impl TryFrom<&CRYPT_PROVIDER_DATA> for CryptProviderData {
    type Error = anyhow::Error;

    fn try_from(value: &CRYPT_PROVIDER_DATA) -> Result<Self, Self::Error> {
        Ok(Self {
            signers: unsafe {
                slice::from_raw_parts(value.pasSigners, value.csSigners as _)
                    .iter()
                    .map(|x| CryptProviderSigner::try_from(x))
                    .collect::<Result<_>>()?
            },
        })
    }
}

pub fn cert_name_blob_to_str(
    encoding: CERT_QUERY_ENCODING_TYPE,
    value: &CRYPT_INTEGER_BLOB,
    string_type: CERT_STRING_TYPE,
) -> Result<String> {
    let required_size = unsafe { CertNameToStrW(encoding, value, string_type, None) };

    let mut buf = vec![0; required_size as _];
    unsafe {
        let converted_bytes = CertNameToStrW(X509_ASN_ENCODING, value, string_type, Some(buf.as_mut_slice()));

        if converted_bytes as usize != buf.len() || buf.len() < 1 {
            bail!(Error::from_win32(ERROR_INCORRECT_SIZE));
        }

        // Trailing null byte needs to be removed
        buf.set_len(buf.capacity() - 1)
    }

    Ok(String::from_utf16(&buf)?)
}

pub fn cert_ctx_eku(ctx: &CERT_CONTEXT) -> Result<Vec<String>> {
    let mut required_size = 0;

    unsafe {
        CertGetEnhancedKeyUsage(ctx, 0, None, &mut required_size)?;
    }

    let mut raw_buf = vec![0u8; required_size as _];

    unsafe {
        CertGetEnhancedKeyUsage(ctx, 0, Some(raw_buf.as_mut_ptr() as _), &mut required_size)?;

        let ctl_usage = raw_buf.as_ptr().cast::<CTL_USAGE>().read();

        Ok(
            slice::from_raw_parts(ctl_usage.rgpszUsageIdentifier, ctl_usage.cUsageIdentifier as _)
                .iter()
                .filter_map(|id| id.to_string_safe().ok())
                .collect(),
        )
    }
}
