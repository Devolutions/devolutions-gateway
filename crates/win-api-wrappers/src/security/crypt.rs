use std::ffi::{OsString, c_void};
use std::fmt::Debug;
use std::fs::File;
use std::io::{Seek as _, SeekFrom};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{Result, anyhow, bail};
use windows::Win32::Foundation::{
    CRYPT_E_BAD_MSG, ERROR_INCORRECT_SIZE, ERROR_INVALID_VARIANT, HANDLE, HWND, INVALID_HANDLE_VALUE, NTE_BAD_ALGID,
    S_OK, TRUST_E_BAD_DIGEST, TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN,
};
use windows::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash,
    CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows::Win32::Security::Cryptography::{
    BCRYPT_SHA256_ALGORITHM, CERT_CONTEXT, CERT_EXTENSION, CERT_INFO, CERT_QUERY_ENCODING_TYPE, CERT_SIMPLE_NAME_STR,
    CERT_STRING_TYPE, CERT_V1, CERT_V2, CERT_V3, CMSG_SIGNER_INFO, CRYPT_ATTRIBUTE, CRYPT_INTEGER_BLOB, CTL_USAGE,
    CertGetEnhancedKeyUsage, CertNameToStrW, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows::Win32::Security::WinTrust::{
    CRYPT_PROVIDER_CERT, CRYPT_PROVIDER_DATA, CRYPT_PROVIDER_SGNR, WINTRUST_ACTION_GENERIC_VERIFY_V2,
    WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
    WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_USE_DEFAULT_OSVER_CHECK, WTHelperProvDataFromStateData, WinVerifyTrustEx,
};
use windows::core::HRESULT;

use crate::Error;
use crate::utils::{SafeWindowsString, WideString, nul_slice_wide_str, slice_from_ptr, u32size_of};

pub struct CatalogInfo {
    pub path: PathBuf,
    pub hash: Vec<u8>,
    pub admin_context: Rc<CatalogAdminContext>,
}

impl CatalogInfo {
    pub fn try_from_file(path: &Path) -> Result<Option<Self>> {
        let file = File::open(path)?;
        Self::try_from_file_handle(&file)
    }

    /// Resolve catalog metadata from the exact retained file object.
    pub fn try_from_file_handle(file: &File) -> Result<Option<Self>> {
        let admin_context = Rc::new(CatalogAdminContext::try_new()?);

        let hash = admin_context.hash_file_handle(file)?;

        let catalog_path = {
            let mut catalogs = admin_context.catalogs_for_hash(&hash);
            catalogs.next()
        };

        Ok(catalog_path.map(|catalog_path| Self {
            hash,
            path: catalog_path,
            admin_context,
        }))
    }
}

fn wintrust_catalog_info(
    catalog_info: &CatalogInfo,
    catalog_path: &WideString,
    member_path: &WideString,
    member_tag: &WideString,
    file: &File,
) -> WINTRUST_CATALOG_INFO {
    WINTRUST_CATALOG_INFO {
        cbStruct: u32size_of::<WINTRUST_CATALOG_INFO>(),
        pcwszCatalogFilePath: catalog_path.as_pcwstr(),
        pcwszMemberFilePath: member_path.as_pcwstr(),
        pcwszMemberTag: member_tag.as_pcwstr(),
        hMemberFile: HANDLE(file.as_raw_handle().cast()),
        hCatAdmin: catalog_info.admin_context.handle.0 as isize,
        ..Default::default()
    }
}

fn wintrust_file_info(path: &WideString, file: &File) -> WINTRUST_FILE_INFO {
    WINTRUST_FILE_INFO {
        cbStruct: u32size_of::<WINTRUST_FILE_INFO>(),
        pcwszFilePath: path.as_pcwstr(),
        hFile: HANDLE(file.as_raw_handle().cast()),
        ..Default::default()
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
/// https://stackoverflow.com/questions/68215779/getting-winverifytrust-to-work-with-catalog-signed-files-such-as-cmd-exe
/// https://github.com/dragokas/Verify-Signature-Cpp/blob/master/verify.cpp#L140
/// https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Security/CodeSigning/cpp/codesigning.cpp
pub fn win_verify_trust(path: &Path, catalog_info: Option<CatalogInfo>) -> Result<WinVerifyTrustResult> {
    let file = File::open(path)?;
    win_verify_trust_for_file(path, &file, catalog_info)
}

/// Verify the exact retained file object; `path` must identify that object and is retained
/// as WinTrust subject metadata.
pub fn win_verify_trust_for_file(
    path: &Path,
    file: &File,
    catalog_info: Option<CatalogInfo>,
) -> Result<WinVerifyTrustResult> {
    let path = WideString::from(path);
    let catalog_strings = catalog_info.as_ref().map(|catalog_info| {
        (
            WideString::from(&catalog_info.path),
            WideString::from(base16ct::upper::encode_string(&catalog_info.hash)),
        )
    });

    enum WintrustInfo {
        Catalog(WINTRUST_CATALOG_INFO),
        File(WINTRUST_FILE_INFO),
    }

    let mut wintrust_info = match (&catalog_info, &catalog_strings) {
        (Some(catalog_info), Some((catalog_path, member_tag))) => WintrustInfo::Catalog(wintrust_catalog_info(
            catalog_info,
            catalog_path,
            &path,
            member_tag,
            file,
        )),
        (None, None) => WintrustInfo::File(wintrust_file_info(&path, file)),
        _ => unreachable!("catalog info and derived strings are created together"),
    };

    let mut win_trust_data = WINTRUST_DATA {
        cbStruct: u32size_of::<WINTRUST_DATA>(),
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

    // SAFETY: No preconditions. Both `pgActionId` and `pWinTrustData` are valid.
    // `pWinTrustData` must rego through `WinVerifyTrustEx` with `WTD_STATEACTION_CLOSE` to close the opened objects.
    let status = unsafe { WinVerifyTrustEx(HWND(INVALID_HANDLE_VALUE.0), &mut guid, &mut win_trust_data) };

    let result = AuthenticodeSignatureStatus::try_from(HRESULT(status));
    let provider = if win_trust_data.hWVTStateData.is_invalid() {
        None
    } else {
        // SAFETY: No preconditions.
        let prov_data = unsafe { WTHelperProvDataFromStateData(win_trust_data.hWVTStateData) };

        // SAFETY: We assume that if the returned pointer is non null it points to a valid `CRYPT_PROVIDER_DATA`.
        unsafe { prov_data.as_ref() }.map(CryptProviderData::try_from)
    };

    win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;

    // SAFETY: No preconditions. Both `pgActionId` and `pWinTrustData` are valid.
    unsafe { WinVerifyTrustEx(HWND(INVALID_HANDLE_VALUE.0), &mut guid, &mut win_trust_data) };

    Ok(WinVerifyTrustResult {
        provider: provider.transpose()?,
        status: result.map_err(Error::from_hresult)?,
    })
}

#[derive(Debug)]
pub struct WinVerifyTrustResult {
    pub provider: Option<CryptProviderData>,
    pub status: AuthenticodeSignatureStatus,
}

pub fn authenticode_status(path: &Path) -> Result<WinVerifyTrustResult> {
    let file = File::open(path)?;
    authenticode_status_for_file(path, &file)
}

/// Read Authenticode status from the exact retained file object identified by `path`.
pub fn authenticode_status_for_file(path: &Path, file: &File) -> Result<WinVerifyTrustResult> {
    let catalog_info = CatalogInfo::try_from_file_handle(file)?;

    win_verify_trust_for_file(path, file, catalog_info)
}

pub struct CatalogAdminContext {
    pub handle: HANDLE,
}

impl CatalogAdminContext {
    pub fn try_new() -> Result<Self> {
        let mut handle = HANDLE::default();

        // TODO: Add more arguments to allow any usage.
        // SAFETY: No preconditions. Must be freed with CryptCATAdminReleaseContext.
        unsafe {
            CryptCATAdminAcquireContext2(
                &mut handle.0 as *mut _ as *mut isize,
                None,
                BCRYPT_SHA256_ALGORITHM,
                None,
                None,
            )
        }?;

        Ok(Self { handle })
    }

    pub fn hash_file(&self, path: &Path) -> Result<Vec<u8>> {
        let file = File::open(path)?;
        self.hash_file_handle(&file)
    }

    /// Hash the exact retained file object and reset its cursor to offset zero.
    pub fn hash_file_handle(&self, file: &File) -> Result<Vec<u8>> {
        // The output has a variable size.
        // Therefore, we must call CryptCATAdminCalcHashFromFileHandle2 once with a zero-size, and check for the ERROR_INSUFFICIENT_BUFFER status.
        // At this point, we call CryptCATAdminCalcHashFromFileHandle2 again with a buffer of the correct size.
        let mut cursor = file;
        cursor.seek(SeekFrom::Start(0))?;
        let mut required_size = 0u32;

        // SAFETY: `hFile` must not be NULL and must be a valid file pointer. The `file` is not dropped so it should be valid.
        unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                self.handle.0 as isize,
                HANDLE(file.as_raw_handle().cast()),
                &mut required_size,
                None,
                None,
            )
        }?;

        let mut allocated_length = required_size;
        let mut hash = vec![0u8; allocated_length as usize];

        // SAFETY: `hFile` must not be NULL and must be a valid file pointer. The `file` is not dropped so it should be valid.
        // `hash` is valid and is of the size `required_size`.
        unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                self.handle.0 as isize,
                HANDLE(file.as_raw_handle().cast()),
                &mut allocated_length,
                Some(hash.as_mut_ptr()),
                None,
            )
        }?;

        debug_assert_eq!(allocated_length, required_size);

        hash.truncate(required_size as usize);
        cursor.seek(SeekFrom::Start(0))?;

        Ok(hash)
    }

    pub fn catalogs_for_hash<'a>(&'a self, hash: &'a [u8]) -> CatalogIterator<'a> {
        CatalogIterator::new(self, hash)
    }
}

impl Drop for CatalogAdminContext {
    fn drop(&mut self) {
        // SAFETY: Handle is valid as it is created at construction of this object.
        let _ = unsafe { CryptCATAdminReleaseContext(self.handle.0 as isize, 0) };
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek as _, SeekFrom};

    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn catalog_hash_uses_retained_handle_and_resets_position() {
        let executable = std::env::current_exe().expect("current executable");
        let mut file = File::open(executable).expect("open current executable");
        file.seek(SeekFrom::Start(17)).expect("move retained handle position");
        let context = CatalogAdminContext::try_new().expect("create catalog context");

        let hash = context
            .hash_file_handle(&file)
            .expect("hash retained executable handle");

        assert!(!hash.is_empty());
        assert_eq!(file.stream_position().expect("query retained handle position"), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn catalog_wintrust_info_carries_live_sha256_context_and_member_handle() {
        let executable = std::env::current_exe().expect("current executable");
        let file = File::open(&executable).expect("open current executable");
        let admin_context = Rc::new(CatalogAdminContext::try_new().expect("create SHA-256 catalog context"));
        let catalog_info = CatalogInfo {
            path: PathBuf::from(r"C:\test\catalog.cat"),
            hash: vec![0xAB; 32],
            admin_context,
        };
        let catalog_path = WideString::from(&catalog_info.path);
        let member_path = WideString::from(&executable);
        let member_tag = WideString::from(base16ct::upper::encode_string(&catalog_info.hash));

        let native = wintrust_catalog_info(&catalog_info, &catalog_path, &member_path, &member_tag, &file);

        assert_eq!(native.hCatAdmin, catalog_info.admin_context.handle.0 as isize);
        assert_eq!(native.hMemberFile, HANDLE(file.as_raw_handle().cast()));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn embedded_wintrust_info_carries_retained_file_handle() {
        let executable = std::env::current_exe().expect("current executable");
        let file = File::open(&executable).expect("open current executable");
        let path = WideString::from(&executable);

        let native = wintrust_file_info(&path, &file);

        assert_eq!(native.hFile, HANDLE(file.as_raw_handle().cast()));
    }

    #[test]
    fn catalog_backed_signature_uses_retained_context_when_available() {
        let Some(windows_dir) = std::env::var_os("WINDIR") else {
            return;
        };
        let candidates = [
            PathBuf::from(&windows_dir).join(r"System32\cmd.exe"),
            PathBuf::from(&windows_dir).join(r"System32\WindowsPowerShell\v1.0\powershell.exe"),
            PathBuf::from(&windows_dir).join(r"System32\drivers\acpi.sys"),
        ];

        for path in candidates {
            let Ok(file) = File::open(&path) else {
                continue;
            };
            let Ok(Some(catalog_info)) = CatalogInfo::try_from_file_handle(&file) else {
                continue;
            };
            let result =
                win_verify_trust_for_file(&path, &file, Some(catalog_info)).expect("verify catalog-backed system file");
            assert!(matches!(result.status, AuthenticodeSignatureStatus::Valid));
            return;
        }
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
        // SAFETY: `hCatAdmin` must remain alive for the lifetime of this object.
        let new_ctx = unsafe {
            CryptCATAdminEnumCatalogFromHash(
                self.admin_ctx.handle.0 as isize,
                self.hash,
                None,
                self.cur.map(|mut x| &mut x.0 as *mut _ as *mut isize),
            )
        };

        if new_ctx == 0 {
            None
        } else {
            self.cur = Some(HANDLE(new_ctx as *mut c_void));

            let mut info = CATALOG_INFO {
                cbStruct: u32size_of::<CATALOG_INFO>(),
                ..Default::default()
            };

            // SAFETY: Nopreconditions. `new_ctx` is not NULL. `info` is not NULL and writeable.
            unsafe { CryptCATCatalogInfoFromContext(new_ctx, &mut info, 0) }.ok()?;

            Some(PathBuf::from(OsString::from_wide(nul_slice_wide_str(
                &info.wszCatalogFile,
            ))))
        }
    }
}

impl Drop for CatalogIterator<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.cur {
            // SAFETY: No preconditions. `hCatAdmin` and `hCatInfo` are both valid.
            let _ =
                unsafe { CryptCATAdminReleaseCatalogContext(self.admin_ctx.handle.0 as isize, handle.0 as isize, 0) };
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
            // SAFETY: We assume `value` is truthful about its members.
            data: unsafe { slice_from_ptr(value.rgValue, value.cValue as usize) }
                .iter()
                // SAFETY: We assume `rg` is truthful about its members.
                .map(|rg| unsafe { slice_from_ptr(rg.pbData, rg.cbData as usize) }.to_vec())
                .collect(),
        })
    }
}

impl TryFrom<&CMSG_SIGNER_INFO> for SignerInfo {
    type Error = anyhow::Error;

    fn try_from(value: &CMSG_SIGNER_INFO) -> Result<Self, Self::Error> {
        Ok(Self {
            issuer: cert_name_blob_to_str(X509_ASN_ENCODING, &value.Issuer, CERT_SIMPLE_NAME_STR)?,
            // SAFETY: We assume `value.SerialNumber` is truthful.
            serial_number: unsafe { slice_from_ptr(value.SerialNumber.pbData, value.SerialNumber.cbData as usize) }
                .to_vec(),
            // SAFETY: We assume `value.AuthAttrs` is truthful.
            authenticated_attributes: unsafe { slice_from_ptr(value.AuthAttrs.rgAttr, value.AuthAttrs.cAttr as usize) }
                .iter()
                .map(CryptAttribute::try_from)
                .collect::<Result<_>>()?,
            // SAFETY: We assume `value.UnauthAttrs` is truthful.
            unauthenticated_attributes: unsafe {
                slice_from_ptr(value.UnauthAttrs.rgAttr, value.UnauthAttrs.cAttr as usize)
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
            // SAFETY: We assume `value.Value` is truthful.
            data: unsafe { slice_from_ptr(value.Value.pbData, value.Value.cbData as usize) }.to_vec(),
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
            // SAFETY: We assume `value.SerialNumber` is truthful.
            serial_number: unsafe { slice_from_ptr(value.SerialNumber.pbData, value.SerialNumber.cbData as usize) }
                .to_vec(),
            issuer: cert_name_blob_to_str(X509_ASN_ENCODING, &value.Issuer, CERT_SIMPLE_NAME_STR)?,
            subject: cert_name_blob_to_str(X509_ASN_ENCODING, &value.Subject, CERT_SIMPLE_NAME_STR)?,
            // SAFETY: We assume `value.rgExtension` is truthful.
            extensions: unsafe { slice_from_ptr(value.rgExtension, value.cExtension as usize) }
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
            // SAFETY: We assume `value` is truthful.
            encoded: unsafe { slice_from_ptr(value.pbCertEncoded, value.cbCertEncoded as usize) }.to_vec(),
            // SAFETY: We assume that if `value.pCertInfo` is non NULL, it points to a valid `CERT_INFO`.
            info: unsafe { value.pCertInfo.as_ref() }
                .map_or_else(|| bail!(Error::NullPointer("pCertInfo")), CertificateInfo::try_from)?,
            eku: cert_ctx_eku(value)?,
        })
    }
}

impl TryFrom<&CRYPT_PROVIDER_CERT> for CryptProviderCertificate {
    type Error = anyhow::Error;

    fn try_from(value: &CRYPT_PROVIDER_CERT) -> Result<Self, Self::Error> {
        Ok(Self {
            // SAFETY: We assume that if `value.pCert` is non NULL, it points to a valid `CERT_CONTEXT`.
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
            // SAFETY: We assume that if `value.psSigner` is non NULL, it points to a valid `CMSG_SIGNER_INFO`.
            signer: unsafe { value.psSigner.as_ref() }
                .map_or_else(|| bail!(Error::NullPointer("psSigner")), SignerInfo::try_from)?,
            // SAFETY: We assume `value` is truthful.
            cert_chain: unsafe { slice_from_ptr(value.pasCertChain, value.csCertChain as usize) }
                .iter()
                .map(CryptProviderCertificate::try_from)
                .collect::<Result<_>>()?,
        })
    }
}

impl TryFrom<&CRYPT_PROVIDER_DATA> for CryptProviderData {
    type Error = anyhow::Error;

    fn try_from(value: &CRYPT_PROVIDER_DATA) -> Result<Self, Self::Error> {
        Ok(Self {
            // SAFETY: We assume `value` is truthful.
            signers: unsafe { slice_from_ptr(value.pasSigners, value.csSigners as usize) }
                .iter()
                .map(CryptProviderSigner::try_from)
                .collect::<Result<_>>()?,
        })
    }
}

pub fn cert_name_blob_to_str(
    encoding: CERT_QUERY_ENCODING_TYPE,
    value: &CRYPT_INTEGER_BLOB,
    string_type: CERT_STRING_TYPE,
) -> Result<String> {
    // SAFETY: We assume `value` is a valid `CERT_NAME_BLOB`.
    let required_size = unsafe { CertNameToStrW(encoding, value, string_type, None) };

    let mut buf = vec![0; required_size as usize];

    // SAFETY: We assume `value` is a valid `CERT_NAME_BLOB`.
    let converted_bytes = unsafe { CertNameToStrW(X509_ASN_ENCODING, value, string_type, Some(buf.as_mut_slice())) };

    if converted_bytes as usize != buf.len() || buf.is_empty() {
        bail!(Error::from_win32(ERROR_INCORRECT_SIZE));
    }

    Ok(String::from_utf16(nul_slice_wide_str(&buf))?)
}

pub fn cert_ctx_eku(ctx: &CERT_CONTEXT) -> Result<Vec<String>> {
    let mut required_size = 0;

    // SAFETY: `ctx` is valid. No preconditions.
    unsafe { CertGetEnhancedKeyUsage(ctx, 0, None, &mut required_size) }?;

    let mut raw_buf = vec![0u8; required_size as usize];

    // SAFETY: `ctx` is valid. No preconditions.
    unsafe { CertGetEnhancedKeyUsage(ctx, 0, Some(raw_buf.as_mut_ptr().cast()), &mut required_size) }?;

    if required_size as usize != raw_buf.len() {
        bail!(Error::from_win32(ERROR_INCORRECT_SIZE));
    }

    // SAFETY: We assume `CertGetEnhancedKeyUsage` actually wrote a valid `CTL_USAGE`.
    #[allow(clippy::cast_ptr_alignment)] // FIXME(DGW-221): Raw* hack is flawed.
    let ctl_usage = unsafe { raw_buf.as_ptr().cast::<CTL_USAGE>().read() };

    Ok(
        // SAFETY: We assume `ctl_usage` is truthful. We assume `ctl_usage` is big enough to fit the VLA.
        unsafe { slice_from_ptr(ctl_usage.rgpszUsageIdentifier, ctl_usage.cUsageIdentifier as usize) }
            .iter()
            .filter_map(|id| id.to_string_safe().ok())
            .collect(),
    )
}
