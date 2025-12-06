use camino::Utf8PathBuf;
use thiserror::Error;
use uuid::Uuid;

use crate::updater::Product;

#[derive(Debug, Error)]
pub(crate) enum UpdaterError {
    #[error("queried `{product}` artifact hash has invalid format: `{hash}`")]
    HashEncoding { product: Product, hash: String },
    #[error(
        "integrity check for downloaded `{product}` artifact has failed, expected hash: `{expected_hash}`, actual hash: `{actual_hash}`"
    )]
    IntegrityCheck {
        product: Product,
        expected_hash: String,
        actual_hash: String,
    },
    #[error("failed to validate `{product}` MSI signature. MSI path: `{msi_path}`")]
    MsiSignature { product: Product, msi_path: Utf8PathBuf },
    #[error("failed to calculate MSI certificate hash for `{product}`. MSI path: `{msi_path}`")]
    MsiCertHash { product: Product, msi_path: Utf8PathBuf },
    #[error(
        "MSI for `{product}` is signed with invalid non-Devolutions certificate. Certificate thumbprint: `{thumbprint}`"
    )]
    MsiCertificateThumbprint { product: Product, thumbprint: String },
    #[error("failed to install `{product}` MSI. Path: `{msi_path}`")]
    MsiInstall { product: Product, msi_path: Utf8PathBuf },
    #[error("failed to uninstall `{product}` MSI. Produc code: `{product_code}`")]
    MsiUninstall { product: Product, product_code: Uuid },
    #[error("ACL string `{acl}` is invalid")]
    AclString { acl: String },
    #[error("failed to set permissions for file: `{file_path}`")]
    SetFilePermissions { file_path: Utf8PathBuf },
    #[error(
        "could not find required file in productinfo.json for product `{product}` (arch: {arch}, type: {file_type})"
    )]
    ProductFileNotFound {
        product: String,
        arch: String,
        file_type: String,
    },
    #[error("download URL for `{product}` is not from official CDN: `{url}`")]
    UnsafeUrl { product: Product, url: String },
    #[error(transparent)]
    WindowsRegistry(#[from] devolutions_agent_shared::windows::registry::RegistryError),
    #[error("missing registry value")]
    MissingRegistryValue,
    #[error("failed to download file at {url}")]
    FileDownload { source: reqwest::Error, url: String },
    #[error("invalid UTF-8")]
    Utf8,
    #[error("IO error")]
    Io(#[from] std::io::Error),
    #[error("process does not have required rights to install MSI")]
    NotElevated,
    #[error("failed to query service state for `{product}`")]
    QueryServiceState { product: Product, source: anyhow::Error },
    #[error("failed to start service for `{product}`")]
    StartService { product: Product, source: anyhow::Error },
}
