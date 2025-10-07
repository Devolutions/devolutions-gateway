use uuid::Uuid;

use crate::DateVersion;
use crate::windows::reversed_hex_uuid::{InvalidReversedHexUuid, reversed_hex_to_uuid, uuid_to_reversed_hex};

const REG_CURRENT_VERSION: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion";

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("failed to open registry key `{key}`")]
    OpenKey { key: String, source: windows_result::Error },
    #[error("failed to enumerate registry key values from `{key}`")]
    EnumKeyValues { key: String, source: windows_result::Error },
    #[error("failed to read registry value `{value}` from key `{key}`")]
    ReadValue {
        value: String,
        key: String,
        source: windows_result::Error,
    },
    #[error(transparent)]
    InvalidReversedHexUuid(#[from] InvalidReversedHexUuid),
}

/// Get the product code of an installed MSI using its upgrade code.
pub fn get_product_code(update_code: Uuid) -> Result<Option<Uuid>, RegistryError> {
    let reversed_hex_uuid = uuid_to_reversed_hex(update_code);

    let key_path = format!("{REG_CURRENT_VERSION}\\Installer\\UpgradeCodes\\{reversed_hex_uuid}");

    let update_code_key = windows_registry::LOCAL_MACHINE.open(&key_path);

    // Product not installed if no key found.
    let update_code_key = match update_code_key {
        Ok(key) => key,
        Err(_) => return Ok(None),
    };

    // Product code is the name of the only value in the registry key.
    let (product_code, _) = match update_code_key
        .values()
        .map_err(|source| RegistryError::EnumKeyValues { key: key_path, source })?
        .next()
    {
        Some(value) => value,
        None => return Ok(None),
    };

    Ok(Some(reversed_hex_to_uuid(&product_code)?))
}

pub enum ProductVersionEncoding {
    Agent,
    Rdm,
}

/// Get the installed version of a product using Windows registry. Returns `None` if the product
/// is not installed.
pub fn get_installed_product_version(
    update_code: Uuid,
    version_encoding: ProductVersionEncoding,
) -> Result<Option<DateVersion>, RegistryError> {
    let product_code_uuid = match get_product_code(update_code)? {
        Some(uuid) => uuid,
        None => return Ok(None),
    }
    .braced();

    let key_path = format!("{REG_CURRENT_VERSION}\\Uninstall\\{product_code_uuid}");

    const VERSION_VALUE_NAME: &str = "Version";

    // Now we know the product code of installed MSI, we could read its version.
    let product_tree = windows_registry::LOCAL_MACHINE
        .open(&key_path)
        .map_err(|source| RegistryError::OpenKey {
            key: key_path.clone(),
            source,
        })?;

    let product_version: u32 = product_tree
        .get_value(VERSION_VALUE_NAME)
        .and_then(TryInto::try_into)
        .map_err(|source| RegistryError::ReadValue {
            value: VERSION_VALUE_NAME.to_owned(),
            key: key_path.clone(),
            source,
        })?;

    // Convert encoded MSI version number to human-readable date.
    let short_year = match version_encoding {
        ProductVersionEncoding::Agent => (product_version >> 24) + 2000,
        ProductVersionEncoding::Rdm => (product_version >> 24) + 0x700,
    };
    let month = (product_version >> 16) & 0xFF;
    let day = product_version & 0xFFFF;

    Ok(Some(DateVersion {
        year: short_year,
        month,
        day,
        // NOTE: Windows apps could only have 3 version numbers (major, minor, patch).
        revision: 0,
    }))
}

/// Get the installation location of a product using Windows registry. Returns `None` if the product
/// is not installed or if the InstallLocation value is not present.
pub fn get_install_location(update_code: Uuid) -> Result<Option<String>, RegistryError> {
    let product_code_uuid = match get_product_code(update_code)? {
        Some(uuid) => uuid,
        None => return Ok(None),
    }
    .braced();

    let key_path = format!("{REG_CURRENT_VERSION}\\Uninstall\\{product_code_uuid}");

    const INSTALL_LOCATION_VALUE_NAME: &str = "InstallLocation";

    // Now we know the product code of installed MSI, we could read its install location.
    let product_tree = windows_registry::LOCAL_MACHINE
        .open(&key_path)
        .map_err(|source| RegistryError::OpenKey {
            key: key_path.clone(),
            source,
        })?;

    let install_location: String = product_tree
        .get_value(INSTALL_LOCATION_VALUE_NAME)
        .and_then(TryInto::try_into)
        .map_err(|source| RegistryError::ReadValue {
            value: INSTALL_LOCATION_VALUE_NAME.to_owned(),
            key: key_path.clone(),
            source,
        })?;

    Ok(Some(install_location))
}
