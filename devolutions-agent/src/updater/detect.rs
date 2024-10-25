//!  Module which provides logic to detect installed products and their versions.

use devolutions_agent_shared::DateVersion;

use crate::updater::uuid::{reversed_hex_to_uuid, uuid_to_reversed_hex};
use crate::updater::{Product, UpdaterError};

const GATEWAY_UPDATE_CODE: &str = "{db3903d6-c451-4393-bd80-eb9f45b90214}";

/// Get the installed version of a product.
pub(crate) fn get_installed_product_version(product: Product) -> Result<Option<DateVersion>, UpdaterError> {
    match product {
        Product::Gateway => get_instaled_product_version_winreg(GATEWAY_UPDATE_CODE),
    }
}

/// Get the installed version of a product using Windows registry.
fn get_instaled_product_version_winreg(update_code: &str) -> Result<Option<DateVersion>, UpdaterError> {
    let reversed_hex_uuid = uuid_to_reversed_hex(update_code)?;

    const REG_CURRENT_VERSION: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion";

    let update_code_key = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(format!(
            "{REG_CURRENT_VERSION}\\Installer\\UpgradeCodes\\{reversed_hex_uuid}"
        ))
        .ok();

    // Product not installed if no key found.
    let update_code_key = match update_code_key {
        Some(key) => key,
        None => return Ok(None),
    };

    // Product code is the name of the only value in the registry key.
    let (product_code, _) = match update_code_key.enum_values().next() {
        Some(value) => value.map_err(UpdaterError::WindowsRegistry)?,
        None => return Err(UpdaterError::MissingRegistryValue),
    };

    let product_code_uuid = reversed_hex_to_uuid(&product_code)?;

    // Now we know the product code of installed MSI, we could read its version.
    let product_tree = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(format!("{REG_CURRENT_VERSION}\\Uninstall\\{product_code_uuid}"))
        .map_err(UpdaterError::WindowsRegistry)?;

    let product_version: u32 = product_tree
        .get_value("Version")
        .map_err(UpdaterError::WindowsRegistry)?;

    // Convert encoded MSI version number to human-readable date.
    let short_year = (product_version >> 24) + 2000;
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
