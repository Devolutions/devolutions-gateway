//!  Module which provides logic to detect installed products and their versions.
use uuid::Uuid;

use devolutions_agent_shared::windows::{registry, GATEWAY_UPDATE_CODE};
use devolutions_agent_shared::DateVersion;

use crate::updater::{Product, UpdaterError};

/// Get the installed version of a product.
pub(crate) fn get_installed_product_version(product: Product) -> Result<Option<DateVersion>, UpdaterError> {
    match product {
        Product::Gateway => {
            registry::get_installed_product_version(GATEWAY_UPDATE_CODE).map_err(UpdaterError::WindowsRegistry)
        }
    }
}

pub(crate) fn get_product_code(product: Product) -> Result<Option<Uuid>, UpdaterError> {
    match product {
        Product::Gateway => registry::get_product_code(GATEWAY_UPDATE_CODE).map_err(UpdaterError::WindowsRegistry),
    }
}
