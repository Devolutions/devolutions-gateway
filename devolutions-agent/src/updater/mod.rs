mod detect;
mod error;
mod integrity;
mod io;
mod package;
mod product;
mod productinfo;
mod security;
mod uuid;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use notify_debouncer_mini::notify::RecursiveMode;
use tokio::fs;

use devolutions_agent_shared::{get_updater_file_path, DateVersion, UpdateJson, VersionSpecification};
use devolutions_gateway_task::{ShutdownSignal, Task};

use crate::config::ConfHandle;

use integrity::validate_artifact_hash;
use io::{download_binary, download_utf8, save_to_temp_file};
use package::{install_package, validate_package};
use productinfo::DEVOLUTIONS_PRODUCTINFO_URL;
use security::set_file_dacl;

pub(crate) use error::UpdaterError;
pub(crate) use product::Product;

const UPDATE_JSON_WATCH_INTERVAL: Duration = Duration::from_secs(3);

// List of updateable products could be extended in future
const PRODUCTS: &[Product] = &[Product::Gateway];

/// Context for updater task
struct UpdaterCtx {
    product: Product,
    conf: ConfHandle,
}

struct UpdateOrder {
    target_version: DateVersion,
    package_url: String,
    hash: Option<String>,
}

pub(crate) struct UpdaterTask {
    conf_handle: ConfHandle,
}

impl UpdaterTask {
    pub(crate) fn new(conf_handle: ConfHandle) -> Self {
        Self { conf_handle }
    }
}

#[async_trait]
impl Task for UpdaterTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "updater";

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        let conf = self.conf_handle.clone();

        // Initialize update.json file if does not exist
        let update_file_path = init_update_json().await?;

        let file_change_notification = Arc::new(tokio::sync::Notify::new());
        let file_change_tx = Arc::clone(&file_change_notification);

        let mut notify_debouncer =
            notify_debouncer_mini::new_debouncer(UPDATE_JSON_WATCH_INTERVAL, move |result| match result {
                Ok(_) => {
                    let _ = file_change_tx.notify_waiters();
                }
                Err(error) => {
                    error!(%error, "Failed to watch update.json file");
                }
            })
            .context("failed to create file notify debouncer")?;

        notify_debouncer
            .watcher()
            .watch(update_file_path.as_std_path(), RecursiveMode::NonRecursive)
            .context("failed to start update file watcher")?;

        // Trigger initial check during task startup
        file_change_notification.notify_waiters();

        loop {
            tokio::select! {
                _ = file_change_notification.notified() => {
                    info!("update.json file changed, checking for updates...");


                    let update_json = match read_update_json(&update_file_path).await {
                        Ok(update_json) => update_json,
                        Err(error) => {
                            error!(%error, "Failed to parse `update.json`");
                            // Allow this error to be non-critical, as this file could be
                            // updated later to be valid again
                            continue;
                        }
                    };

                    let mut update_orders = vec![];

                    for product in PRODUCTS {
                        let update_order = match check_for_updates(*product, &update_json).await {
                            Ok(order) => order,
                            Err(error) => {
                                error!(%product, %error, "Failed to check for updates for a product.");
                                continue;
                            }
                        };

                        if let Some(order) = update_order {
                            update_orders.push((*product, order));
                        }
                    }

                    if update_orders.is_empty() {
                        info!("No updates available for any product");
                    }

                    for (product, order) in update_orders {
                        if let Err(error) = update_product(conf.clone(), product, order).await {
                            error!(%product, %error, "Failed to update product");
                        }
                    }
                }
                _ = shutdown_signal.wait() => {
                    break;
                }
            }
        }

        Ok(())
    }
}

async fn update_product(conf: ConfHandle, product: Product, order: UpdateOrder) -> anyhow::Result<()> {
    let target_version = order.target_version;
    let hash = order.hash;

    let package_data = download_binary(&order.package_url)
        .await
        .with_context(|| format!("failed to download package file for `{product}`"))?;

    let package_path = save_to_temp_file(&package_data, Some(product.get_package_extension())).await?;

    info!(%product, %target_version, %package_path, "Downloaded product Installer");

    let ctx = UpdaterCtx { product, conf };

    if let Some(hash) = hash {
        validate_artifact_hash(&ctx, &package_data, &hash).context("failed to validate package file integrity")?;
    }

    validate_package(&ctx, &package_path).context("failed to validate package contents")?;

    if ctx.conf.get_conf().debug.skip_msi_install {
        warn!(%product, "DEBUG MODE: Skipping package installation due to debug configuration");
        return Ok(());
    }

    install_package(&ctx, &package_path)
        .await
        .context("failed to install package")?;

    info!(%product, "Product updated to v{target_version}!");

    Ok(())
}

async fn read_update_json(update_file_path: &Utf8Path) -> anyhow::Result<UpdateJson> {
    let update_json_data = fs::read(update_file_path)
        .await
        .context("failed to read update.json file")?;
    let update_json: UpdateJson =
        serde_json::from_slice(&update_json_data).context("failed to parse update.json file")?;

    Ok(update_json)
}

async fn check_for_updates(product: Product, update_json: &UpdateJson) -> anyhow::Result<Option<UpdateOrder>> {
    let target_version = match product.get_update_info(update_json).map(|info| info.target_version) {
        Some(version) => version,
        None => {
            trace!(%product, "No target version specified in update.json, skipping update check");
            return Ok(None);
        }
    };

    let detected_version = match detect::get_installed_product_version(product) {
        Ok(Some(version)) => version,
        Ok(None) => {
            trace!(%product, "Product is not installed, skipping update check");
            return Ok(None);
        }
        Err(err) => {
            return Err(err.into());
        }
    };

    trace!(%product, %detected_version, "Detected installed product version");

    let is_target_version_same_as_insatlled = match target_version {
        VersionSpecification::Latest => false,
        VersionSpecification::Specific(target) => target == detected_version,
    };

    // Early exit without checking remote database.
    if is_target_version_same_as_insatlled {
        info!(%product, %detected_version, "Product is up to date, skipping update");
        return Ok(None);
    }

    info!(%product, %target_version, "Ready to update the product");

    let product_info_db = download_utf8(DEVOLUTIONS_PRODUCTINFO_URL)
        .await
        .context("failed to download productinfo database")?;

    let product_info_db: productinfo::ProductInfoDb = product_info_db.parse()?;

    let product_info = product_info_db
        .get(product.get_productinfo_id())
        .ok_or_else(|| anyhow!("product `{product}` info not found in remote database"))?;

    let remote_version = product_info.version.parse::<DateVersion>()?;

    match target_version {
        VersionSpecification::Latest => {
            if remote_version <= detected_version {
                info!(%product, %detected_version, "Product is up to date, skipping update (update to `latest` requested)");
                return Ok(None);
            }
        }
        VersionSpecification::Specific(version) => {
            if version == detected_version {
                info!(%product, %detected_version, "Product is up to date, skipping update");
                return Ok(None);
            }

            // If the target version is not available on devolutions.net, try to guess the requested
            // version MSI URL by modifying the detected version.
            //
            // TODO(@pacmancoder): This is a temporary workaround until we have improved productinfo
            // database with multiple version information.
            if version != remote_version {
                let modified_url = try_modify_product_url_version(&product_info.url, remote_version, version)?;

                // Quick check if the modified URL points to existing resource.
                let response = reqwest::Client::builder().build()?.head(&modified_url).send().await?;
                if !response.status().is_success() {
                    warn!(
                        %product,
                        %version,
                        %modified_url,
                        "Modified product URL does not exist, skipping update"
                    );
                    return Ok(None);
                }

                // Target MSI found, proceed with update.
                return Ok(Some(UpdateOrder {
                    target_version: version,
                    package_url: modified_url,
                    hash: None,
                }));
            }
        }
    }

    Ok(Some(UpdateOrder {
        target_version: remote_version,
        package_url: product_info.url.clone(),
        hash: product_info.hash.clone(),
    }))
}

async fn init_update_json() -> anyhow::Result<Utf8PathBuf> {
    let update_file_path = get_updater_file_path();

    let default_update_json =
        serde_json::to_string_pretty(&UpdateJson::default()).context("failed to serialize default update.json")?;

    fs::write(&update_file_path, default_update_json)
        .await
        .context("failed to write default update.json file")?;

    // Set permissions for update.json file:
    match set_file_dacl(&update_file_path, security::UPDATE_JSON_DACL) {
        Ok(_) => {
            info!("Created new `update.json` and set permissions successfully");
        }
        Err(err) => {
            // Remove update.json file if failed to set permissions
            std::fs::remove_file(update_file_path.as_std_path()).unwrap_or_else(
                |error| warn!(%error, "Failed to remove update.json file after failed permissions set"),
            );

            // Treat as fatal error
            return Err(anyhow!(err).context("failed to set update.json file permissions"));
        }
    }

    Ok(update_file_path)
}

/// Change the version in the URL to the target version.
///
/// Fails if the URL does not contain the original version.
///
/// Example:
/// - Original version: 2024.3.3.0
/// - Target version: 2024.4.0.0
/// - Original URL: https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2024.3.3.0.msi
/// - Modified URL: https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2024.4.0.0.msi
fn try_modify_product_url_version(
    url: &str,
    original_version: DateVersion,
    version: DateVersion,
) -> anyhow::Result<String> {
    let new_url = url.replace(&original_version.to_string(), &version.to_string());

    if new_url == url {
        return Err(anyhow!("Product URL has unexpected format, version cannot be modified"));
    }

    Ok(new_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_modify_product_url_version() {
        let url = "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2024.3.3.0.msi";
        let original_version = DateVersion {
            year: 2024,
            month: 3,
            day: 3,
            revision: 0,
        };
        let target_version = DateVersion {
            year: 2024,
            month: 4,
            day: 0,
            revision: 0,
        };

        let new_url = try_modify_product_url_version(url, original_version, target_version).unwrap();
        assert_eq!(
            new_url,
            "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2024.4.0.0.msi"
        );
    }
}
