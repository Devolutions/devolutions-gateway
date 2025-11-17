mod detect;
mod error;
mod integrity;
mod io;
mod package;
mod product;
mod product_actions;
mod productinfo;
mod security;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_agent_shared::{DateVersion, UpdateJson, VersionSpecification, get_updater_file_path};
use devolutions_gateway_task::{ShutdownSignal, Task};
use notify_debouncer_mini::notify::RecursiveMode;
use tokio::fs;
use uuid::Uuid;

use self::detect::get_product_code;
use self::integrity::validate_artifact_hash;
use self::io::{download_binary, download_utf8, save_to_temp_file};
use self::package::{install_package, uninstall_package, validate_package};
use self::product_actions::{ProductUpdateActions, build_product_actions};
use self::productinfo::DEVOLUTIONS_PRODUCTINFO_URL;
use self::security::set_file_dacl;
use crate::config::ConfHandle;

pub(crate) use self::error::UpdaterError;
pub(crate) use self::product::Product;

const UPDATE_JSON_WATCH_INTERVAL: Duration = Duration::from_secs(3);

// List of updateable products could be extended in future
const PRODUCTS: &[Product] = &[Product::Gateway, Product::HubService];

/// Context for updater task
struct UpdaterCtx {
    product: Product,
    actions: Box<dyn ProductUpdateActions + Send + Sync + 'static>,
    conf: ConfHandle,
}

struct DowngradeInfo {
    installed_version: DateVersion,
    product_code: Uuid,
}

struct UpdateOrder {
    target_version: DateVersion,
    downgrade: Option<DowngradeInfo>,
    package_source: PackageSource,
}

enum PackageSource {
    Remote { url: String, hash: Option<String> },
    Local { path: String },
}

pub struct UpdaterTask {
    conf_handle: ConfHandle,
}

impl UpdaterTask {
    pub fn new(conf_handle: ConfHandle) -> Self {
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

    let mut ctx = UpdaterCtx {
        product,
        actions: build_product_actions(product),
        conf,
    };

    let package_path = match order.package_source {
        PackageSource::Remote { url, hash } => {
            info!(%product, %target_version, "Downloading package from remote URL");

            let package_data = download_binary(&url)
                .await
                .with_context(|| format!("failed to download package file for `{product}`"))?;

            let package_path = save_to_temp_file(&package_data, Some(product.get_package_extension())).await?;

            info!(%product, %target_version, %package_path, "Downloaded product installer");

            if let Some(hash) = hash {
                validate_artifact_hash(&ctx, &package_data, &hash)
                    .context("failed to validate package file integrity")?;
            }

            package_path
        }
        PackageSource::Local { path } => {
            info!(%product, %target_version, %path, "Using local package file (skipping download and checksum verification)");

            // Convert to Utf8PathBuf and verify the file exists
            let local_path = Utf8PathBuf::from(&path);
            if !local_path.exists() {
                return Err(anyhow!("Local package file does not exist: {}", path));
            }

            local_path
        }
    };

    //validate_package(&ctx, &package_path).context("failed to validate package contents")?;

    if ctx.conf.get_conf().debug.skip_msi_install {
        warn!(%product, "DEBUG MODE: Skipping package installation due to debug configuration");
        return Ok(());
    }

    ctx.actions.pre_update()?;

    if let Some(downgrade) = order.downgrade {
        let installed_version = downgrade.installed_version;
        info!(%product, %installed_version, %target_version, "Downgrading product...");

        let uninstall_log_path = package_path.with_extension("uninstall.log");

        // NOTE: An uninstall/reinstall will lose any custom feature selection or other options in the existing installation
        uninstall_package(&ctx, downgrade.product_code, &uninstall_log_path).await?;
    }

    let log_path = package_path.with_extension("log");

    install_package(&ctx, &package_path, &log_path)
        .await
        .context("failed to install package")?;

    ctx.actions.post_update()?;

    info!(%product, %target_version, "Product updated!");

    Ok(())
}

async fn read_update_json(update_file_path: &Utf8Path) -> anyhow::Result<UpdateJson> {
    let update_json_data = fs::read(update_file_path)
        .await
        .context("failed to read update.json file")?;

    // Strip UTF-8 BOM if present (some editors add it)
    let data_without_bom = if update_json_data.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &update_json_data[3..]
    } else {
        &update_json_data
    };

    let update_json: UpdateJson =
        serde_json::from_slice(data_without_bom).context("failed to parse update.json file")?;

    Ok(update_json)
}

async fn check_for_updates(product: Product, update_json: &UpdateJson) -> anyhow::Result<Option<UpdateOrder>> {
    let update_info = match product.get_update_info(update_json) {
        Some(info) => info,
        None => {
            trace!(%product, "No target version specified in update.json, skipping update check");
            return Ok(None);
        }
    };

    let target_version = update_info.target_version;
    let local_package_path = update_info.local_package_path;

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

    // If a local package path is provided, use it directly
    if let Some(local_path) = local_package_path {
        info!(%product, %local_path, "Using local package file, skipping remote checks");

        let target_version = match target_version {
            VersionSpecification::Specific(version) => version,
            VersionSpecification::Latest => {
                // For local packages with "latest", we can't determine the actual version
                // from the file without unpacking it, so we'll assume it's newer and proceed
                warn!(%product, "Using local package with 'latest' version specification - cannot verify version without installation");
                // Use a dummy future version to ensure update proceeds
                DateVersion {
                    year: 9999,
                    month: 12,
                    day: 31,
                    revision: 0,
                }
            }
        };

        // For local packages, we still check if downgrade is needed
        let downgrade = if target_version < detected_version {
            let product_code = get_product_code(product)?.ok_or(UpdaterError::MissingRegistryValue)?;
            Some(DowngradeInfo {
                installed_version: detected_version,
                product_code,
            })
        } else {
            None
        };

        return Ok(Some(UpdateOrder {
            target_version,
            downgrade,
            package_source: PackageSource::Local { path: local_path },
        }));
    }

    match target_version {
        VersionSpecification::Specific(target) if target == detected_version => {
            // Early exit without checking remote database.
            info!(%product, %detected_version, "Product is up to date, skipping update");
            return Ok(None);
        }
        VersionSpecification::Latest | VersionSpecification::Specific(_) => {}
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

            Ok(Some(UpdateOrder {
                target_version: remote_version,
                downgrade: None,
                package_source: PackageSource::Remote {
                    url: product_info.url.clone(),
                    hash: product_info.hash.clone(),
                },
            }))
        }
        VersionSpecification::Specific(version) => {
            // If the target version is not available on devolutions.net, try to guess the requested
            // version MSI URL by modifying the detected version.
            //
            // TODO(@pacmancoder): This is a temporary workaround until we have improved productinfo
            // database with multiple version information.
            let package_url = if version == remote_version {
                product_info.url.clone()
            } else {
                try_modify_product_url_version(&product_info.url, remote_version, version)?
            };

            // Quick check if the package URL points to existing resource.
            let response = reqwest::Client::builder().build()?.head(&package_url).send().await?;
            if let Err(error) = response.error_for_status() {
                warn!(
                    %error,
                    %product,
                    %version,
                    %package_url,
                    "Failed to access the product URL, skipping update"
                );
                return Ok(None);
            }
            // Target MSI found, proceed with update.

            // For the downgrade, we remove the installed product and install the target
            // version. This is the simplest and more reliable way to handle downgrades. (WiX
            // downgrade is not used).
            let downgrade = if version < detected_version {
                let product_code = get_product_code(product)?.ok_or(UpdaterError::MissingRegistryValue)?;

                Some(DowngradeInfo {
                    installed_version: detected_version,
                    product_code,
                })
            } else {
                None
            };

            Ok(Some(UpdateOrder {
                target_version: version,
                downgrade,
                package_source: PackageSource::Remote {
                    url: package_url,
                    hash: None,
                },
            }))
        }
    }
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
        return Err(anyhow!("product URL has unexpected format, version cannot be modified"));
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

        let new_url = try_modify_product_url_version(url, original_version, target_version)
            .expect("failed to modify product URL version");
        assert_eq!(
            new_url,
            "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2024.4.0.0.msi"
        );
    }
}
