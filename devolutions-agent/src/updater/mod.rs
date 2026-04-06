mod detect;
mod error;
mod integrity;
mod io;
mod package;
mod product;
mod product_actions;
mod productinfo;
mod security;

/// Schedule a file for deletion on the next system reboot (best-effort).
///
/// Wraps the internal reboot-removal logic with an [`anyhow::Error`] return type for use
/// outside this crate.
pub fn remove_file_on_reboot(file_path: &Utf8Path) -> anyhow::Result<()> {
    io::remove_file_on_reboot(file_path).map_err(anyhow::Error::from)
}

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_agent_shared::{
    DateVersion, InstalledProductUpdateInfo, ProductUpdateInfo, UpdateManifest, UpdateManifestV2, UpdateProductKey,
    UpdateSchedule, UpdateStatus, UpdateStatusV2, VersionSpecification, get_update_status_file_path,
    get_updater_file_path,
};
use devolutions_gateway_task::{ShutdownSignal, Task};
use notify_debouncer_mini::notify::RecursiveMode;
use tokio::fs;
use uuid::Uuid;
use win_api_wrappers::service::{ServiceManager, ServiceStartupMode};

use self::detect::get_product_code;
pub(crate) use self::error::UpdaterError;
use self::integrity::validate_artifact_hash;
use self::io::{download_binary, download_utf8, save_to_temp_file};
use self::package::{install_package, uninstall_package, validate_package};
pub(crate) use self::product::Product;
use self::product_actions::{ProductUpdateActions, build_product_actions};
use self::productinfo::DEVOLUTIONS_PRODUCTINFO_URL;
use self::security::set_file_dacl;
use crate::config::ConfHandle;
use crate::config::dto::UpdaterSchedule;
use crate::updater::productinfo::ProductInfoDb;

/// Windows service name for Devolutions Agent.
pub const AGENT_SERVICE_NAME: &str = "DevolutionsAgent";

/// Service state captured before the MSI update begins, used to restore state afterwards.
pub struct AgentServiceState {
    pub was_running: bool,
    pub startup_was_automatic: bool,
}

/// Query the Devolutions Agent service state before the MSI update begins.
///
/// Called while the agent service is still running so startup mode and running state
/// reflect the pre-update configuration.
pub fn query_agent_service_state() -> anyhow::Result<AgentServiceState> {
    let sm = ServiceManager::open_read()?;
    let svc = sm.open_service_read(AGENT_SERVICE_NAME)?;
    Ok(AgentServiceState {
        startup_was_automatic: svc.startup_mode()? == ServiceStartupMode::Automatic,
        was_running: svc.is_running()?,
    })
}

/// Start the Devolutions Agent service after a successful update if its startup mode is manual.
///
/// Services configured for automatic startup are restarted by the Windows SCM after the MSI
/// completes. Services with manual startup must be started explicitly.
///
/// Returns `true` if the service was started, `false` if a start was not needed.
pub fn start_agent_service_if_needed(state: &AgentServiceState) -> anyhow::Result<bool> {
    // Automatic-startup services restart themselves via the SCM; no action needed.
    if state.startup_was_automatic || !state.was_running {
        return Ok(false);
    }
    let sm = ServiceManager::open_all_access()?;
    let svc = sm.open_service_all_access(AGENT_SERVICE_NAME)?;
    svc.start()?;
    Ok(true)
}

const UPDATE_JSON_WATCH_INTERVAL: Duration = Duration::from_secs(3);

/// Delay before the first unconditional `update_status.json` refresh after agent start.
///
/// 30 seconds gives the MSI installer enough time to finish after an agent self-update
/// so the registry reflects the newly installed version when we re-probe it.
const STATUS_REFRESH_INITIAL_DELAY: Duration = Duration::from_secs(30);

/// Interval between subsequent unconditional `update_status.json` refreshes.
///
/// This catches manual re-installations or any other external change that the
/// update-triggered refresh would miss.
const STATUS_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

// List of updateable products could be extended in future.
const PRODUCTS: &[Product] = &[Product::Gateway, Product::HubService, Product::Agent];

// The first agent version with self-update support is 2026.2.
const AGENT_MIN_SELF_UPDATE_VERSION: DateVersion = DateVersion {
    year: 2026,
    month: 2,
    day: 0,
    revision: 0,
};

fn is_agent_self_update_supported(version: DateVersion) -> bool {
    version >= AGENT_MIN_SELF_UPDATE_VERSION
}

/// Load productinfo source from configured URL or file path
async fn load_productinfo_source(conf: &ConfHandle) -> Result<String, UpdaterError> {
    let conf_data = conf.get_conf();
    let source = conf_data
        .debug
        .productinfo_url
        .as_deref()
        .unwrap_or(DEVOLUTIONS_PRODUCTINFO_URL);

    let proxy_conf = &conf_data.proxy;

    if source.starts_with("file://") {
        info!(%source, "Loading productinfo from file path");
        download_utf8(source, proxy_conf).await
    } else {
        info!(%source, "Downloading productinfo from URL");
        download_utf8(source, proxy_conf).await
    }
}

/// Validate that download URL is from official CDN unless unsafe URLs are allowed
fn validate_download_url(ctx: &UpdaterCtx, url: &str) -> Result<(), UpdaterError> {
    // The URL is matching our CDN, we allow.
    if url.starts_with("https://cdn.devolutions.net/") {
        return Ok(());
    }

    // The allow_unsafe_updater_urls flag is set, we allow anything.
    if ctx.conf.get_conf().debug.allow_unsafe_updater_urls {
        warn!(%url, "DEBUG MODE: Allowing non-CDN download URL");
        return Ok(());
    }

    // Otherwise, we reject.
    Err(UpdaterError::UnsafeUrl {
        product: ctx.product,
        url: url.to_owned(),
    })
}

/// Context for updater task
pub(crate) struct UpdaterCtx {
    product: Product,
    actions: Box<dyn ProductUpdateActions + Send + Sync + 'static>,
    conf: ConfHandle,
    shutdown_signal: ShutdownSignal,
    /// For agent self-update downgrades: the product code of the currently installed version
    /// to be uninstalled by the shim before installing the target version.
    downgrade_product_code: Option<Uuid>,
}

struct DowngradeInfo {
    installed_version: DateVersion,
    product_code: Uuid,
}

struct UpdateOrder {
    target_version: DateVersion,
    downgrade: Option<DowngradeInfo>,
    package_url: String,
    hash: Option<String>,
}

/// Set to `true` while the agent self-update shim is running.
///
/// Used as a lightweight guard to prevent overlapping agent updates and to block any
/// other product update from starting while the agent MSI is being installed (the MSI
/// may restart dependent services).
static AGENT_UPDATE_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

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

        // Derive the initial auto-update schedule from agent.json.
        let initial_schedule: Option<UpdaterSchedule> = {
            let conf_data = conf.get_conf();
            conf_data.updater.schedule.clone()
        };
        let update_file_path = init_update_json().await?;

        let mut current_schedule: Option<UpdateSchedule> = initial_schedule.map(UpdateSchedule::from);

        // Write update_status.json with the current schedule and installed product versions.
        // The gateway reads this file for GET /jet/update/schedule and GET /jet/update.
        init_update_status_json(current_schedule.as_ref()).await?;

        // Unconditional status refresh: fires 30 s after start (catches self-update where the
        // agent is re-launched before the MSI finishes writing to the registry), then every 5
        // minutes (catches manual re-installations and any other external change).
        let status_refresh = tokio::time::sleep(STATUS_REFRESH_INITIAL_DELAY);
        tokio::pin!(status_refresh);

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

        // Absolute local timestamp of the last auto-update check, used to compute
        // true elapsed time even when the interval spans multiple days.
        let mut last_check_at_local: Option<time::OffsetDateTime> = None;

        loop {
            // Compute the delay to the next auto-update check slot.
            // Schedule is re-read every iteration so external changes (e.g. written by the
            // gateway via update.json) take effect without restarting the agent.
            let auto_update_sleep = match current_schedule.as_ref().filter(|s| s.enabled) {
                None => tokio::time::sleep(Duration::MAX),
                Some(schedule) => {
                    let now: time::OffsetDateTime = local_now();

                    // How many seconds have elapsed since the last check?
                    let last_check_ago = elapsed_since_last_check_secs(now, last_check_at_local);

                    let delay = next_poll_delay(seconds_since_midnight(now), last_check_ago, schedule);
                    trace!(delay_secs = delay.as_secs(), "Next auto-update check scheduled");
                    tokio::time::sleep(delay)
                }
            };

            tokio::select! {
                _ = &mut status_refresh => {
                    // Trace instead of Info since logging each 5 minutes produces
                    // a lot of noise in logs.
                    trace!("Refreshing update_status.json (periodic status check)");

                    refresh_update_status_json(current_schedule.as_ref()).await;
                    status_refresh.as_mut().reset(tokio::time::Instant::now() + STATUS_REFRESH_INTERVAL);
                }
                _ = auto_update_sleep => {
                    let Some(ref schedule) = current_schedule else { continue };

                    if !schedule.enabled {
                        continue;
                    }

                    // Confirm we are inside the window at the actual wake-up instant.
                    // The sleep duration is computed from wall-clock seconds, so minor
                    // clock drift or a very short interval could cause us to wake up
                    // fractionally early or outside the window.
                    let now = local_now();
                    let now_secs = seconds_since_midnight(now);

                    if !is_in_update_window(
                        now_secs,
                        u64::from(schedule.update_window_start),
                        schedule.update_window_end.map(u64::from),
                    ) {
                        // Not yet in the window; loop to recompute the exact delay.
                        continue;
                    }

                    info!("Agent scheduled auto-update: maintenance window active, checking for new version");
                    last_check_at_local = Some(now);

                    // Build the product map from the schedule's product list, requesting
                    // the latest version for each.  An empty list means no products are
                    // configured for auto-update; still record the check timestamp so the
                    // scheduler advances normally.
                    let scheduled_products: HashMap<UpdateProductKey, ProductUpdateInfo> = schedule
                        .products
                        .iter()
                        .map(|key| {
                            (
                                key.clone(),
                                ProductUpdateInfo { target_version: VersionSpecification::Latest },
                            )
                        })
                        .collect();

                    if scheduled_products.is_empty() {
                        info!("Agent scheduled auto-update: no products configured, skipping");
                    } else if run_product_updates(&scheduled_products, &conf, shutdown_signal.clone()).await {
                        // Update status needs updating.
                        refresh_update_status_json(current_schedule.as_ref()).await;
                    }
                }
                _ = file_change_notification.notified() => {
                    info!("update.json file changed, checking for updates...");

                    let manifest = match read_update_json(&update_file_path).await {
                        Ok(manifest) => manifest,
                        Err(error) => {
                            error!(%error, "Failed to parse `update.json`");
                            // Allow this error to be non-critical, as this file could be
                            // updated later to be valid again
                            continue;
                        }
                    };


                    // Apply schedule changes when the gateway writes a new Schedule field.
                    // If the manifest has no Schedule field, leave the current schedule unchanged.
                    let mut status_needs_update = if let UpdateManifest::ManifestV2(ref v2) = manifest
                        && let Some(new_schedule) = v2.schedule.clone()
                        && current_schedule.as_ref() != Some(&new_schedule)
                    {
                        info!("Auto-update schedule changed via update.json; persisting to agent.json");
                        let persisted = UpdaterSchedule::from(new_schedule.clone());
                        if let Err(error) = conf.save_updater_schedule(&persisted) {
                            error!(%error, "Failed to persist auto-update schedule to agent.json");
                        }
                        current_schedule = Some(new_schedule);
                        // Rebase scheduler state to the newly applied schedule so checks are
                        // computed from the new window/interval policy.
                        last_check_at_local = None;
                        true
                    } else {
                        false
                    };

                    let products_map = manifest.into_products();

                    // If update.json has no Products field, do not trigger any update.
                    if products_map.is_empty() {
                        info!("update.json has no Products field, skipping update check");
                    } else {
                        status_needs_update |=
                            run_product_updates(&products_map, &conf, shutdown_signal.clone()).await;
                    }

                    // Refresh status after we applied all changes from the manifest.
                    if status_needs_update {
                        refresh_update_status_json(current_schedule.as_ref()).await;
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

/// Check for and run updates for all products present in `products_map`.
///
/// Iterates [`PRODUCTS`] in definition order, collects those that have an available update,
/// sorts them so the Agent update runs last (its MSI stops the agent service, which would
/// abort any subsequent product update), then installs each one.
///
/// Returns `true` when `update_status.json` should be refreshed after this call.
async fn run_product_updates(
    products_map: &HashMap<UpdateProductKey, ProductUpdateInfo>,
    conf: &ConfHandle,
    shutdown_signal: ShutdownSignal,
) -> bool {
    let mut update_orders: Vec<(Product, UpdateOrder)> = vec![];

    for &product in PRODUCTS {
        let update_order = match check_for_updates(product, products_map, conf).await {
            Ok(order) => order,
            Err(error) => {
                error!(%product, error = format!("{error:#}"), "Failed to check for updates for a product");
                continue;
            }
        };

        if let Some(order) = update_order {
            update_orders.push((product, order));
        }
    }

    if update_orders.is_empty() {
        info!("No updates available for any product");
        return false;
    }

    // Agent self-update must go last: its MSI stops the agent service,
    // which would prevent any subsequent products from being updated.
    update_orders.sort_by_key(|(product, _)| *product == Product::Agent);

    let mut agent_updated = false;
    let mut update_successful = false;

    for (product, order) in update_orders {
        match update_product(conf.clone(), product, order, shutdown_signal.clone()).await {
            Ok(()) => {
                if product == Product::Agent {
                    agent_updated = true;
                }

                update_successful = true;
            }
            Err(error) => {
                error!(%product, %error, "Failed to update product");
            }
        }
    }

    // If the agent was successfully updated a restart is imminent; status refreshes on next start.
    update_successful && !agent_updated
}

async fn update_product(
    conf: ConfHandle,
    product: Product,
    order: UpdateOrder,
    shutdown_signal: ShutdownSignal,
) -> anyhow::Result<()> {
    // Block any product update while the agent shim is running in the background.
    // The agent MSI restarts dependent services and must complete uninterrupted.
    if AGENT_UPDATE_IN_PROGRESS.load(Ordering::Acquire) {
        anyhow::bail!("skipping {product} update: agent update is in progress");
    }

    let target_version = order.target_version;
    let hash = order.hash;

    let mut ctx = UpdaterCtx {
        product,
        actions: build_product_actions(product),
        conf,
        shutdown_signal,
        downgrade_product_code: order.downgrade.as_ref().and_then(|d| {
            // For Agent, the shim handles uninstall + install in sequence; pass the product
            // code so it can run `msiexec /x` before `msiexec /i`.
            (product == Product::Agent).then_some(d.product_code)
        }),
    };

    validate_download_url(&ctx, &order.package_url)?;

    let proxy_conf = &ctx.conf.get_conf().proxy;

    let package_data = download_binary(&order.package_url, proxy_conf)
        .await
        .with_context(|| format!("failed to download package file for `{product}`"))?;

    let package_path = save_to_temp_file(&package_data, Some(product.get_package_extension())).await?;

    info!(%product, %target_version, %package_path, "Downloaded product Installer");

    if let Some(hash) = hash {
        if ctx.conf.get_conf().debug.skip_updater_hash_validation {
            warn!(%product, "DEBUG MODE: Skipping hash validation");
        } else {
            validate_artifact_hash(&ctx, &package_data, &hash).context("failed to validate package file integrity")?;
        }
    }

    validate_package(&ctx, &package_path).context("failed to validate package contents")?;

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
        // For Product::Agent the shim handles uninstall; skip the in-process step.
        if product != Product::Agent {
            uninstall_package(&ctx, downgrade.product_code, &uninstall_log_path).await?;
        }
    }

    let log_path = package_path.with_extension("log");

    install_package(&ctx, &package_path, &log_path)
        .await
        .context("failed to install package")?;

    ctx.actions.post_update()?;

    info!(%product, %target_version, "Product updated!");

    Ok(())
}

/// Read and parse `update.json` asynchronously.
///
/// Transparently upgrades a legacy V1 file to a V2 manifest in memory so the rest of the
/// updater task never needs to handle the old format.  The file on disk is left unchanged;
/// the next write will persist the upgraded format.
async fn read_update_json(update_file_path: &Utf8Path) -> anyhow::Result<UpdateManifest> {
    let data = fs::read(update_file_path)
        .await
        .context("failed to read update.json file")?;

    let manifest = UpdateManifest::parse(&data).context("failed to parse update.json file")?;

    // Transparently upgrade V1 → V2 in memory.
    let upgraded = match manifest {
        UpdateManifest::ManifestV2(_) => manifest,
        UpdateManifest::Legacy(v1) => {
            let mut products = HashMap::new();
            if let Some(gw) = v1.gateway {
                products.insert(UpdateProductKey::Gateway, gw);
            }
            if let Some(hs) = v1.hub_service {
                products.insert(UpdateProductKey::HubService, hs);
            }
            UpdateManifest::ManifestV2(UpdateManifestV2 {
                products,
                ..UpdateManifestV2::default()
            })
        }
    };

    Ok(upgraded)
}

async fn check_for_updates(
    product: Product,
    products: &HashMap<UpdateProductKey, ProductUpdateInfo>,
    conf: &ConfHandle,
) -> anyhow::Result<Option<UpdateOrder>> {
    let target_version = match products
        .get(&product.as_update_product_key())
        .map(|info| info.target_version.clone())
    {
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

    match target_version {
        VersionSpecification::Specific(target) if target == detected_version => {
            // Early exit without checking remote database.
            info!(%product, %detected_version, "Product is up to date, skipping update");
            return Ok(None);
        }
        VersionSpecification::Latest | VersionSpecification::Specific(_) => {}
    }

    info!(%product, %target_version, "Ready to update the product");

    let product_info_json = load_productinfo_source(conf)
        .await
        .context("failed to load productinfo database")?;

    let parse_result = ProductInfoDb::parse_product_info(&product_info_json);

    let product_info = parse_result
        .db
        .lookup_current_msi_for_target_arch(product.get_productinfo_id())
        .ok_or_else(|| {
            // At this point, log all parsing errors as warnings so we can investigate.
            for e in parse_result.errors {
                warn!(
                    error = format!("{:#}", anyhow::Error::new(e)),
                    "productinfo.json parsing error"
                );
            }

            UpdaterError::ProductFileNotFound {
                product: product.get_productinfo_id().to_owned(),
                arch: productinfo::get_target_arch().to_owned(),
                file_type: "msi".to_owned(),
            }
        })?;

    let remote_version = product_info.version.parse::<DateVersion>()?;

    match target_version {
        VersionSpecification::Latest => {
            if remote_version <= detected_version {
                info!(%product, %detected_version, "Product is up to date, skipping update (update to `latest` requested)");
                return Ok(None);
            }

            if product == Product::Agent && !is_agent_self_update_supported(remote_version) {
                warn!(
                    %product,
                    target_version = %remote_version,
                    min_version = %AGENT_MIN_SELF_UPDATE_VERSION,
                    "Latest version does not support agent self-update; skipping to avoid breaking auto-update"
                );
                return Ok(None);
            }

            Ok(Some(UpdateOrder {
                target_version: remote_version,
                downgrade: None,
                package_url: product_info.url.clone(),
                hash: Some(product_info.hash.clone()),
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
            if let Some(path) = io::parse_file_url(&package_url) {
                // For file:// URLs, check if the file exists on disk
                if !path.exists() {
                    warn!(
                        %product,
                        %version,
                        %package_url,
                        "File does not exist, skipping update"
                    );
                    return Ok(None);
                }
            } else {
                let proxy_conf = &conf.get_conf().proxy;

                let target_url = url::Url::parse(&package_url)?;
                let proxy_config = proxy_conf.to_proxy_config();

                let client = http_client_proxy::get_or_create_cached_client(
                    reqwest::Client::builder(),
                    &target_url,
                    &proxy_config,
                )?;

                let response = client.head(&package_url).send().await?;
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
            }
            // Target MSI found, proceed with update.

            if product == Product::Agent && !is_agent_self_update_supported(version) {
                warn!(
                    %product,
                    %version,
                    min_version = %AGENT_MIN_SELF_UPDATE_VERSION,
                    "Target version does not support agent self-update; skipping to avoid breaking auto-update"
                );
                return Ok(None);
            }

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
                package_url,
                hash: None,
            }))
        }
    }
}

/// Collect the currently installed version of every known product.
///
/// Products that are not installed or whose version cannot be detected are silently
/// omitted from the returned map.
fn collect_installed_products() -> HashMap<UpdateProductKey, InstalledProductUpdateInfo> {
    let mut products = HashMap::new();
    for &product in PRODUCTS {
        match detect::get_installed_product_version(product) {
            Ok(Some(version)) => {
                products.insert(
                    product.as_update_product_key(),
                    InstalledProductUpdateInfo {
                        version: VersionSpecification::Specific(version),
                    },
                );
            }
            Ok(None) => {
                trace!(%product, "Product not installed, omitting from update_status.json");
            }
            Err(error) => {
                warn!(%product, %error, "Failed to detect installed product version for update_status.json");
            }
        }
    }
    products
}

/// Create `update_status.json` at startup, populate it with the current schedule and
/// installed product versions, and apply the DACL that restricts the Gateway service
/// to read-only access.
async fn init_update_status_json(schedule: Option<&UpdateSchedule>) -> anyhow::Result<()> {
    let status_file_path = get_update_status_file_path();

    let status = UpdateStatus::StatusV2(UpdateStatusV2 {
        schedule: schedule.cloned(),
        products: collect_installed_products(),
        ..UpdateStatusV2::default()
    });

    let json = serde_json::to_string_pretty(&status).context("failed to serialize update_status.json")?;
    fs::write(&status_file_path, json)
        .await
        .context("failed to write update_status.json")?;

    match set_file_dacl(&status_file_path, security::UPDATE_STATUS_JSON_DACL) {
        Ok(_) => {
            info!("Created `update_status.json` and set permissions successfully");
        }
        Err(err) => {
            std::fs::remove_file(status_file_path.as_std_path()).unwrap_or_else(
                |error| warn!(%error, "Failed to remove update_status.json after failed permissions set"),
            );
            return Err(anyhow!(err).context("failed to set update_status.json file permissions"));
        }
    }

    Ok(())
}

/// Refresh `update_status.json` with the latest schedule and re-detected installed
/// product versions.
///
/// Called after each updater run (even when some product updates fail — the file is
/// always updated to reflect the current on-disk state) and after a schedule change.
///
/// Note: if the agent itself is being updated, `update_status.json` will be automatically
/// refreshed when the agent restarts after the update completes.
///
/// Errors are logged but treated as non-fatal so a failed write never aborts the updater.
async fn refresh_update_status_json(schedule: Option<&UpdateSchedule>) {
    let status_file_path = get_update_status_file_path();

    let status = UpdateStatus::StatusV2(UpdateStatusV2 {
        schedule: schedule.cloned(),
        products: collect_installed_products(),
        ..UpdateStatusV2::default()
    });

    match serde_json::to_string_pretty(&status) {
        Ok(json) => {
            if let Err(error) = fs::write(&status_file_path, json).await {
                error!(%error, "Failed to write update_status.json");
            }
        }
        Err(error) => {
            error!(%error, "Failed to serialize update_status.json");
        }
    }
}

async fn init_update_json() -> anyhow::Result<Utf8PathBuf> {
    let update_file_path = get_updater_file_path();

    // update.json is the gateway->agent command channel.
    // Do not mirror agent runtime state into this file; schedule and installed products
    // are published by the agent through update_status.json.
    let v2 = UpdateManifestV2::default();

    let initial_manifest = UpdateManifest::ManifestV2(v2);
    let default_update_json =
        serde_json::to_string_pretty(&initial_manifest).context("failed to serialize default update.json")?;

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

const SECS_PER_DAY: u64 = 86_400;

/// Returns `true` when `now` falls within the configured maintenance window.
///
/// `now`, `window_start`, and `window_end` are seconds past local midnight.
/// When `window_end` is `None`, the window spans an implicit full 24 h period starting at
/// `window_start`, therefore every local time is in-window.  When `window_end` is `Some`
/// and `end < start`, midnight crossing is assumed
/// (e.g. `79200`–`10800` covers `[22:00, midnight) ∪ [midnight, 03:00)`).
fn is_in_update_window(now: u64, window_start: u64, window_end: Option<u64>) -> bool {
    match window_end {
        None => true,
        Some(end) => {
            if end < window_start {
                // Window crosses midnight: [start, midnight) ∪ [midnight, end)
                now >= window_start || now < end
            } else {
                // Normal window: [start, end)
                now >= window_start && now < end
            }
        }
    }
}

fn local_now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc())
}

fn seconds_since_midnight(now: time::OffsetDateTime) -> u64 {
    u64::from(now.hour()) * 3_600 + u64::from(now.minute()) * 60 + u64::from(now.second())
}

fn elapsed_since_last_check_secs(
    now_local: time::OffsetDateTime,
    last_check_at_local: Option<time::OffsetDateTime>,
) -> Option<u64> {
    last_check_at_local.map(|last| u64::try_from((now_local - last).whole_seconds()).unwrap_or(0))
}

/// Compute how long to sleep before the next auto-update check.
///
/// The function is pure (takes explicit `now_secs`) so it can be unit-tested without
/// mocking the system clock.
///
/// # Rules
///
/// The window rolls over every 24 h. When `window_end` is `None` the window spans exactly
/// one full day starting at `window_start` (no upper bound restriction within that day).
///
/// * **Outside window** — sleep until the next window start, then also check that the
///   cross-day rule since the last check is respected.  If the interval is longer than
///   24 h, the next check slot may be more than one day away.
/// * **Inside window, `interval == 0`** — single check per window; sleep until the
///   *next* window start (i.e. fire once, then skip to tomorrow's window).
/// * **Inside window, `interval > 0`** — checks land on multiples of `interval` counted
///   from `window_start`.  Return the delay to the next such slot that lies inside the
///   window.  If no further slot fits in the current window, sleep until the next window
///   start (tomorrow).
///
/// For intervals greater than 24 h, an additional cross-day rule is enforced while
/// in-window: if the previous check happened less than `interval` seconds ago, the
/// returned delay is increased to at least the remaining interval.
///
/// # Arguments
///
/// * `now_since_midnight`— seconds past local midnight, in `[0, 86400)`.
/// * `last_check_ago`    — elapsed seconds since the previous successful check
///   (`None` means no check has fired yet).
/// * `schedule`          — the current [`UpdateSchedule`].
///
/// Returns a positive [`Duration`] (never zero, minimum 1 s) to avoid busy-loops.
fn next_poll_delay(now_since_midnight: u64, last_check_ago: Option<u64>, schedule: &UpdateSchedule) -> Duration {
    let window_start = u64::from(schedule.update_window_start);
    // None → no end bound; treat the window as spanning the full 24 h from window_start.
    let window_end = schedule.update_window_end.map(u64::from);
    // interval == 0 is treated as a single daily check (fire once at window start).
    let interval = if schedule.interval == 0 {
        SECS_PER_DAY
    } else {
        schedule.interval
    };

    // How many seconds until the next window start (wrapping around midnight)?
    let secs_until_window_start = if now_since_midnight < window_start {
        window_start - now_since_midnight
    } else {
        SECS_PER_DAY - now_since_midnight + window_start
    };

    // Is `now` inside the window?
    let in_window = {
        let end = window_end.unwrap_or(window_start + SECS_PER_DAY);
        if end <= window_start {
            // Midnight-crossing window: [start, 24h) ∪ [0, end)
            now_since_midnight >= window_start || now_since_midnight < end
        } else {
            now_since_midnight >= window_start && now_since_midnight < end
        }
    };

    if !in_window {
        // Outside the window.  Check whether the cross-day rule would push us past the
        // next window start; if so, honour the interval instead.
        let delay = if let Some(last_ago) = last_check_ago {
            if last_ago < interval {
                // Interval not yet elapsed since last check; wait the remaining interval
                // time but no longer than until the window re-opens.
                let remaining_interval = interval - last_ago;
                remaining_interval.max(secs_until_window_start)
            } else {
                secs_until_window_start
            }
        } else {
            secs_until_window_start
        };

        return Duration::from_secs(delay.max(1));
    }

    // Inside the window.  Find how far past window_start we are (may need to wrap around
    // midnight for crossing windows).
    let secs_past_start = if now_since_midnight >= window_start {
        now_since_midnight - window_start
    } else {
        // We are before midnight but inside a crossing window (now_secs < window_start
        // and we are in the [0, end) portion).
        SECS_PER_DAY - window_start + now_since_midnight
    };

    // Next slot index (from window_start) is ceil(secs_past_start / interval).
    let next_slot_offset = {
        let elapsed_slots = secs_past_start / interval;
        // If we're exactly on a slot boundary, still move to next slot (the current
        // slot either just fired or is about to; either way don't re-fire immediately).
        (elapsed_slots + 1) * interval
    };

    // Does that slot still fall inside the window?
    let window_size = match window_end {
        Some(end) if end > window_start => end - window_start,
        Some(end) => SECS_PER_DAY - window_start + end, // crossing
        None => SECS_PER_DAY,
    };

    let mut delay_secs = if next_slot_offset < window_size {
        // Next check fires inside this window.
        next_slot_offset - secs_past_start
    } else {
        // No more slots in this window; sleep until the next window start.
        secs_until_window_start
    };

    // Enforce the cross-day rule only for intervals longer than one day. For shorter
    // intervals, keep the legacy in-window slot semantics unchanged.
    if let Some(last_ago) = last_check_ago
        && interval > SECS_PER_DAY
        && last_ago < interval
    {
        delay_secs = delay_secs.max(interval - last_ago);
    }

    // Enforce a minimum of 30 s to prevent unnecessarily fast polling loops even if the
    // schedule is configured with a very small interval.
    const MIN_POLL_SECS: u64 = 30;
    Duration::from_secs(delay_secs.max(MIN_POLL_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(h: u64, m: u64) -> u64 {
        h * 3_600 + m * 60
    }

    fn sched(window_start: u64, window_end: Option<u64>, interval: u64) -> UpdateSchedule {
        UpdateSchedule {
            enabled: true,
            interval,
            update_window_start: u32::try_from(window_start).expect("window start within a day"),
            update_window_end: window_end.map(|end| u32::try_from(end).expect("window end within a day")),
            products: vec![],
        }
    }

    fn at(ts: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(ts).expect("valid unix timestamp")
    }

    fn at_u64(ts: u64) -> time::OffsetDateTime {
        at(i64::try_from(ts).expect("test timestamp fits in i64"))
    }

    #[test]
    fn maintenance_window_bounded_cases() {
        let start = t(2, 0);
        let end = Some(t(4, 0));

        for (time, expected) in [
            (t(1, 59), false),
            (t(2, 0), true),
            (t(3, 0), true),
            (t(4, 0), false),
            (t(4, 1), false),
        ] {
            assert_eq!(is_in_update_window(time, start, end), expected, "time={time}");
        }
    }

    #[test]
    fn maintenance_window_open_ended_cases() {
        let start = t(2, 0);

        for (time, expected) in [(t(1, 59), true), (t(2, 0), true), (t(23, 59), true)] {
            assert_eq!(is_in_update_window(time, start, None), expected, "time={time}");
        }
    }

    #[test]
    fn maintenance_window_midnight_crossing_cases() {
        let start = t(22, 0);
        let end = Some(t(3, 0));

        for (time, expected) in [
            (t(22, 0), true),
            (t(23, 0), true),
            (t(1, 0), true),
            (t(3, 0), false),
            (t(10, 0), false),
        ] {
            assert_eq!(is_in_update_window(time, start, end), expected, "time={time}");
        }
    }

    #[test]
    fn next_poll_delay_outside_window_cases() {
        for (now_time, last_check_ago, schedule, expected_delay) in [
            (t(0, 0), None, sched(t(2, 0), Some(t(4, 0)), t(1, 0)), t(2, 0)),
            (
                t(5, 0),
                Some(t(0, 10)),
                sched(t(2, 0), Some(t(4, 0)), t(1, 0)),
                t(21, 0),
            ),
            (t(5, 0), Some(t(2, 0)), sched(t(2, 0), Some(t(4, 0)), t(1, 0)), t(21, 0)),
            (t(0, 0), None, sched(t(2, 0), Some(t(4, 0)), t(0, 0)), t(2, 0)),
        ] {
            assert_eq!(
                next_poll_delay(now_time, last_check_ago, &schedule).as_secs(),
                expected_delay
            );
        }
    }

    #[test]
    fn next_poll_delay_inside_window_slot_cases() {
        for (now_time, last_check_ago, schedule, expected_delay) in [
            (t(0, 0), None, sched(t(0, 0), Some(t(8, 0)), t(2, 0)), t(2, 0)),
            (t(1, 30), None, sched(t(0, 0), Some(t(8, 0)), t(2, 0)), t(0, 30)),
            (t(2, 0), None, sched(t(0, 0), Some(t(8, 0)), t(2, 0)), t(2, 0)),
            (t(2, 30), None, sched(t(0, 0), Some(t(3, 0)), t(2, 0)), t(21, 30)),
            (
                t(1, 30),
                Some(t(0, 15)),
                sched(t(0, 0), Some(t(8, 0)), t(2, 0)),
                t(0, 30),
            ),
        ] {
            assert_eq!(
                next_poll_delay(now_time, last_check_ago, &schedule).as_secs(),
                expected_delay
            );
        }
    }

    #[test]
    fn next_poll_delay_special_window_cases() {
        for (now_time, schedule, expected_delay) in [
            (t(2, 0), sched(t(2, 0), Some(t(4, 0)), t(0, 0)), SECS_PER_DAY),
            (t(3, 0), sched(t(2, 0), None, t(4, 0)), t(3, 0)),
            (t(1, 0), sched(t(22, 0), Some(t(3, 0)), t(2, 0)), t(1, 0)),
        ] {
            assert_eq!(next_poll_delay(now_time, None, &schedule).as_secs(), expected_delay);
        }
    }

    #[test]
    fn next_poll_delay_long_interval_respects_cross_day_rule_inside_window() {
        // interval = 36h, last check was 1h ago, now is inside window.
        // Remaining interval must win over "next window start" delay.
        let schedule = sched(t(2, 0), Some(t(4, 0)), t(36, 0));
        assert_eq!(next_poll_delay(t(2, 30), Some(t(1, 0)), &schedule).as_secs(), t(35, 0));
    }

    #[test]
    fn next_poll_delay_long_interval_outside_window_keeps_remaining_interval() {
        // interval = 36h, last check was 2h ago, now outside window.
        // Remaining 34h is longer than waiting for next window start and must be used.
        let schedule = sched(t(2, 0), Some(t(4, 0)), t(36, 0));
        assert_eq!(next_poll_delay(t(5, 0), Some(t(2, 0)), &schedule).as_secs(), t(34, 0));
    }

    #[test]
    fn next_poll_delay_long_interval_without_last_check_inside_window() {
        // interval = 36h, no previous check, now is inside window.
        // The first eligible slot inside the current window should be used.
        let schedule = sched(t(2, 0), Some(t(4, 0)), t(36, 0));
        assert_eq!(next_poll_delay(t(2, 30), None, &schedule).as_secs(), t(23, 30));
    }

    #[test]
    fn next_poll_delay_long_interval_without_last_check_outside_window() {
        // interval = 36h, no previous check, now is outside window.
        // With no cross-day rule to honor yet, wait only until the next window start.
        let schedule = sched(t(2, 0), Some(t(4, 0)), t(36, 0));
        assert_eq!(next_poll_delay(t(5, 0), None, &schedule).as_secs(), t(21, 0));
    }

    #[test]
    fn elapsed_since_last_check_secs_supports_multi_day_runtime_intervals() {
        assert_eq!(
            elapsed_since_last_check_secs(at_u64(t(72, 0) + t(1, 0)), Some(at_u64(t(1, 0)))),
            Some(t(72, 0))
        );
    }

    #[test]
    fn elapsed_since_last_check_secs_without_previous_check_is_none() {
        assert_eq!(elapsed_since_last_check_secs(at_u64(t(1, 0)), None), None);
    }

    #[test]
    fn try_modify_product_url_version_replaces_embedded_version() {
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

    #[test]
    fn agent_self_update_support_boundary() {
        let before_boundary = DateVersion {
            year: 2026,
            month: 1,
            day: 0,
            revision: 0,
        };
        let boundary = DateVersion {
            year: 2026,
            month: 2,
            day: 0,
            revision: 0,
        };
        let after_boundary = DateVersion {
            year: 2026,
            month: 2,
            day: 1,
            revision: 0,
        };

        assert!(!is_agent_self_update_supported(before_boundary));
        assert!(is_agent_self_update_supported(boundary));
        assert!(is_agent_self_update_supported(after_boundary));
    }
}
