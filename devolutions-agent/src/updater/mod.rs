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
use std::time::{Duration, Instant};

use time::Time;
use time::macros::format_description;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_agent_shared::{DateVersion, ProductUpdateInfo, UpdateJson, VersionSpecification, get_updater_file_path};
use devolutions_gateway_task::{ShutdownSignal, Task};
use notify_debouncer_mini::notify::RecursiveMode;
use tokio::fs;
use uuid::Uuid;

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
use crate::updater::productinfo::ProductInfoDb;

const UPDATE_JSON_WATCH_INTERVAL: Duration = Duration::from_secs(3);
/// How often the task checks whether an auto-update should be triggered.
const POLL_INTERVAL: Duration = Duration::from_secs(60);

// List of updateable products could be extended in future.
const PRODUCTS: &[Product] = &[Product::Gateway, Product::HubService, Product::Agent];

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
struct UpdaterCtx {
    product: Product,
    actions: Box<dyn ProductUpdateActions + Send + Sync + 'static>,
    conf: ConfHandle,
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

        let mut last_auto_update_trigger: Option<Instant> = None;

        // First poll fires after POLL_INTERVAL, not immediately on startup.
        let mut poll_ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + POLL_INTERVAL,
            POLL_INTERVAL,
        );

        loop {
            tokio::select! {
                _ = poll_ticker.tick() => {
                    let auto_update = {
                        let conf_data = conf.get_conf();
                        conf_data.updater.agent_auto_update.clone()
                    };

                    let Some(auto_update) = auto_update else { continue };

                    if !auto_update.enabled {
                        continue;
                    }

                    let interval = parse_interval(&auto_update.interval);
                    if let Some(last) = last_auto_update_trigger
                        && last.elapsed() < interval
                    {
                        continue;
                    }

                    let now = time::OffsetDateTime::now_local()
                        .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
                    if !is_in_update_window(now.time(), &auto_update.update_window_start, auto_update.update_window_end.as_deref()) {
                        continue;
                    }

                    info!("Agent auto-update: maintenance window active, checking for new version");
                    last_auto_update_trigger = Some(Instant::now());

                    let synthetic = UpdateJson {
                        agent: Some(ProductUpdateInfo { target_version: VersionSpecification::Latest }),
                        gateway: None,
                        hub_service: None,
                    };

                    match check_for_updates(Product::Agent, &synthetic, &conf).await {
                        Ok(Some(order)) => {
                            if let Err(error) = update_product(conf.clone(), Product::Agent, order).await {
                                error!(error = format!("{error:#}"), "Agent auto-update: failed to update agent");
                            }
                        }
                        Ok(None) => {
                            info!("Agent auto-update: agent is already up to date");
                        }
                        Err(error) => {
                            error!(error = format!("{error:#}"), "Agent auto-update: failed to check for updates");
                        }
                    }
                }
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
                        let update_order = match check_for_updates(*product, &update_json, &conf).await {
                            Ok(order) => order,
                            Err(error) => {
                                error!(%product, error = format!("{error:#}"), "Failed to check for updates for a product");
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

    let mut ctx = UpdaterCtx {
        product,
        actions: build_product_actions(product),
        conf,
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

async fn check_for_updates(
    product: Product,
    update_json: &UpdateJson,
    conf: &ConfHandle,
) -> anyhow::Result<Option<UpdateOrder>> {
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

    // The first agent version with self-update support is 2026.2 (anything built after
    // 2026.1.x lacks the updater shim and would permanently disable auto-update).
    const AGENT_MIN_SELF_UPDATE_VERSION: DateVersion = DateVersion {
        year: 2026,
        month: 1,
        day: 0,
        revision: 0,
    };

    let remote_version = product_info.version.parse::<DateVersion>()?;

    match target_version {
        VersionSpecification::Latest => {
            if remote_version <= detected_version {
                info!(%product, %detected_version, "Product is up to date, skipping update (update to `latest` requested)");
                return Ok(None);
            }

            if product == Product::Agent && remote_version <= AGENT_MIN_SELF_UPDATE_VERSION {
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

            if product == Product::Agent && version <= AGENT_MIN_SELF_UPDATE_VERSION {
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

/// Parse a humantime duration string into a [`Duration`].
///
/// A bare integer with no unit suffix is treated as seconds.
/// Falls back to 24 hours if the string cannot be parsed.
fn parse_interval(s: &str) -> Duration {
    if let Ok(secs) = s.trim().parse::<u64>() {
        return Duration::from_secs(secs);
    }
    match humantime::parse_duration(s) {
        Ok(d) => d,
        Err(_) => {
            warn!(interval = s, "Agent auto-update: invalid interval format, falling back to 24 hours");
            Duration::from_secs(86_400)
        }
    }
}

/// Returns `true` when `now` falls within the configured maintenance window.
///
/// `window_start` must be in `HH:MM` (24-hour) local-time format.
/// When `window_end` is `None` the window is unbounded: any time at or after `window_start`
/// is accepted.  When `window_end` is `Some` and `end \u2264 start`, midnight crossing is assumed
/// (e.g. `"22:00"`\u2013`"03:00"` covers `[22:00, midnight) \u222a [midnight, 03:00)`).
fn is_in_update_window(now: Time, window_start: &str, window_end: Option<&str>) -> bool {
    let fmt = format_description!("[hour]:[minute]");
    let parse = |s: &str| Time::parse(s, fmt).ok();

    let Some(start) = parse(window_start) else {
        warn!(
            window_start,
            "Agent auto-update: invalid maintenance window start time format, skipping check"
        );
        return false;
    };

    match window_end {
        None => now >= start,
        Some(end_str) => {
            let Some(end) = parse(end_str) else {
                warn!(
                    window_end = end_str,
                    "Agent auto-update: invalid maintenance window end time format, skipping check"
                );
                return false;
            };
            if end <= start {
                // Window crosses midnight: [start, midnight) \u222a [midnight, end)
                now >= start || now < end
            } else {
                // Normal window: [start, end)
                now >= start && now < end
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use time::Time;
    use time::macros::format_description;

    use super::*;

    fn t(s: &str) -> Time {
        Time::parse(s, format_description!("[hour]:[minute]")).expect("valid test time")
    }

    // --- Maintenance window tests ---

    #[test]
    fn inside_window() {
        assert!(is_in_update_window(t("03:00"), "02:00", Some("04:00")));
    }

    #[test]
    fn at_window_start() {
        assert!(is_in_update_window(t("02:00"), "02:00", Some("04:00")));
    }

    #[test]
    fn at_window_end_exclusive() {
        assert!(!is_in_update_window(t("04:00"), "02:00", Some("04:00")));
    }

    #[test]
    fn before_window() {
        assert!(!is_in_update_window(t("01:59"), "02:00", Some("04:00")));
    }

    #[test]
    fn after_window() {
        assert!(!is_in_update_window(t("04:01"), "02:00", Some("04:00")));
    }

    #[test]
    fn invalid_window_format_returns_false() {
        assert!(!is_in_update_window(t("03:00"), "bad", Some("04:00")));
        assert!(!is_in_update_window(t("03:00"), "02:00", Some("not-a-time")));
    }

    #[test]
    fn no_end_allows_any_time_after_start() {
        assert!(!is_in_update_window(t("01:59"), "02:00", None));
        assert!(is_in_update_window(t("02:00"), "02:00", None));
        assert!(is_in_update_window(t("23:59"), "02:00", None));
    }

    #[test]
    fn invalid_start_with_no_end_returns_false() {
        assert!(!is_in_update_window(t("03:00"), "bad", None));
    }

    #[test]
    fn midnight_crossing_inside_early() {
        // 22:00..03:00 \u2014 time is 01:00, past midnight but before end
        assert!(is_in_update_window(t("01:00"), "22:00", Some("03:00")));
    }

    #[test]
    fn midnight_crossing_inside_late() {
        // 22:00..03:00 \u2014 time is 23:00, before midnight but after start
        assert!(is_in_update_window(t("23:00"), "22:00", Some("03:00")));
    }

    #[test]
    fn midnight_crossing_at_start() {
        assert!(is_in_update_window(t("22:00"), "22:00", Some("03:00")));
    }

    #[test]
    fn midnight_crossing_at_end_exclusive() {
        assert!(!is_in_update_window(t("03:00"), "22:00", Some("03:00")));
    }

    #[test]
    fn midnight_crossing_outside() {
        // 22:00..03:00 \u2014 time is 10:00, outside the window
        assert!(!is_in_update_window(t("10:00"), "22:00", Some("03:00")));
    }

    // --- Interval parsing tests ---

    #[test]
    fn interval_bare_number_is_seconds() {
        assert_eq!(parse_interval("3600"), Duration::from_secs(3600));
    }

    #[test]
    fn interval_bare_small_number_is_seconds_not_fallback() {
        // "30" has no unit suffix; must be treated as 30 seconds, not fall back to 24 hours.
        assert_eq!(parse_interval("30"), Duration::from_secs(30));
    }

    #[test]
    fn interval_humantime_day() {
        assert_eq!(parse_interval("1d"), Duration::from_secs(86_400));
    }

    #[test]
    fn interval_humantime_hours_minutes() {
        assert_eq!(parse_interval("1h 30m"), Duration::from_secs(5400));
    }

    #[test]
    fn interval_invalid_falls_back() {
        assert_eq!(parse_interval("not-a-duration"), Duration::from_secs(86_400));
    }

    // --- URL version modification tests ---

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
