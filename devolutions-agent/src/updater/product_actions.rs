use win_api_wrappers::service::{ServiceManager, ServiceStartupMode};

use crate::updater::{Product, UpdaterError};

const GATEWAY_SERVICE_NAME: &str = "DevolutionsGateway";

// Hub Service installs up to 3 separate Windows services (depending on selected features)
const HUB_SERVICE_NAMES: &[&str] = &[
    "Devolutions Hub PAM Service",
    "Devolutions Hub Encryption Service",
    "Devolutions Hub Reporting Service",
];

/// Additional actions that need to be performed during product update process
pub(crate) trait ProductUpdateActions {
    fn pre_update(&mut self) -> Result<(), UpdaterError>;
    fn get_msiexec_install_params(&self) -> Vec<String>;
    fn post_update(&mut self) -> Result<(), UpdaterError>;
}

/// State information for a single service
#[derive(Debug)]
struct ServiceState {
    name: &'static str,
    exists: bool,
    was_running: bool,
    startup_was_automatic: bool,
}

/// Generic service update actions for Windows service-based products
struct ServiceUpdateActions {
    product: Product,
    service_states: Vec<ServiceState>,
}

impl ServiceUpdateActions {
    fn new_single_service(product: Product, service_name: &'static str) -> Self {
        Self {
            product,
            service_states: vec![ServiceState {
                name: service_name,
                exists: false,
                was_running: false,
                startup_was_automatic: false,
            }],
        }
    }

    fn new_multi_service(product: Product, service_names: &'static [&'static str]) -> Self {
        Self {
            product,
            service_states: service_names
                .iter()
                .map(|&name| ServiceState {
                    name,
                    exists: false,
                    was_running: false,
                    startup_was_automatic: false,
                })
                .collect(),
        }
    }

    fn pre_update_impl(&mut self) -> anyhow::Result<()> {
        info!("Querying service states for {}", self.product);
        let service_manager = ServiceManager::open_read()?;

        for state in &mut self.service_states {
            // Try to open the service - it may not exist if it wasn't installed (e.g., optional Hub features)
            match service_manager.open_service_read(state.name) {
                Ok(service) => {
                    state.exists = true;
                    state.startup_was_automatic = service.startup_mode()? == ServiceStartupMode::Automatic;
                    state.was_running = service.is_running()?;

                    info!(
                        "Service '{}' found - running: {}, automatic_startup: {}",
                        state.name, state.was_running, state.startup_was_automatic
                    );
                }
                Err(e) => {
                    state.exists = false;
                    debug!("Service '{}' not found (feature not installed): {}", state.name, e);
                    // Keep defaults (exists: false, was_running: false, startup_was_automatic: false)
                }
            }
        }

        Ok(())
    }

    fn post_update_impl(&self) -> anyhow::Result<()> {
        let service_manager = ServiceManager::open_all_access()?;

        for state in &self.service_states {
            // Skip services that weren't installed before the update
            if !state.exists {
                debug!("Skipping service '{}' (was not installed)", state.name);
                continue;
            }

            // Start service if it was running prior to the update, but service startup
            // was set to manual.
            if !state.startup_was_automatic && state.was_running {
                info!("Starting '{}' service after update", state.name);

                match service_manager.open_service_all_access(state.name) {
                    Ok(service) => {
                        service.start()?;
                        info!("Service '{}' started", state.name);
                    }
                    Err(e) => {
                        warn!("Failed to start service '{}' after update: {}", state.name, e);
                    }
                }
            } else {
                debug!(
                    "Service '{}' doesn't need manual restart (automatic_startup: {}, was_running: {})",
                    state.name, state.startup_was_automatic, state.was_running
                );
            }
        }

        Ok(())
    }
}

impl ProductUpdateActions for ServiceUpdateActions {
    fn pre_update(&mut self) -> Result<(), UpdaterError> {
        self.pre_update_impl()
            .map_err(|source| UpdaterError::QueryServiceState {
                product: self.product,
                source,
            })
    }

    fn get_msiexec_install_params(&self) -> Vec<String> {
        // When performing update, we want to make sure the service startup mode is restored to the
        // previous state. (Installer sets Manual by default).
        
        // For products with a single primary service, check if it should be automatic
        if self.service_states.len() == 1 && self.service_states[0].startup_was_automatic {
            info!("Adjusting MSIEXEC parameters for {} service startup mode", self.product);
            return vec!["P.SERVICESTART=Automatic".to_owned()];
        }

        // For Hub Service with multiple services, check if any PAM service should be automatic
        // (The MSI installer controls the main PAM service startup via P.SERVICESTART)
        if self.product == Product::HubService {
            if let Some(pam_state) = self
                .service_states
                .iter()
                .find(|s| s.exists && s.name.contains("PAM"))
            {
                if pam_state.startup_was_automatic {
                    info!("Adjusting MSIEXEC parameters for Hub PAM service startup mode");
                    return vec!["P.SERVICESTART=Automatic".to_owned()];
                }
            }
        }

        Vec::new()
    }

    fn post_update(&mut self) -> Result<(), UpdaterError> {
        self.post_update_impl().map_err(|source| UpdaterError::StartService {
            product: self.product,
            source,
        })
    }
}

pub(crate) fn build_product_actions(product: Product) -> Box<dyn ProductUpdateActions + Sync + Send + 'static> {
    match product {
        Product::Gateway => Box::new(ServiceUpdateActions::new_single_service(
            Product::Gateway,
            GATEWAY_SERVICE_NAME,
        )),
        Product::HubService => Box::new(ServiceUpdateActions::new_multi_service(
            Product::HubService,
            HUB_SERVICE_NAMES,
        )),
    }
}
