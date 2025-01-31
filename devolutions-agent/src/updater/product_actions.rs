use win_api_wrappers::service::{ServiceManager, ServiceStartupMode};

use crate::updater::{Product, UpdaterError};

const SERVICE_NAME: &str = "DevolutionsGateway";

/// Additional actions that need to be performed during product update process
pub(crate) trait ProductUpdateActions {
    fn pre_update(&mut self) -> Result<(), UpdaterError>;
    fn get_msiexec_install_params(&self) -> Vec<String>;
    fn post_update(&mut self) -> Result<(), UpdaterError>;
}

/// Gateway specific update actions
#[derive(Default)]
struct GatewayUpdateActions {
    service_was_running: bool,
    service_startup_was_automatic: bool,
}

impl GatewayUpdateActions {
    fn pre_update_impl(&mut self) -> anyhow::Result<()> {
        info!("Querying service state for Gateway");
        let service_manager = ServiceManager::open_read()?;
        let service = service_manager.open_service_read(SERVICE_NAME)?;

        self.service_startup_was_automatic = service.startup_mode()? == ServiceStartupMode::Automatic;
        self.service_was_running = service.is_running()?;

        info!(
            "Service state for Gateway before update: running: {}, automatic_startup: {}",
            self.service_was_running, self.service_startup_was_automatic
        );

        Ok(())
    }

    fn post_update_impl(&self) -> anyhow::Result<()> {
        // Start service if it was running prior to the update, but service startup
        // was set to manual.
        if !self.service_startup_was_automatic && self.service_was_running {
            info!("Starting Gateway service after update");

            let service_manager = ServiceManager::open_all_access()?;
            let service = service_manager.open_service_all_access(SERVICE_NAME)?;
            service.start()?;

            info!("Gateway service started");
        }

        Ok(())
    }
}

impl ProductUpdateActions for GatewayUpdateActions {
    fn pre_update(&mut self) -> Result<(), UpdaterError> {
        self.pre_update_impl()
            .map_err(|source| UpdaterError::QueryServiceState {
                product: Product::Gateway,
                source,
            })
    }

    fn get_msiexec_install_params(&self) -> Vec<String> {
        // When performing update, we want to make sure the service startup mode is restored to the
        // previous state. (Installer sets Manual by default).
        if self.service_startup_was_automatic {
            info!("Adjusting MSIEXEC parameters for Gateway service startup mode");

            return vec!["P.SERVICESTART=Automatic".to_owned()];
        }

        Vec::new()
    }

    fn post_update(&mut self) -> Result<(), UpdaterError> {
        self.post_update_impl().map_err(|source| UpdaterError::StartService {
            product: Product::Gateway,
            source,
        })
    }
}

pub(crate) fn build_product_actions(product: Product) -> Box<dyn ProductUpdateActions + Sync + Send + 'static> {
    match product {
        Product::Gateway => Box::new(GatewayUpdateActions::default()),
    }
}
