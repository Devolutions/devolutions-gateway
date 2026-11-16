//! The services every device-management request handler shares.
//!
//! One context serves every Authority link of every identity, so they all resolve users through one registry.
//! A default context has no services, and device management stays unavailable through it.

#[cfg(windows)]
use std::sync::Arc;

#[cfg(windows)]
use camino::Utf8Path;
#[cfg(windows)]
use now_package_broker::registration::RegistrationHandle;
#[cfg(windows)]
use now_package_broker::server::BrokerState;

#[cfg(windows)]
use super::operation_journal::OperationJournal;
#[cfg(windows)]
use super::user_registry::UserRegistry;

/// Where the user registry lives below the Agent data directory.
#[cfg(windows)]
const USER_REGISTRY_DIR: [&str; 2] = ["device-management", "user-registry"];

#[derive(Clone)]
pub(crate) struct DeviceManagementContext {
    remote_inventory_enabled: bool,
    remote_writes_enabled: bool,
    #[cfg(windows)]
    registration: Option<RegistrationHandle>,
    #[cfg(windows)]
    broker: Option<Arc<BrokerState>>,
    #[cfg(windows)]
    users: Option<Arc<UserRegistry>>,
    #[cfg(windows)]
    journal: Option<Arc<OperationJournal>>,
}

/// A context with no services, and both remote features enabled, as the configuration defaults them.
impl Default for DeviceManagementContext {
    fn default() -> Self {
        Self {
            remote_inventory_enabled: true,
            remote_writes_enabled: true,
            #[cfg(windows)]
            registration: None,
            #[cfg(windows)]
            broker: None,
            #[cfg(windows)]
            users: None,
            #[cfg(windows)]
            journal: None,
        }
    }
}

impl DeviceManagementContext {
    /// Sets whether the Authority may request inventory and package writes, which do not depend on the services.
    #[must_use]
    pub(crate) fn with_remote_features(mut self, inventory_enabled: bool, writes_enabled: bool) -> Self {
        self.remote_inventory_enabled = inventory_enabled;
        self.remote_writes_enabled = writes_enabled;
        self
    }

    #[cfg(windows)]
    pub(super) fn remote_inventory_enabled(&self) -> bool {
        self.remote_inventory_enabled
    }

    #[cfg(windows)]
    pub(super) fn remote_writes_enabled(&self) -> bool {
        self.remote_writes_enabled
    }
}

#[cfg(windows)]
impl DeviceManagementContext {
    /// Adds a running package broker, with the user registry opened below `data_dir`.
    ///
    /// When the registry cannot be opened, the services stay unavailable: a handler must not discover or target users
    /// without it.
    /// The registry is opened here, once, and the open does blocking file I/O.
    pub(crate) fn with_package_broker(
        self,
        registration: RegistrationHandle,
        broker: Arc<BrokerState>,
        data_dir: &Utf8Path,
    ) -> Self {
        self.with_package_broker_using(registration, broker, data_dir, UserRegistry::open)
    }

    fn with_package_broker_using(
        self,
        registration: RegistrationHandle,
        broker: Arc<BrokerState>,
        data_dir: &Utf8Path,
        open_users: fn(&Utf8Path) -> anyhow::Result<UserRegistry>,
    ) -> Self {
        let directory = USER_REGISTRY_DIR
            .iter()
            .fold(data_dir.to_owned(), |path, leaf| path.join(leaf));
        // UNTESTED: A journal-open failure must not disable live inventory, which shares this context.
        // The context test has no authenticated UniGetUI client; request inventory with a corrupt journal when changing this.
        let journal = match OperationJournal::open(data_dir) {
            Ok(journal) => Some(Arc::new(journal)),
            Err(error) => {
                error!(
                    error = format!("{error:#}"),
                    %data_dir,
                    "Cannot open the device-management operation journal; package writes are unavailable"
                );
                None
            }
        };

        match open_users(&directory) {
            Ok(users) => Self {
                registration: Some(registration),
                broker: Some(broker),
                users: Some(Arc::new(users)),
                journal,
                ..self
            },
            Err(error) => {
                error!(
                    error = format!("{error:#}"),
                    %directory,
                    "Cannot open the device-management user registry; device management is unavailable"
                );
                Self {
                    registration: None,
                    broker: None,
                    users: None,
                    journal: None,
                    ..self
                }
            }
        }
    }

    pub(crate) fn registration(&self) -> Option<&RegistrationHandle> {
        self.registration.as_ref()
    }

    pub(crate) fn broker(&self) -> Option<&Arc<BrokerState>> {
        self.broker.as_ref()
    }

    pub(crate) fn users(&self) -> Option<&Arc<UserRegistry>> {
        self.users.as_ref()
    }

    /// The durable operation journal; `None` makes package writes unavailable.
    pub(super) fn journal(&self) -> Option<&Arc<OperationJournal>> {
        self.journal.as_ref()
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::time::Duration;

    use agent_channel_proto::{PackageOperationRequest, PackageOperationStatus, PackageOperationType};
    use now_package_broker::registration::run_registration_server;
    use now_package_broker::task::{BrokerTask, BrokerTaskConfig};
    use uuid::Uuid;

    use super::*;
    use crate::device_management::operation;
    use crate::device_management::operation_journal::{Admission, Outcome, Settled};

    #[tokio::test]
    async fn corrupt_journal_disables_writes_but_not_discovery() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
        let parent = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = tempfile::Builder::new().prefix("operation-").tempdir_in(parent)?;
        let data = Utf8Path::from_path(root.path()).expect("data path is UTF-8");
        let request = PackageOperationRequest {
            operation_id: "operation-1".to_owned(),
            r#type: PackageOperationType::Install.into(),
            manager: "Pip".to_owned(),
            source: "pip".to_owned(),
            package_id: "six".to_owned(),
            scope: "User".to_owned(),
            target_user_uuid: Uuid::new_v4().to_string(),
            registry_epoch: Uuid::new_v4().to_string(),
            ..Default::default()
        };
        let journal = OperationJournal::open(data)?;
        journal.admit(&Uuid::nil().to_string(), &request)?;
        drop(journal);
        std::fs::remove_dir_all(data.join("package-operations").join("records"))?;

        let broker = BrokerTask::new(BrokerTaskConfig {
            policy_path: Some(data.join("missing-policy.json").to_string()),
            ..Default::default()
        });
        let registration = broker.registration();
        let pipe = format!(r"\\.\pipe\agent-journal-test-{}", Uuid::new_v4().simple());
        let server_registration = registration.clone();
        let server =
            tokio::spawn(async move { run_registration_server(&server_registration, &pipe, Default::default()).await });
        tokio::time::timeout(Duration::from_secs(10), async {
            while registration.snapshot().is_err() && !server.is_finished() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        registration.snapshot()?;

        let context = DeviceManagementContext::default().with_package_broker_using(
            registration,
            broker.state(),
            data,
            UserRegistry::open_for_test,
        );
        let result = operation::run(&context, Uuid::nil(), request).await;
        assert_eq!(result.status, i32::from(PackageOperationStatus::Unknown));
        assert_eq!(result.operation_id, "operation-1");
        assert_eq!(result.execution_started, None);
        assert!(matches!(
            super::super::package_operation_report(result).report,
            Some(agent_channel_proto::device_management_report::Report::PackageOperationUnknown(_))
        ));
        let discovered = super::super::collect_instances(&context).await?;
        assert!(discovered.instances.is_empty());
        assert_eq!(Uuid::parse_str(&discovered.registry_epoch)?.get_version_num(), 4);
        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn recorded_failure_with_empty_error_is_unknown() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let parent = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = tempfile::Builder::new().prefix("operation-").tempdir_in(parent)?;
        let data = Utf8Path::from_path(root.path()).expect("data path is UTF-8");
        let request = PackageOperationRequest {
            operation_id: "operation-1".to_owned(),
            ..Default::default()
        };
        let authority = Uuid::nil();
        let journal = OperationJournal::open(data)?;
        assert_eq!(journal.admit(&authority.to_string(), &request)?, Admission::Admitted);
        journal.complete(
            &authority.to_string(),
            &request,
            Outcome::Failed {
                error: "rejected".to_owned(),
            },
        )?;
        drop(journal);

        let records = data.join("package-operations").join("records");
        let record = std::fs::read_dir(records)?
            .map(|entry| entry.expect("record entry is readable").path())
            .find(|path| path.file_name().expect("record has a name") != "journal.json")
            .expect("operation record exists");
        let mut stored: serde_json::Value = serde_json::from_slice(&std::fs::read(&record)?)?;
        stored["outcome"]["failed"]["error"] = String::new().into();
        std::fs::write(record, serde_json::to_vec(&stored)?)?;

        let context = DeviceManagementContext {
            journal: Some(Arc::new(OperationJournal::open(data)?)),
            ..Default::default()
        };
        let result = operation::run(&context, authority, request).await;

        assert_eq!(result.status, i32::from(PackageOperationStatus::Unknown));
        Ok(())
    }

    #[tokio::test]
    async fn damaged_live_journal_returns_unknown_for_new_writes_and_keeps_recorded_results() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let parent = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = tempfile::Builder::new().prefix("operation-").tempdir_in(parent)?;
        let data = Utf8Path::from_path(root.path()).expect("data path is UTF-8");
        let known = PackageOperationRequest {
            operation_id: "known".to_owned(),
            ..Default::default()
        };
        let new = PackageOperationRequest {
            operation_id: "new".to_owned(),
            ..Default::default()
        };
        let authority = Uuid::nil();
        let journal = Arc::new(OperationJournal::open(data)?);
        journal.admit(&authority.to_string(), &known)?;
        journal.complete(&authority.to_string(), &known, Outcome::Succeeded)?;
        let context = DeviceManagementContext {
            journal: Some(journal),
            ..Default::default()
        };
        let index = data.join("package-operations").join("records").join("journal.json");
        std::fs::remove_file(&index)?;

        let refused = operation::run(&context, authority, new).await;
        assert_eq!(refused.status, i32::from(PackageOperationStatus::Unknown));
        assert!(!refused.success);
        assert!(refused.error.is_empty());
        assert_eq!(refused.execution_started, None);
        assert!(!index.exists());
        let recorded = operation::run(&context, authority, known).await;
        assert_eq!(recorded.status, i32::from(PackageOperationStatus::Unspecified));
        assert!(recorded.success);
        Ok(())
    }

    #[tokio::test]
    async fn changed_payload_for_recorded_operation_is_unknown() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let parent = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = tempfile::Builder::new().prefix("operation-").tempdir_in(parent)?;
        let data = Utf8Path::from_path(root.path()).expect("data path is UTF-8");
        let request = PackageOperationRequest {
            operation_id: "operation-1".to_owned(),
            package_id: "original".to_owned(),
            ..Default::default()
        };
        let authority = Uuid::nil();
        let journal = Arc::new(OperationJournal::open(data)?);
        assert_eq!(journal.admit(&authority.to_string(), &request)?, Admission::Admitted);
        journal.mark_started(&authority.to_string(), &request)?;
        journal.complete(&authority.to_string(), &request, Outcome::Succeeded)?;
        let context = DeviceManagementContext {
            journal: Some(Arc::clone(&journal)),
            ..Default::default()
        };
        let changed = PackageOperationRequest {
            package_id: "different".to_owned(),
            ..request.clone()
        };

        let result = operation::run(&context, authority, changed).await;

        assert_eq!(result.status, i32::from(PackageOperationStatus::Unknown));
        assert_eq!(
            journal.admit(&authority.to_string(), &request)?,
            Admission::Recorded(Settled {
                outcome: Outcome::Succeeded,
                execution_started: Some(true),
            })
        );
        Ok(())
    }
}
