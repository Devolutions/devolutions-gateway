//! The services every device-management request handler shares.
//!
//! One context serves every Authority link of every identity, so they all resolve users through one registry.
//! A default context has no services, and device management stays unavailable through it.

#[cfg(windows)]
use std::sync::Arc;

#[cfg(windows)]
use camino::Utf8Path;
#[cfg(windows)]
use devolutions_gateway_task::ShutdownSignal;
#[cfg(windows)]
use now_package_broker::registration::RegistrationHandle;
#[cfg(windows)]
use now_package_broker::server::BrokerState;

#[cfg(windows)]
use super::operation::Coordinator;
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
    #[cfg(windows)]
    shutdown: Option<ShutdownSignal>,
    #[cfg(windows)]
    operations: Arc<Coordinator>,
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
            #[cfg(windows)]
            shutdown: None,
            #[cfg(windows)]
            operations: Arc::new(Coordinator::default()),
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
    pub(crate) fn with_shutdown(mut self, shutdown: ShutdownSignal) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    pub(super) fn shutdown(&self) -> Option<ShutdownSignal> {
        self.shutdown.clone()
    }

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
        // UNTESTED: A damaged journal must remain in this context until the Agent process exits.
        // Check the service and context lifecycle before allowing a journal to be reopened.
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

    pub(super) fn operations(&self) -> &Arc<Coordinator> {
        &self.operations
    }
}

#[cfg(all(test, windows))]
impl DeviceManagementContext {
    pub(crate) fn with_full_journal_for_test(mut self, data_dir: &Utf8Path) -> anyhow::Result<Self> {
        let mut journal = OperationJournal::open(data_dir)?;
        journal.exhaust_index_for_test();
        self.journal = Some(Arc::new(journal));
        Ok(self)
    }

    pub(crate) fn with_recorded_operation_for_test(
        mut self,
        data_dir: &Utf8Path,
        request: &agent_channel_proto::PackageOperationRequest,
    ) -> anyhow::Result<(Self, std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>)> {
        use super::operation_journal::{Admission, Outcome};

        let mut journal = OperationJournal::open(data_dir)?;
        anyhow::ensure!(
            journal.admit(&uuid::Uuid::nil().to_string(), request)? == Admission::Admitted,
            "test operation was not admitted"
        );
        journal.complete(&uuid::Uuid::nil().to_string(), request, Outcome::Succeeded)?;
        let (entered, resume) = journal.pause_index_write_for_test();
        self.journal = Some(Arc::new(journal));
        Ok((self, entered, resume))
    }

    pub(crate) async fn submit_operation_for_test(
        &self,
        request: agent_channel_proto::PackageOperationRequest,
    ) -> agent_channel_proto::PackageOperationResult {
        super::operation::run(self, uuid::Uuid::nil(), request).await
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
        assert_eq!(refused.execution_started, None);
        assert!(!index.exists());
        let recorded = operation::run(&context, authority, known).await;
        assert_eq!(recorded.status, i32::from(PackageOperationStatus::Unspecified));
        assert!(recorded.success);

        let mut permits = Vec::new();
        while let Some(permit) = context.operations().try_worker() {
            permits.push(permit);
        }
        assert!(!permits.is_empty());
        let refused = operation::run(
            &context,
            authority,
            PackageOperationRequest {
                operation_id: "another-new".to_owned(),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(refused.status, i32::from(PackageOperationStatus::Unknown));
        assert_eq!(refused.execution_started, None);
        Ok(())
    }

    #[test]
    fn legacy_operation_id_is_not_ignored_while_the_journal_is_refused() -> anyhow::Result<()> {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        // oracle: regression #2197 a refused journal let the malformed-ID check drop a possibly recorded ID
        let parent = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = tempfile::Builder::new().prefix("operation-").tempdir_in(parent)?;
        let data = Utf8Path::from_path(root.path()).expect("data path is UTF-8");
        drop(OperationJournal::open(data)?);
        std::fs::write(
            data.join("package-operations").join("records").join("journal.json"),
            b"{",
        )?;
        let context = DeviceManagementContext {
            journal: Some(Arc::new(OperationJournal::open(data)?)),
            ..Default::default()
        };
        let request = agent_channel_proto::DeviceManagementRequest {
            request: Some(
                agent_channel_proto::device_management_request::Request::PackageOperation(PackageOperationRequest {
                    operation_id: "legacy-id".to_owned(),
                    ..Default::default()
                }),
            ),
        };

        assert!(!super::super::has_unrecorded_malformed_operation_id(&context, &request));
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
        let mut permits = Vec::new();
        while let Some(permit) = context.operations().try_worker() {
            permits.push(permit);
        }
        assert!(!permits.is_empty());

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

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn a_new_operation_at_capacity_is_busy_and_can_be_delivered_later() -> anyhow::Result<()> {
        let parent = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = tempfile::Builder::new().prefix("operation-").tempdir_in(parent)?;
        let data = Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let journal = Arc::new(OperationJournal::open(data)?);
        let context = DeviceManagementContext {
            journal: Some(Arc::clone(&journal)),
            ..Default::default()
        }
        .with_remote_features(true, false);
        let request = PackageOperationRequest {
            operation_id: "11111111-2222-4333-8444-555555555555".to_owned(),
            ..Default::default()
        };
        let mut permits = Vec::new();
        while let Some(permit) = context.operations().try_worker() {
            permits.push(permit);
        }
        assert!(!permits.is_empty());

        let busy = operation::run(&context, Uuid::nil(), request.clone()).await;
        assert_eq!(busy.operation_id, request.operation_id);
        assert!(!busy.success);
        assert_eq!(busy.error, "agent busy: nothing was started");
        assert_eq!(busy.status, i32::from(PackageOperationStatus::Unspecified));
        assert_eq!(busy.execution_started, None);

        drop(permits);
        let later = operation::run(&context, Uuid::nil(), request).await;
        assert_eq!(later.error, "remote package writes are disabled");
        assert_eq!(later.status, i32::from(PackageOperationStatus::Unspecified));
        Ok(())
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-remote-operations
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn a_recorded_operation_is_replayed_at_capacity() -> anyhow::Result<()> {
        let parent = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = tempfile::Builder::new().prefix("operation-").tempdir_in(parent)?;
        let data = Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let journal = Arc::new(OperationJournal::open(data)?);
        let request = PackageOperationRequest {
            operation_id: "recorded-operation".to_owned(),
            ..Default::default()
        };
        let authority = Uuid::nil();
        assert_eq!(journal.admit(&authority.to_string(), &request)?, Admission::Admitted);
        journal.mark_started(&authority.to_string(), &request)?;
        journal.complete(&authority.to_string(), &request, Outcome::Succeeded)?;
        let context = DeviceManagementContext {
            journal: Some(journal),
            ..Default::default()
        };
        let mut permits = Vec::new();
        while let Some(permit) = context.operations().try_worker() {
            permits.push(permit);
        }
        assert!(!permits.is_empty());

        let replay = operation::run(&context, authority, request).await;

        assert_eq!(replay.operation_id, "recorded-operation");
        assert!(replay.success);
        assert_eq!(replay.error, "");
        assert_eq!(replay.status, i32::from(PackageOperationStatus::Unspecified));
        assert_eq!(replay.execution_started, Some(true));
        Ok(())
    }
}
