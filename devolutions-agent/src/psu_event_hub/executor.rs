use std::sync::Arc;

use anyhow::Context as _;
use camino::Utf8PathBuf;
use serde_json::Value;
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::config::dto::PsuEventHubConnectionConf;
use crate::psu_event_hub::models::WebsocketEventResponse;
use crate::psu_event_hub::powershell_worker::PowerShellWorker;
use crate::psu_event_hub::result_store::ResultStore;

#[derive(Debug, Clone)]
pub(super) struct EventHubExecutor {
    hub: String,
    script_path: Option<Utf8PathBuf>,
    worker: Arc<PowerShellWorker>,
    result_store: ResultStore,
}

impl EventHubExecutor {
    pub(super) fn new(connection: &PsuEventHubConnectionConf, worker: Arc<PowerShellWorker>) -> Self {
        Self {
            hub: connection.hub.clone(),
            script_path: connection.script_path.as_ref().map(normalize_script_path),
            worker,
            result_store: ResultStore::default(),
        }
    }

    pub(super) fn handle_invocation(
        &self,
        target: &str,
        arguments: &[Value],
        execution_tasks: &mut JoinSet<()>,
    ) -> anyhow::Result<Option<Value>> {
        if target == "GetResult" {
            let execution_id = required_string_argument(arguments, 0, "event id")?;
            let result = self.result_store.take(execution_id);
            return serde_json::to_value(result)
                .map(Some)
                .context("failed to serialize PSU GetResult response");
        }

        if target == self.hub {
            let data = required_string_argument(arguments, 0, "event data")?.to_owned();
            let execution_id = self.execute_script(data, true, execution_tasks);
            return Ok(Some(Value::String(execution_id)));
        }

        if target == format!("{}Void", self.hub) {
            let data = required_string_argument(arguments, 0, "event data")?.to_owned();
            self.execute_script(data, false, execution_tasks);
            return Ok(None);
        }

        if target == format!("{}Module", self.hub) {
            let command = required_string_argument(arguments, 0, "command")?.to_owned();
            let data = required_string_argument(arguments, 1, "event data")?.to_owned();
            let execution_id = self.execute_command(command, data, true, execution_tasks);
            return Ok(Some(Value::String(execution_id)));
        }

        if target == format!("{}ModuleVoid", self.hub) {
            let command = required_string_argument(arguments, 0, "command")?.to_owned();
            let data = required_string_argument(arguments, 1, "event data")?.to_owned();
            self.execute_command(command, data, false, execution_tasks);
            return Ok(None);
        }

        warn!(%target, hub = %self.hub, "Received unknown PSU Event Hub invocation");
        Ok(None)
    }

    fn execute_command(
        &self,
        command: String,
        data: String,
        return_result: bool,
        execution_tasks: &mut JoinSet<()>,
    ) -> String {
        let execution_id = Uuid::new_v4().to_string();
        let worker = Arc::clone(&self.worker);
        let result_store = self.result_store.clone();
        let stored_execution_id = execution_id.clone();

        execution_tasks.spawn(async move {
            match worker.execute_command(command, data, return_result).await {
                Ok(response) if return_result => result_store.insert(stored_execution_id, response),
                Ok(_) => {}
                Err(error) if return_result => {
                    result_store.insert(
                        stored_execution_id,
                        WebsocketEventResponse::terminating_error(error.to_string()),
                    );
                }
                Err(error) => warn!(error = format!("{error:#}"), "PSU command execution failed"),
            }
        });

        execution_id
    }

    fn execute_script(&self, data: String, return_result: bool, execution_tasks: &mut JoinSet<()>) -> String {
        let execution_id = Uuid::new_v4().to_string();
        let Some(script_path) = self.script_path.clone() else {
            if return_result {
                self.result_store.insert(
                    execution_id.clone(),
                    WebsocketEventResponse::terminating_error("No script block found."),
                );
            }
            return execution_id;
        };

        let worker = Arc::clone(&self.worker);
        let result_store = self.result_store.clone();
        let stored_execution_id = execution_id.clone();

        execution_tasks.spawn(async move {
            match worker.execute_script(script_path, data, return_result).await {
                Ok(response) if return_result => result_store.insert(stored_execution_id, response),
                Ok(_) => {}
                Err(error) if return_result => {
                    result_store.insert(
                        stored_execution_id,
                        WebsocketEventResponse::terminating_error(error.to_string()),
                    );
                }
                Err(error) => warn!(error = format!("{error:#}"), "PSU script execution failed"),
            }
        });

        execution_id
    }
}

fn required_string_argument<'a>(arguments: &'a [Value], index: usize, name: &str) -> anyhow::Result<&'a str> {
    arguments
        .get(index)
        .and_then(Value::as_str)
        .with_context(|| format!("missing or invalid PSU invocation argument: {name}"))
}

fn normalize_script_path(path: &Utf8PathBuf) -> Utf8PathBuf {
    if path.is_absolute() {
        return path.clone();
    }

    if let Some(program_data) =
        std::env::var_os("ProgramData").and_then(|path| Utf8PathBuf::from_path_buf(path.into()).ok())
    {
        return program_data.join("PowerShellUniversal").join(path);
    }

    path.clone()
}
