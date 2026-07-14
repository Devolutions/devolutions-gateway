//! Background execution task handling.

use std::sync::Arc;

use now_policy_api::ResourceId;
use tracing::{error, info};

use crate::broker::executor::{CommandExecutor, ExecutionContext};
use crate::broker::operation_tracker::OperationTracker;

pub(super) fn spawn_execution(
    executor: Arc<dyn CommandExecutor>,
    tracker: OperationTracker,
    operation_id: ResourceId,
    context: ExecutionContext,
) {
    let exe_name = context.command.first().cloned().unwrap_or_else(|| "process".to_owned());
    let operation_id_string = operation_id.to_string();

    tokio::spawn(async move {
        let timeout = OperationTracker::operation_timeout();
        match tokio::time::timeout(timeout, executor.execute(&context)).await {
            Ok(Ok(output)) => {
                let stdout = (!output.stdout.is_empty()).then_some(output.stdout);
                let note = if output.exit_code == 0 {
                    "process exited successfully".to_owned()
                } else {
                    #[allow(clippy::cast_sign_loss)]
                    let unsigned = output.exit_code as u32;
                    match crate::broker::executor::describe_exit_code(output.exit_code) {
                        Some(description) => format!(
                            "{exe_name} exited with code {} (0x{unsigned:08X}): {description}",
                            output.exit_code
                        ),
                        None => format!("{exe_name} exited with code {} (0x{unsigned:08X})", output.exit_code),
                    }
                };
                info!(
                    operation_id = %operation_id_string,
                    exit_code = output.exit_code,
                    "Background execution completed"
                );
                tracker.mark_completed(&operation_id_string, output.exit_code, note, stdout);
            }
            Ok(Err(error)) => {
                let note = format!("{error:#}");
                error!(operation_id = %operation_id_string, %error, "Background execution failed");
                tracker.mark_failed(&operation_id_string, note, None);
            }
            Err(_elapsed) => {
                let note = format!("operation timed out after {} seconds", timeout.as_secs());
                error!(
                    operation_id = %operation_id_string,
                    timeout_secs = timeout.as_secs(),
                    "Background execution timed out"
                );
                tracker.mark_failed(&operation_id_string, note, None);
            }
        }
    });
}
