//! Background execution task handling.

use std::sync::Arc;

use now_policy_api::ResourceId;
use tracing::{error, info};

use crate::executor::{CommandExecutor, ExecutionContext, ProcessStartedCallback, is_canceled_error};
use crate::operation_tracker::OperationTracker;

pub(super) fn spawn_execution(
    executor: Arc<dyn CommandExecutor>,
    tracker: OperationTracker,
    operation_id: ResourceId,
    context: ExecutionContext,
) {
    let exe_name = context.command.first().cloned().unwrap_or_else(|| "process".to_owned());
    let operation_id_string = operation_id.to_string();

    tokio::spawn(async move {
        let started_tracker = tracker.clone();
        let started_operation_id = operation_id_string.clone();
        let process_started: ProcessStartedCallback = Arc::new(move |started_at| {
            started_tracker.mark_running(&started_operation_id, started_at);
        });
        match executor.execute(&context, Some(process_started)).await {
            Ok(output) => {
                let note = if output.exit_code == 0 {
                    "process exited successfully".to_owned()
                } else {
                    #[allow(clippy::cast_sign_loss)]
                    let unsigned = output.exit_code as u32;
                    match crate::executor::describe_exit_code(output.exit_code) {
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
                tracker.mark_completed(&operation_id_string, output.exit_code, note, output.started_at);
            }
            Err(error) if is_canceled_error(&error) => {
                info!(operation_id = %operation_id_string, "Background execution canceled");
                tracker.mark_canceled(
                    &operation_id_string,
                    "operation was canceled at the client's request".to_owned(),
                );
            }
            Err(error) => {
                let note = format!("{error:#}");
                error!(operation_id = %operation_id_string, %error, "Background execution failed");
                tracker.mark_failed(&operation_id_string, note);
            }
        }
    });
}
