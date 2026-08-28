//! Test infrastructure for package broker integration tests.

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use axum::Router;
use now_policy::PolicyDocument;

use super::{BrokerState, ManagerProbeCache, build_router_for_client};
use crate::auth::PipeClient;
use crate::executor::{CommandExecutor, ExecutionContext, ExecutionOutput, ProcessStartedCallback};
use crate::operation_tracker::OperationTracker;

struct NoopExecutor;

#[async_trait]
impl CommandExecutor for NoopExecutor {
    async fn execute(
        &self,
        _ctx: &ExecutionContext,
        _process_started: Option<ProcessStartedCallback>,
    ) -> anyhow::Result<ExecutionOutput> {
        anyhow::bail!("not used in route tests")
    }
}

/// Builds the production package broker router around an optional active policy.
///
/// Client signature validation is skipped through the compile-time test feature.
pub fn router(policy: Option<PolicyDocument>) -> anyhow::Result<Router> {
    let state = Arc::new(BrokerState {
        policy: RwLock::new(policy.map(Arc::new)),
        executor: Arc::new(NoopExecutor),
        pipe_name: "testsuite-policy-pipe".to_owned(),
        tracker: OperationTracker::new(),
        skip_signature_validation: true,
        manager_probe_cache: ManagerProbeCache::default(),
    });
    let client = PipeClient::from_current_process()?;

    Ok(build_router_for_client(state, client))
}
