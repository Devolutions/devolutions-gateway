use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::err::HandlerError;

#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ElevateTemporaryPayload {
    /// The number of seconds to elevate the user for.
    ///
    /// This must be between 1 and `i32::MAX`.
    pub(crate) seconds: u64,
}

/// Temporarily elevates the user's session.
pub(crate) async fn elevate_temporary() -> Result<(), HandlerError> {
    unimplemented!()
}
