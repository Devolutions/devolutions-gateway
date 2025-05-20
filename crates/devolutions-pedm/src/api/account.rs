use aide::NoApi;
use axum::Json;
use schemars::JsonSchema;
use serde::Serialize;

use crate::account::AccountWithId;
use crate::db::Db;

use super::err::HandlerError;

/// An account with its ID, name, and SID.
#[derive(Serialize, JsonSchema)]
pub(crate) struct AccountData {
    pub(crate) id: i16,
    pub(crate) name: String,
    pub(crate) sid: String,
}

impl From<AccountWithId> for AccountData {
    fn from(account: AccountWithId) -> Self {
        Self {
            id: account.id,
            name: account.name,
            sid: account.sid.to_string(),
        }
    }
}

/// Gets accounts on the system.
///
/// Includes info like the account name and SID.
pub(crate) async fn get_accounts(NoApi(Db(db)): NoApi<Db>) -> Result<Json<Vec<AccountData>>, HandlerError> {
    Ok(Json(db.get_accounts().await?.into_iter().map(Into::into).collect()))
}
