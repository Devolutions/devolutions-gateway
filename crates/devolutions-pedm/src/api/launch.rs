use std::path::{Path, PathBuf};

use aide::NoApi;
use axum::extract::State;
use axum::{Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::info;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::process::{Process, StartupInfo};
use win_api_wrappers::raw::Win32::Security::{TOKEN_QUERY, WinLocalSystemSid};
use win_api_wrappers::raw::Win32::System::Threading::{
    PROCESS_CREATE_PROCESS, PROCESS_CREATION_FLAGS, PROCESS_QUERY_INFORMATION, STARTUPINFOW_FLAGS,
};
use win_api_wrappers::thread::{ThreadAttributeList, ThreadAttributeType};
use win_api_wrappers::token::Token;
use win_api_wrappers::utils::{CommandLine, WideString, environment_block, expand_environment_path};

use super::NamedPipeConnectInfo;
use crate::api::state::AppState;
use crate::elevator;
use crate::error::Error;
use crate::policy::Policy;

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct StartupInfoDto {
    pub(crate) desktop: Option<String>,
    pub(crate) title: Option<String>,
    pub(crate) x: u32,
    pub(crate) y: u32,
    pub(crate) x_size: u32,
    pub(crate) y_size: u32,
    pub(crate) x_count_chars: u32,
    pub(crate) y_count_chars: u32,
    pub(crate) fill_attribute: u32,
    pub(crate) flags: u32,
    pub(crate) show_window: u16,
    pub(crate) parent_pid: Option<u32>,
}

impl From<&StartupInfoDto> for StartupInfo {
    fn from(value: &StartupInfoDto) -> Self {
        Self {
            desktop: value.desktop.as_ref().map(WideString::from).unwrap_or_default(),
            title: value.title.as_ref().map(WideString::from).unwrap_or_default(),
            x: value.x,
            y: value.y,
            x_size: value.x_size,
            y_size: value.y_size,
            x_count_chars: value.x_count_chars,
            y_count_chars: value.y_count_chars,
            fill_attribute: value.fill_attribute,
            flags: STARTUPINFOW_FLAGS(value.flags),
            show_window: value.show_window,
            ..Default::default()
        }
    }
}

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct LaunchPayload {
    pub(crate) executable_path: Option<PathBuf>,
    pub(crate) command_line: Option<String>,
    pub(crate) creation_flags: u32,
    pub(crate) working_directory: Option<PathBuf>,
    pub(crate) startup_info: Option<StartupInfoDto>,
}

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct LaunchResponse {
    pub(crate) process_id: u32,
    pub(crate) thread_id: u32,
}

fn win_canonicalize(path: &Path, token: Option<&Token>) -> Result<PathBuf, Error> {
    let environment = environment_block(token, false)?;

    let path = expand_environment_path(path, &environment)?;
    Ok(dunce::canonicalize(path)?)
}

pub(crate) async fn post_launch(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(State(state)): NoApi<State<AppState>>,
    Json(mut payload): Json<LaunchPayload>,
) -> Result<Json<LaunchResponse>, Error> {
    let profile = state.db.get_user_profile(&named_pipe_info.user).await?;
    let policy = Policy { profile };

    payload.executable_path = payload
        .executable_path
        .map(|x| win_canonicalize(&x, Some(named_pipe_info.token.as_ref())))
        .transpose()?;

    payload.working_directory = payload
        .working_directory
        .map(|x| win_canonicalize(&x, Some(named_pipe_info.token.as_ref())))
        .transpose()?;

    info!(?payload, "Received launch request");

    let mut startup_info = payload.startup_info.as_ref().map(StartupInfo::from).unwrap_or_default();

    let parent_pid = payload
        .startup_info
        .as_ref()
        .and_then(|x| x.parent_pid)
        .unwrap_or(named_pipe_info.pipe_process_id);

    let process = Process::get_by_pid(parent_pid, PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS)?;

    let caller_sid = named_pipe_info.token.sid_and_attributes()?.sid;

    // If NT AUTHORITY\SYSTEM is caller, it can be on behalf of anyone
    if caller_sid != Sid::from_well_known(WinLocalSystemSid, None)? {
        let process_token = process.token(TOKEN_QUERY)?;

        if process_token.sid_and_attributes()?.sid != caller_sid
            || process_token.session_id()? != named_pipe_info.token.session_id()?
        {
            info!(user = ?named_pipe_info.user, "User tried to create process under an unowned process");
            return Err(Error::AccessDenied);
        }
    }

    let mut attributes = ThreadAttributeList::with_count(1)?;
    let attr = ThreadAttributeType::ParentProcess(&process);
    attributes.update(&attr)?;

    startup_info.attribute_list = Some(Some(attributes.raw()));

    let proc_info = elevator::try_start_elevated(
        &state.db_handle,
        &policy,
        &named_pipe_info.token,
        parent_pid,
        payload.executable_path.as_deref(),
        payload
            .command_line
            .as_deref()
            .map(CommandLine::from_command_line)
            .as_ref(),
        PROCESS_CREATION_FLAGS(payload.creation_flags),
        payload.working_directory.as_deref(),
        &mut startup_info,
    )?;

    Ok(Json(LaunchResponse {
        process_id: proc_info.process_id,
        thread_id: proc_info.thread_id,
    }))
}
