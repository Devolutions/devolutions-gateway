use std::{
    fs,
    path::{Path, PathBuf},
};

use axum::{Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::info;
use win_api_wrappers::{
    raw::Win32::{
        Security::{WinLocalSystemSid, TOKEN_QUERY},
        System::Threading::{
            PROCESS_CREATE_PROCESS, PROCESS_CREATION_FLAGS, PROCESS_QUERY_INFORMATION, STARTUPINFOW_FLAGS,
        },
    },
    win::{
        environment_block, expand_environment_path, Process, Sid, StartupInfo, ThreadAttributeList,
        ThreadAttributeType, Token, WideString,
    },
};

use crate::{elevator, error::Error};

use super::NamedPipeConnectInfo;

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub struct StartupInfoDto {
    pub desktop: Option<String>,
    pub title: Option<String>,
    pub x: u32,
    pub y: u32,
    pub x_size: u32,
    pub y_size: u32,
    pub x_count_chars: u32,
    pub y_count_chars: u32,
    pub fill_attribute: u32,
    pub flags: u32,
    pub show_window: u16,
    pub parent_pid: u32,
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
pub struct LaunchPayload {
    pub executable_path: Option<PathBuf>,
    pub command_line: Option<String>,
    pub creation_flags: u32,
    pub working_directory: Option<PathBuf>,
    pub startup_info: Option<StartupInfoDto>,
}

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub struct LaunchResponse {
    pub process_id: u32,
    pub thread_id: u32,
}

fn win_canonicalize(path: &Path, token: Option<&Token>) -> Result<PathBuf, Error> {
    let environment = environment_block(token, false)?;

    let path = expand_environment_path(path, &environment)?;

    Ok(fs::canonicalize(path)?)
}

pub async fn post_launch(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    Json(mut payload): Json<LaunchPayload>,
) -> Result<Json<LaunchResponse>, Error> {
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
        .map_or(named_pipe_info.pipe_process_id, |x| x.parent_pid);

    let process = Process::try_get_by_pid(parent_pid, PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS)?;

    let caller_sid = named_pipe_info.token.sid_and_attributes()?.sid;
    if caller_sid != Sid::from_well_known(WinLocalSystemSid, None)? {
        let process_token = process.token(TOKEN_QUERY)?;

        if process_token.sid_and_attributes()?.sid != caller_sid
            || process_token.session_id()? != named_pipe_info.token.session_id()?
        {
            return Err(Error::AccessDenied);
        }
    }

    let mut attributes = ThreadAttributeList::with_count(1)?;
    let attr = ThreadAttributeType::ParentProcess(&process);
    attributes.update(&attr)?;

    startup_info.attribute_list = Some(Some(attributes.raw()));

    let proc_info = elevator::try_start_elevated(
        &named_pipe_info.token,
        parent_pid,
        payload.executable_path.as_deref(),
        payload.command_line.as_deref(),
        PROCESS_CREATION_FLAGS(payload.creation_flags),
        payload.working_directory.as_deref(),
        &mut startup_info,
    )?;

    Ok(Json(LaunchResponse {
        process_id: proc_info.process_id,
        thread_id: proc_info.thread_id,
    }))
}
