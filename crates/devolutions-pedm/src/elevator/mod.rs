mod local_admin_elevator;
mod virtual_account_elevator;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::OnceLock;

use devolutions_pedm_shared::policy::{ElevationMethod, ElevationRequest, ElevationResult};
use local_admin_elevator::LocalAdminElevator;
use virtual_account_elevator::VirtualAccountElevator;
use win_api_wrappers::win::environment_block;
use win_api_wrappers::{
    raw::Win32::{Foundation::ERROR_INVALID_PARAMETER, System::Threading::PROCESS_CREATION_FLAGS},
    win::{parse_command_line, ProcessInformation, StartupInfo, Token, TokenElevationType},
    Error,
};

use anyhow::{anyhow, Result};

use crate::policy::{self, application_from_path};
use crate::utils::{start_process, AccountExt};
use crate::{config, log};

trait Elevator {
    fn elevate_token(&self, token: &Token) -> Result<Token>;
}

fn local_admin_elevator() -> &'static LocalAdminElevator {
    static ELEVATOR: OnceLock<LocalAdminElevator> = OnceLock::new();
    ELEVATOR.get_or_init(|| LocalAdminElevator::new(&config::LADM_SRC_NAME, config::LADM_SRC_LUID))
}

fn virtual_account_elevator() -> &'static VirtualAccountElevator {
    static ELEVATOR: OnceLock<VirtualAccountElevator> = OnceLock::new();
    ELEVATOR.get_or_init(|| VirtualAccountElevator::new(config::VADM_DOMAIN.to_owned(), config::VADM_RID))
}

fn elevator(method: ElevationMethod) -> &'static dyn Elevator {
    match method {
        ElevationMethod::LocalAdmin => local_admin_elevator(),
        ElevationMethod::VirtualAccount => virtual_account_elevator(),
    }
}

fn elevate_token(token: &Token) -> Result<Token> {
    match token.elevation_type()? {
        TokenElevationType::Default => {
            let policy = policy::policy().read().unwrap();
            let elevation_method = policy
                .user_current_profile(&token.sid_and_attributes()?.sid.account(None)?.to_user())
                .ok_or_else(|| anyhow!("User not assigned"))?
                .elevation_method;
            elevator(elevation_method).elevate_token(token)
        }
        TokenElevationType::Full => token.try_clone(),
        TokenElevationType::Limited => token.linked_token(),
    }
}

fn validate_elevation(
    client_token: &Token,
    client_pid: u32,
    executable_path: Option<&Path>,
    command_line: Option<&str>,
    working_directory: Option<&Path>,
) -> Result<()> {
    let asker = policy::application_from_process(client_pid)?;
    let working_directory = working_directory
        .unwrap_or_else(|| asker.working_directory.as_path())
        .to_owned();

    let (executable_path, command_line) = match (executable_path, command_line) {
        (None, None) => Err(Error::from_win32(ERROR_INVALID_PARAMETER)),
        (None, Some(command_line)) => Ok::<_, Error>((
            parse_command_line(command_line)?
                .get(0)
                .and_then(|x| PathBuf::from_str(x).ok())
                .ok_or_else(|| Error::from_win32(ERROR_INVALID_PARAMETER))?,
            command_line.to_owned(),
        )),
        (Some(executable_path), None) => Ok((
            executable_path.to_owned(),
            executable_path
                .to_str()
                .ok_or_else(|| Error::from_win32(ERROR_INVALID_PARAMETER))?
                .to_owned(),
        )),
        (Some(executable_path), Some(command_line)) => Ok((executable_path.to_owned(), command_line.to_owned())),
    }?;

    let target = application_from_path(executable_path, command_line, working_directory, asker.user.clone())?;

    let req = ElevationRequest::new(asker, target);

    let validation = policy::policy()
        .read()
        .unwrap()
        .validate(client_token.session_id()?, &req);

    log::log_elevation(&ElevationResult {
        request: req,
        successful: validation.is_ok(),
    })?;

    validation
}

pub fn try_start_elevated(
    client_token: &Token,
    client_pid: u32,
    executable_path: Option<&Path>,
    command_line: Option<&str>,
    creation_flags: PROCESS_CREATION_FLAGS,
    current_directory: Option<&Path>,
    startup_info: &mut StartupInfo,
) -> Result<ProcessInformation> {
    validate_elevation(
        client_token,
        client_pid,
        executable_path,
        command_line,
        current_directory,
    )?;

    let elevation = elevate_token(client_token)?;

    // Build environment with client token, as admin token might be Virtual Account.
    let environment = environment_block(Some(&client_token), false)?;

    Ok(start_process(
        &elevation.duplicate_impersonation()?,
        executable_path,
        command_line,
        false,
        creation_flags,
        Some(&environment),
        current_directory,
        startup_info,
    )?)
}
