//! Module in charge of elevating tokens.
mod local_admin_elevator;
mod virtual_account_elevator;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::OnceLock;

use devolutions_pedm_shared::policy::{ElevationMethod, ElevationRequest, ElevationResult};
use local_admin_elevator::LocalAdminElevator;
use virtual_account_elevator::VirtualAccountElevator;
use win_api_wrappers::process::{ProcessInformation, StartupInfo};
use win_api_wrappers::raw::Win32::Foundation::ERROR_INVALID_PARAMETER;
use win_api_wrappers::raw::Win32::System::Threading::PROCESS_CREATION_FLAGS;
use win_api_wrappers::token::{Token, TokenElevationType, TokenSecurityAttribute, TokenSecurityAttributeValues};
use win_api_wrappers::undoc::{TOKEN_SECURITY_ATTRIBUTE_FLAG, TOKEN_SECURITY_ATTRIBUTE_OPERATION};
use win_api_wrappers::utils::{environment_block, CommandLine, WideString};
use win_api_wrappers::Error;

use anyhow::{anyhow, Result};

use crate::policy::{self, application_from_path};
use crate::utils::{start_process, AccountExt};
use crate::{config, log};

trait Elevator {
    fn elevate_token(&self, token: &Token) -> Result<Token>;
}

fn local_admin_elevator() -> &'static LocalAdminElevator {
    static ELEVATOR: OnceLock<LocalAdminElevator> = OnceLock::new();
    ELEVATOR.get_or_init(|| LocalAdminElevator::new(config::LADM_SRC_NAME, config::LADM_SRC_LUID))
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
            let policy = policy::policy().read();
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
    command_line: Option<&CommandLine>,
    working_directory: Option<&Path>,
) -> Result<()> {
    let asker = policy::application_from_process(client_pid)?;
    let working_directory = working_directory
        .unwrap_or(asker.working_directory.as_path())
        .to_owned();

    let (executable_path, command_line) = match (executable_path, command_line) {
        (None, None) => Err(Error::from_win32(ERROR_INVALID_PARAMETER)),
        (None, Some(command_line)) => Ok::<_, Error>((
            command_line
                .args()
                .first()
                .and_then(|x| PathBuf::from_str(x).ok())
                .ok_or_else(|| Error::from_win32(ERROR_INVALID_PARAMETER))?,
            command_line.clone(),
        )),
        (Some(executable_path), None) => Ok((
            executable_path.to_owned(),
            CommandLine::new(vec![executable_path
                .to_str()
                .ok_or_else(|| Error::from_win32(ERROR_INVALID_PARAMETER))?
                .to_owned()]),
        )),
        (Some(executable_path), Some(command_line)) => Ok((executable_path.to_owned(), command_line.clone())),
    }?;

    let target = application_from_path(executable_path, command_line, working_directory, asker.user.clone())?;

    let req = ElevationRequest::new(asker, target);

    let validation = policy::policy().read().validate(client_token.session_id()?, &req);

    log::log_elevation(&ElevationResult {
        request: req,
        successful: validation.is_ok(),
    })?;

    validation
}

pub(crate) fn try_start_elevated(
    client_token: &Token,
    client_pid: u32,
    executable_path: Option<&Path>,
    command_line: Option<&CommandLine>,
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

    let mut elevation = elevate_token(client_token)?.duplicate_impersonation()?;

    let attribute = TokenSecurityAttribute {
        name: WideString::from("PEDM_TAGGED"),
        flags: TOKEN_SECURITY_ATTRIBUTE_FLAG(0),
        values: TokenSecurityAttributeValues::Uint64(vec![0x1337, 1337]),
    };

    elevation.apply_security_attribute(
        TOKEN_SECURITY_ATTRIBUTE_OPERATION::TOKEN_SECURITY_ATTRIBUTE_OPERATION_ADD,
        &attribute,
    )?;

    // Build environment with client token, as admin token might be Virtual Account.
    let environment = environment_block(Some(client_token), false)?;

    start_process(
        &elevation,
        executable_path,
        command_line,
        false,
        creation_flags,
        Some(&environment),
        current_directory,
        startup_info,
    )
}
