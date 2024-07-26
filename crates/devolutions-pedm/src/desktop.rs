use std::io::Read;
use std::path::Path;

use anyhow::Result;

use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::process::{Process, StartupInfo};
use win_api_wrappers::raw::Win32::Foundation::ERROR_BAD_ARGUMENTS;
use win_api_wrappers::raw::Win32::Security::{
    SecurityAnonymous, TokenPrimary, TOKEN_ACCESS_MASK, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
};
use win_api_wrappers::raw::Win32::System::Threading::CREATE_SUSPENDED;
use win_api_wrappers::security::acl::SecurityAttributes;
use win_api_wrappers::thread::{ThreadAttributeList, ThreadAttributeType};
use win_api_wrappers::utils::{CommandLine, Pipe, WideString};

use crate::utils::{start_process, AccountExt};
use crate::{config, policy};

static SECURE_DESKTOP: &str = r"WinSta0\Winlogon";

fn launch_desktop(
    session_id: u32,
    verb: &str,
    argument: Option<&str>,
    user_behalf: &Sid,
    secure_desktop: bool,
) -> Result<Vec<u8>> {
    let mut token = Process::current_process()
        .token(
            TOKEN_ADJUST_SESSIONID
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_PRIVILEGES
                | TOKEN_QUERY
                | TOKEN_DUPLICATE
                | TOKEN_ASSIGN_PRIMARY,
        )?
        .duplicate(TOKEN_ACCESS_MASK(0), None, SecurityAnonymous, TokenPrimary)?;

    token.set_session_id(session_id)?;

    let (mut rx, tx) = Pipe::new_anonymous(
        Some(&SecurityAttributes {
            inherit_handle: true,
            security_descriptor: None,
        }),
        256,
    )?;

    let mut attributes = ThreadAttributeList::with_count(1)?;
    let attr = ThreadAttributeType::HandleList(vec![tx.handle.raw()]);
    attributes.update(&attr)?;

    let mut startup_info = StartupInfo {
        desktop: secure_desktop
            .then(|| WideString::from(SECURE_DESKTOP))
            .unwrap_or_default(),
        attribute_list: Some(Some(attributes.raw())),
        ..Default::default()
    };

    let command_line = CommandLine::new(vec![
        config::pedm_desktop_path()
            .to_str()
            .ok_or_else(|| win_api_wrappers::Error::from_win32(ERROR_BAD_ARGUMENTS))?
            .to_owned(),
        user_behalf.to_string(),
        verb.to_owned(),
        format!("{}", tx.handle.raw().0 as isize),
        argument.unwrap_or_default().to_owned(),
    ]);

    let proc = start_process(
        &token,
        Some(config::pedm_desktop_path()),
        Some(&command_line),
        true, // Safe to inherit, as startup info has inherit list
        CREATE_SUSPENDED,
        None,
        None,
        &mut startup_info,
    )?;

    drop(tx);

    proc.thread.resume()?;

    let _ = proc.process.wait(None)?;

    let mut buf = Vec::new();

    let _ = rx.read_to_end(&mut buf);

    Ok(buf)
}

pub(crate) fn launch_consent(session_id: u32, user_behalf: &Sid, path: &Path) -> Result<bool> {
    let status = launch_desktop(
        session_id,
        "consent",
        path.to_str(),
        user_behalf,
        policy::policy()
            .read()
            .user_current_profile(&user_behalf.account(None)?.to_user())
            .map_or(true, |x| x.prompt_secure_desktop),
    )?
    .first()
    .is_some_and(|x| *x != 0);

    Ok(status)
}
