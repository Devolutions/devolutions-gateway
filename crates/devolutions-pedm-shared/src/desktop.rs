use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

use anyhow::Result;
use win_api_wrappers::process::Process;
use win_api_wrappers::raw::Win32::Security::TOKEN_QUERY;
use windows_registry::LOCAL_MACHINE;

pub fn install_dir() -> Result<PathBuf> {
    // TODO: lookup from registry only works when installed by MSI
    Ok(PathBuf::from_str(
        &LOCAL_MACHINE
            .open(r"SOFTWARE\Devolutions\Agent")?
            .get_string("InstallDir")?,
    )?)
}

pub fn desktop_exe() -> Result<PathBuf> {
    let mut exe = install_dir()?;

    exe.push("desktop");
    exe.push("DevolutionsDesktopAgent.exe");

    Ok(exe)
}

pub enum DesktopMode {
    Error(win_api_wrappers::raw::core::Error),
}

pub fn launch(mode: &DesktopMode) -> Result<()> {
    let mut base_command = Command::new(desktop_exe()?);
    base_command.arg(desktop_exe()?);
    base_command.arg(
        Process::current_process()
            .token(TOKEN_QUERY)?
            .sid_and_attributes()?
            .sid
            .to_string(),
    );

    match mode {
        DesktopMode::Error(err) => base_command.arg("error").arg(err.code().0.to_string()).spawn()?,
    };

    Ok(())
}
