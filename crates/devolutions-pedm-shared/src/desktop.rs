use std::{error::Error, path::PathBuf, process::Command, str::FromStr};
use win_api_wrappers::{raw::Win32::Security::TOKEN_QUERY, win::Process};
use windows_registry::LOCAL_MACHINE;

pub fn install_dir() -> Result<PathBuf, Box<dyn Error>> {
    Ok(PathBuf::from_str(
        &LOCAL_MACHINE
            .open(r"SOFTWARE\Devolutions\Agent")?
            .get_string("InstallDir")?,
    )?)
}

pub fn desktop_exe() -> Result<PathBuf, Box<dyn Error>> {
    let mut exe = install_dir()?;

    exe.push("desktop/DevolutionsPedmDesktop.exe");

    Ok(exe)
}

pub enum DesktopMode {
    Error(win_api_wrappers::raw::core::Error),
}

pub fn launch(mode: &DesktopMode) -> Result<(), Box<dyn Error>> {
    let mut base_command = Command::new(desktop_exe()?);
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
