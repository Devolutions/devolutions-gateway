//! Module in charge of handling elevation logs for each user.
//!
//! Each user will have a directory only readable by them in `%ProgramData%\Devolutions\Agent\pedm\logs\<SID>`.
//! This directory will only be writeable by `NT AUTHORITY\SYSTEM`.
use anyhow::Result;
use camino::Utf8PathBuf;
use chrono::Local;
use devolutions_pedm_shared::policy::{ElevationResult, User};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead};
use walkdir::WalkDir;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::raw::Win32::Security::WinBuiltinUsersSid;

use crate::config;
use crate::utils::ensure_protected_directory;

fn log_path() -> Utf8PathBuf {
    let mut dir = config::data_dir();
    dir.push("logs");
    dir
}

fn log_path_for_user(user: &User) -> Result<Utf8PathBuf> {
    let mut dir = log_path();
    ensure_protected_directory(dir.as_std_path(), vec![Sid::from_well_known(WinBuiltinUsersSid, None)?])?;

    dir.push(&user.account_sid);

    ensure_protected_directory(dir.as_std_path(), vec![Sid::try_from(user.account_sid.as_str())?])?;

    Ok(dir)
}

pub(crate) fn log_elevation(res: &ElevationResult) -> Result<()> {
    let mut log_path = log_path_for_user(&res.request.asker.user)?;

    let cur_time = Local::now();

    log_path.push(cur_time.format("%Y_%m_%d.json").to_string());

    // FIXME: Depending on log rotation, the log file may not exist
    // TODO: Log to a local database rather than a file
    //let mut file = OpenOptions::new().append(true).create(true).open(log_path)?;

    //file.write_all(serde_json::to_string(res)?.as_bytes())?;
    //file.write_all(b"\n")?;

    Ok(())
}

pub(crate) fn query_logs(user: Option<&User>) -> Result<Vec<ElevationResult>> {
    let log_path = user.map_or_else(|| Ok(log_path()), log_path_for_user)?;

    let mut logs = vec![];
    for entry in WalkDir::new(log_path).into_iter() {
        let entry = entry?;
        if !(entry.file_type().is_file() && entry.path().extension().is_some_and(|ext| ext == "json")) {
            continue;
        }

        for line in io::BufReader::new(fs::File::open(entry.path())?).lines() {
            logs.push(serde_json::from_str(line?.as_str())?);
        }
    }

    Ok(logs)
}
