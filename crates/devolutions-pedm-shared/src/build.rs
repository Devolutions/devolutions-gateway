use std::env;
use std::ffi::OsString;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;

pub fn target_dir() -> Result<PathBuf> {
    let mut dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let target_dirs = [OsString::from(env::var("TARGET").unwrap()), OsString::from("target")];

    loop {
        if dir
            .parent()
            .is_some_and(|f| f.file_name().is_some_and(|f| target_dirs.iter().any(|x| x == f)))
        {
            return Ok(dir);
        } else if !dir.pop() {
            return Err(Error::new(ErrorKind::NotFound, "Target path not found"));
        }
    }
}
