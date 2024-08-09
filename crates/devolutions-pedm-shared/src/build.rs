use std::env;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;

pub fn target_dir() -> Result<PathBuf> {
    let mut dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    loop {
        if dir.file_name().is_some_and(|f| *f == *env::var("PROFILE").unwrap()) {
            return Ok(dir);
        } else if !dir.pop() {
            return Err(Error::new(ErrorKind::NotFound, "Target path not found"));
        }
    }
}
