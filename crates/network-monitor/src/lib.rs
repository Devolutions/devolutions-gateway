extern crate serde_json;

use std::io;
use std::fs;
use camino::Utf8PathBuf;
use devolutions_agent_shared::get_data_dir;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
#[error(transparent)]
pub enum SetConfigError {
    Io(#[from] io::Error),
    Serde(#[from] serde_json::Error)
}

pub async fn set_config(config: MonitorsConfig) -> Result<(), SetConfigError> {
    let file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(get_monitor_config_path())?;

    serde_json::to_writer_pretty(&file, &config)?;

    Ok(())
}

fn get_monitor_config_path() -> Utf8PathBuf {
    get_data_dir().join("monitors.json")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonitorsConfig {
    monitors: Vec<MonitorDefinition>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonitorDefinition {
    id: String,
    probe: String,
    address: String,
    interval: i64,
    timeout: i64,
    port: Option<i16>
}

#[cfg(test)]
mod tests {
    extern crate tempdir;

    use super::*;
    use tempdir::TempDir;
    use tokio_test::{self, assert_ok};

    #[test]
    fn set_config_writes_to_disk() {
        let temp_dir = TempDir::new("dgw-network-monitor-test").expect("could not create temp dir");

        std::env::set_var("DGATEWAY_CONFIG_PATH", temp_dir.path());

        let config = MonitorsConfig { 
            monitors : vec![ 
                MonitorDefinition {
                    id: "a".to_string(),
                    probe: "b".to_string(),
                    address: "c".to_string(),
                    interval: 1,
                    timeout: 2,
                    port: Some(3)
                }
            ]
        };

        assert_ok!(tokio_test::block_on(set_config(config)));

        assert!(temp_dir.path().join("monitors.json").exists());
    }
}
