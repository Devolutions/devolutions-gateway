mod packets_parsing;
mod plugin_info;
mod recording;

pub use packets_parsing::PacketsParser;
pub use recording::Recorder;

use anyhow::Context as _;
use camino::Utf8Path;
use dlopen::symbor::Library;
use lazy_static::lazy_static;
use parking_lot::Mutex;
use plugin_info::{PluginCapabilities, PluginInformation};
use std::sync::Arc;

use crate::config::Conf;

#[derive(Clone)]
struct Plugin {
    lib: Arc<Library>,
    info: Arc<PluginInformation>,
}

pub struct PluginManager {
    libs: Vec<Plugin>,
}

lazy_static! {
    pub static ref PLUGIN_MANAGER: Mutex<PluginManager> = Mutex::new(PluginManager { libs: Vec::new() });
}

impl PluginManager {
    pub fn get_recording_plugin(&self) -> Option<Recorder> {
        for plugin in &self.libs {
            let info = Arc::clone(&plugin.info);
            if info.get_capabilities().contains(&PluginCapabilities::Recording) {
                if let Ok(plugin) = Recorder::new(Arc::clone(&plugin.lib)) {
                    debug!("recording plugin found");
                    return Some(plugin);
                }
            }
        }
        None
    }

    pub fn get_parsing_packets_plugin(&self) -> Option<PacketsParser> {
        for plugin in &self.libs {
            let info = Arc::clone(&plugin.info);
            if info.get_capabilities().contains(&PluginCapabilities::PacketsParsing) {
                if let Ok(plugin) = PacketsParser::new(Arc::clone(&plugin.lib)) {
                    debug!("parsing plugin found");
                    return Some(plugin);
                }
            }
        }

        None
    }

    pub fn load_plugin(&mut self, path: &Utf8Path) -> anyhow::Result<()> {
        let lib = Arc::new(Library::open(path)?);
        let info = PluginInformation::new(Arc::clone(&lib))?;
        info!("Plugin {} loaded", info.get_name());

        self.libs.push(Plugin {
            lib,
            info: Arc::new(info),
        });

        Ok(())
    }
}

pub fn load_plugins(conf: &Conf) -> anyhow::Result<()> {
    if let Some(plugins) = &conf.plugins {
        let mut manager = PLUGIN_MANAGER.lock();
        for plugin in plugins {
            manager
                .load_plugin(plugin)
                .with_context(|| format!("Failed to load plugin {plugin}"))?;
        }
    }

    Ok(())
}
