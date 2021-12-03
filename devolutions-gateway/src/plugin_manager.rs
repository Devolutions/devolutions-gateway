mod packets_parsing;
mod plugin_info;
mod recording;

pub use packets_parsing::PacketsParser;
pub use recording::Recorder;

use camino::Utf8Path;
use dlopen::symbor::Library;
use lazy_static::lazy_static;
use plugin_info::{PluginCapabilities, PluginInformation};
use slog_scope::debug;
use std::sync::{Arc, Mutex};

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
            let info = plugin.info.clone();
            if info.get_capabilities().contains(&PluginCapabilities::Recording) {
                if let Ok(plugin) = Recorder::new(plugin.lib.clone()) {
                    debug!("recording plugin found");
                    return Some(plugin);
                }
            }
        }
        None
    }

    pub fn get_parsing_packets_plugin(&self) -> Option<PacketsParser> {
        for plugin in &self.libs {
            let info = plugin.info.clone();
            if info.get_capabilities().contains(&PluginCapabilities::PacketsParsing) {
                if let Ok(plugin) = PacketsParser::new(plugin.lib.clone()) {
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
        slog_scope::info!("Plugin {} loaded", info.get_name());

        self.libs.push(Plugin {
            lib,
            info: Arc::new(info),
        });

        Ok(())
    }
}
