use dlopen::{symbor::Library, Error};
use lazy_static::lazy_static;
use slog_scope::debug;
use std::sync::{Arc, Mutex};

mod packets_parsing;
mod plugin_info;
mod recording;
pub use packets_parsing::PacketsParser;
use plugin_info::{PluginCapabilities, PluginInformation};
pub use recording::Recorder;

pub struct PluginManager {
    lib: Vec<Arc<Library>>,
}

lazy_static! {
    pub static ref PLUGIN_MANAGER: Mutex<PluginManager> = Mutex::new(PluginManager { lib: Vec::new() });
}

impl PluginManager {
    pub fn get_recording_plugin(&self) -> Option<Recorder> {
        for lib in &self.lib {
            let info = PluginInformation::new(lib.clone());
            if info.get_capabilities().contains(&PluginCapabilities::Recording) {
                debug!("recording plugin found");
                return Some(Recorder::new(lib.clone()));
            }
        }
        None
    }

    pub fn get_parsing_packets_plugin(&self) -> Option<PacketsParser> {
        for lib in &self.lib {
            let info = PluginInformation::new(lib.clone());
            if info.get_capabilities().contains(&PluginCapabilities::PacketsParsing) {
                debug!("parsing plugin found");
                return Some(PacketsParser::new(lib.clone()));
            }
        }
        None
    }

    pub fn load_plugin(&mut self, path: &str) -> Result<(), Error> {
        let lib = Arc::new(Library::open(path)?);
        self.lib.push(lib.clone());
        let info = PluginInformation::new(lib);
        slog_scope::info!("Plugin {} loaded", info.get_name());
        Ok(())
    }
}
