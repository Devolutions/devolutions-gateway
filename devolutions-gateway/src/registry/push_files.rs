use slog_scope::{debug, error};
use sogar_core::config::{get_mime_type_from_file_extension, CommandData, CommandType, Settings};
use sogar_core::export_sogar_file_artifact;
use std::fs;
use std::path::Path;

pub struct SogarData {
    registry_url: String,
    username: String,
    password: String,
    image_name: String,
    file_pattern: String,
}

impl SogarData {
    pub fn new(
        registry_url: Option<String>,
        username: Option<String>,
        password: Option<String>,
        image_name: Option<String>,
        file_pattern: Option<String>,
    ) -> Option<Self> {
        if let (Some(registry_url), Some(username), Some(password), Some(image_name), Some(file_pattern)) =
            (registry_url, username, password, image_name, file_pattern)
        {
            debug!("Sogar data created!");
            Some(SogarData {
                registry_url,
                username,
                password,
                image_name,
                file_pattern,
            })
        } else {
            None
        }
    }

    pub async fn push(&self, path: &Path, tag: String) {
        let file_paths = get_file_list_from_path(self.file_pattern.as_str(), path);
        if file_paths.is_empty() {
            debug!(
                "The recording folder does not contain the files with the specified file name {}",
                self.file_pattern
            );
            return;
        }

        let command_data = CommandData {
            media_type: get_mime_type_from_file_extension(&file_paths[0]),
            reference: format!("{}:{}", self.image_name, tag),
            filepath: file_paths,
        };

        let sogar_setting = Settings {
            registry_url: self.registry_url.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            command_type: CommandType::Export,
            command_data,
            registry_cache: None,
        };

        if let Err(e) = export_sogar_file_artifact(&sogar_setting).await {
            error!("Export sogar file artifact failed: {}", e);
        }
    }
}

pub fn get_file_list_from_path(file_pattern: &str, path: &Path) -> Vec<String> {
    match fs::read_dir(path) {
        Ok(paths) => paths
            .filter_map(|path| match path {
                Ok(dir_entry) => match (dir_entry.file_name().into_string(), dir_entry.path().to_str()) {
                    (Ok(filename), Some(path)) => {
                        if filename.starts_with(file_pattern) {
                            Some(path.to_string())
                        } else {
                            None
                        }
                    }
                    _ => None,
                },
                Err(_) => None,
            })
            .collect::<Vec<_>>(),
        Err(e) => {
            error!("Failed to read dir {:?} with error {}", path, e);
            Vec::new()
        }
    }
}
