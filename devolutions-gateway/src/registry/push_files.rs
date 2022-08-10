use sogar_core::config::{get_mime_type_from_file_extension, CommandData, CommandType, Settings};
use sogar_core::export_sogar_file_artifact;
use std::fs;
use std::path::Path;

pub async fn do_push(
    registry_url: &str,
    username: &str,
    password: &str,
    image_name: &str,
    file_pattern: &str,
    path: &Path,
    tag: String,
) {
    let file_paths = get_file_list_from_path(file_pattern, path);

    if file_paths.is_empty() {
        debug!(
            "The recording folder does not contain the files with the specified file name {}",
            file_pattern
        );
        return;
    }

    let command_data = CommandData {
        media_type: get_mime_type_from_file_extension(&file_paths[0]),
        reference: format!("{}:{}", image_name, tag),
        filepath: file_paths,
    };

    let sogar_setting = Settings {
        registry_url: registry_url.to_owned(),
        username: username.to_owned(),
        password: password.to_owned(),
        command_type: CommandType::Export,
        command_data,
        registry_cache: None,
    };

    if let Err(e) = export_sogar_file_artifact(&sogar_setting).await {
        error!("Export sogar file artifact failed: {}", e);
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
