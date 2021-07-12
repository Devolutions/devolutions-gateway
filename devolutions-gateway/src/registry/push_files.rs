use slog_scope::{debug, error};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct SogarData {
    sogar_path: PathBuf,
    registry_url: String,
    username: String,
    password: String,
    image_name: String,
    file_pattern: String,
}

impl SogarData {
    pub fn new(
        sogar_path: Option<PathBuf>,
        registry_url: Option<String>,
        username: Option<String>,
        password: Option<String>,
        image_name: Option<String>,
        file_pattern: Option<String>,
    ) -> Option<Self> {
        if let (
            Some(sogar_path),
            Some(registry_url),
            Some(username),
            Some(password),
            Some(image_name),
            Some(file_pattern),
        ) = (sogar_path, registry_url, username, password, image_name, file_pattern)
        {
            debug!("Sogar data created!");
            Some(SogarData {
                sogar_path,
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

    pub fn push(&self, path: &Path, tag: String) {
        let file_paths = get_file_list_from_path(self.file_pattern.as_str(), path);
        if file_paths.is_empty() {
            debug!(
                "The recording folder does not contain the files with the specified file name {}",
                self.file_pattern
            );
            return;
        }

        let reference = format!("{}:{}", self.image_name, tag);
        let joined_path: &str = &file_paths.join(";");
        self.invoke_command(joined_path, reference);
    }

    fn invoke_command(&self, file_path: &str, reference: String) {
        if self.sogar_path.to_str().is_none() || !self.sogar_path.is_file() {
            error!("Failed to retrieve path string or path is not a file: {}", self.sogar_path.display());
            return;
        }

        let mut command = Command::new(self.sogar_path.to_str().unwrap());
        let args = command
            .arg("--registry-url")
            .arg(self.registry_url.clone().as_str())
            .arg("--username")
            .arg(self.username.clone().as_str())
            .arg("--password")
            .arg(self.password.clone().as_str())
            .arg("--export-artifact")
            .arg("--reference")
            .arg(reference)
            .arg("--filepath")
            .arg(file_path.to_string());

        debug!("Command args for sogar are: {:?}", args);

        match args.output() {
            Ok(output) => {
                if !output.status.success() {
                    error!("Status of the output is fail!");
                }
                debug!("Sogar output: {:?}", output);
            }
            Err(e) => error!("Command failed with error: {}", e),
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
