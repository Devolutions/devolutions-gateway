use slog_scope::{debug, error};
use std::fs::DirEntry;
use std::path::Path;
use std::process::Command;
use std::{fs, io};

pub struct SogarData {
    sogar_path: String,
    registry_url: String,
    username: String,
    password: String,
    image_name: String,
    file_pattern: String,
}

impl SogarData {
    pub fn new(
        sogar_path: Option<String>,
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

        let reference = format!("{}:{}", self.image_name.clone(), tag);
        let joined_path: &str = &file_paths.join(";");
        self.invoke_command(joined_path, reference);
        for filepath in file_paths {
            if let Err(e) = fs::remove_file(filepath.as_str()) {
                error!("Failed to delete file {} after push: {}", filepath, e);
            }
        }
    }

    fn invoke_command(&self, file_path: &str, reference: String) {
        let mut command = Command::new(self.sogar_path.clone());
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

fn get_filtered_files(file_pattern: &str, path: &Path) -> Vec<io::Result<DirEntry>> {
    match fs::read_dir(path) {
        Ok(paths) => paths
            .filter(|path| match path {
                Ok(dir_entry) => match dir_entry.file_name().into_string() {
                    Ok(filename) => filename.starts_with(file_pattern),
                    Err(_) => false,
                },
                Err(_) => false,
            })
            .collect::<Vec<_>>(),
        Err(e) => {
            error!("Failed to read dir {:?} with error {}", path, e);
            Vec::new()
        }
    }
}

pub fn get_file_list_from_path(file_pattern: &str, path: &Path) -> Vec<String> {
    let filtered_files = get_filtered_files(file_pattern, path);
    if !filtered_files.is_empty() {
        let mut file_paths = Vec::new();
        for file in filtered_files {
            match file {
                Ok(entry) => {
                    if let Some(path) = entry.path().to_str() {
                        file_paths.push(path.to_string())
                    }
                }
                Err(e) => error!("Failed to get filename for the push: {}", e),
            }
        }

        return file_paths;
    }

    Vec::new()
}
