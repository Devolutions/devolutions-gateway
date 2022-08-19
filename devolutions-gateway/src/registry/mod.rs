mod push_files;

use crate::config::Conf;
use sogar_core::{create_annotation_for_filename, parse_digest, read_file_data, registry, FileInfo, Layer};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{fs, thread};
use tempfile::NamedTempFile;

pub struct Registry {
    config: Arc<Conf>,
    registry_path: PathBuf,
}

impl Registry {
    pub fn new(config: Arc<Conf>) -> Self {
        let registry_name = config.sogar.registry_name.clone();
        let registry_namespace = config.sogar.registry_image.clone();
        let registry_path = format!("{}/{}", registry_name, registry_namespace);

        Self {
            config,
            registry_path: PathBuf::from(registry_path),
        }
    }

    pub async fn manage_files(&self, tag: String, file_pattern: String, recording_dir: &Path) {
        let files = push_files::get_file_list_from_path(file_pattern.as_str(), recording_dir);

        if self.config.sogar.serve_as_registry {
            self.move_file_to_registry(files.clone(), tag.as_str());
        }

        if self.config.sogar.push_files {
            self.push_files(file_pattern, recording_dir, tag).await;
        }

        if self.config.sogar.keep_files {
            if let Some(duration) = self.config.sogar.keep_time {
                thread::spawn(move || {
                    thread::sleep(Duration::from_secs(duration));
                    remove_files(files);
                });
            }
        } else {
            remove_files(files);
        }
    }

    fn move_file_to_registry(&self, files: Vec<String>, tag: &str) {
        let mut layers = Vec::new();
        for file in files {
            if let Some(file_data) = move_blob(&file, self.registry_path.as_path()) {
                layers.push(file_data.layer.clone());
            }
        }

        let config_file = NamedTempFile::new();
        if let Err(e) = &config_file {
            error!("Failed to create config file file with error {}.", e);
            return;
        }

        let config_file = config_file.unwrap();
        let config_data = sogar_core::create_config(config_file.path());

        if let Err(e) = &config_data {
            error!("Failed to create file info about config with error {}. Skipping it.", e);
            return;
        }

        let manifest_mime = create_and_move_manifest(self.registry_path.as_path(), config_data.unwrap(), layers, tag);

        registry::add_artifacts_info(tag, manifest_mime, self.registry_path.as_path());
    }

    async fn push_files(&self, file_pattern: String, recording_dir: &Path, tag: String) {
        let conf = &self.config.sogar;

        push_files::do_push(
            &conf.registry_url,
            &conf.username,
            &conf.password,
            &conf.image_name,
            &file_pattern,
            recording_dir,
            tag,
        )
        .await;
    }
}

fn remove_files(files: Vec<String>) {
    for file in files {
        if let Err(e) = fs::remove_file(Path::new(&file)) {
            error!("Failed to remove file {} with error {}", file, e);
        }
    }
}

fn create_and_move_manifest(
    registry_path: &Path,
    config_data: FileInfo,
    layers: Vec<Layer>,
    tag: &str,
) -> Option<String> {
    let manifest_file = NamedTempFile::new();
    if let Err(e) = &manifest_file {
        error!("Failed to create manifest file with error {}.", e);
        return None;
    }

    let manifest_file = manifest_file.unwrap();
    let manifest = sogar_core::Manifest {
        schema_version: 2,
        config: config_data.layer,
        layers,
    };

    let manifest_file_info = sogar_core::create_file_info(manifest, manifest_file.path());

    if let Err(e) = &manifest_file_info {
        error!("Failed to create manifest with error {}.", e);
        return None;
    }

    let manifest_file_info = manifest_file_info.unwrap();
    let manifest_path = registry_path.join(registry::ARTIFACTS_DIR).join(tag);

    if let Err(e) = fs::copy(manifest_file_info.path, manifest_path) {
        error!("Failed to copy manifest to the registry with error {}!", e);
        return None;
    }

    Some(manifest_file_info.layer.media_type)
}

fn move_blob(file_path: &str, registry_path: &Path) -> Option<FileInfo> {
    let mime_type = sogar_core::config::get_mime_type_from_file_extension(file_path);
    let file_path = Path::new(file_path);
    let annotations = create_annotation_for_filename(file_path);
    let file_data = read_file_data(file_path, mime_type, Some(annotations));

    if let Err(e) = &file_data {
        error!(
            "Failed to create file info about file {:?} with error {}. Skipping it.",
            file_path, e
        );
        return None;
    }

    let file_data = file_data.unwrap();
    let digest = parse_digest(&file_data.layer.digest);
    if digest.is_none() {
        error!("Failed to parse digest for the file {}", file_path.display());
        return None;
    }

    let digest = digest.unwrap();
    let blob_dir = registry_path.join(registry::ARTIFACTS_DIR).join(&digest.digest_type);

    let blob_path = blob_dir.join(&digest.value);

    if !blob_dir.exists() {
        if let Err(e) = fs::create_dir_all(blob_dir) {
            error!("Failed to create dir for the blob with error {}!", e);
            return None;
        }
    } else if blob_path.exists() {
        debug!("File {} already saved in registry!", file_path.display());
        return None;
    }

    if let Err(e) = fs::copy(file_path, blob_path) {
        error!("Failed to copy blob to the registry with error {}!", e);
    }

    Some(file_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use picky::key::PublicKey;
    use rstest::*;
    use std::fs::File;
    use std::io::Write;

    const PROVISIONER_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsiLoIx
mXaZAFRBKtHYZhiF8m+pYR+xGIpupvsdDEvKO92D6fIccgVLIW6p6sSNk
oXx5J6KDSMbA/chy5M6pRvJkaCXCI4zlCPMYvPhI8OxN3RYPfdQTLpgPy
wrlfdn2CAum7o4D8nR4NJacB3NfPnS9tsJ2L3p5iHviuTB4xm03IKmPPq
saJy+nXUFC1XS9E/PseVHRuNvKa7WmlwSZngQzKAVSIwqpgCc+oP1pKEe
J0M3LHFo8ao5SuzhfXUIGrPnkUKEE3m7B0b8xXZfP1N6ELoonWDK+RMgY
IBaZdgBhPfHxF8KfTHvSzcUzWZojuR+ynaFL9AJK+8RiXnB4CJwIDAQAB
-----END PUBLIC KEY-----"#;

    #[fixture]
    fn conf() -> Conf {
        Conf {
            id: None,
            listeners: Vec::new(),
            hostname: "hostname".to_owned(),
            subscriber: None,
            capture_path: None,
            log_file: String::new().into(),
            log_directive: None,
            tls: None,
            provisioner_public_key: PublicKey::from_pem_str(PROVISIONER_KEY).unwrap(),
            sub_provisioner_public_key: None,
            delegation_private_key: None,
            plugins: None,
            recording_path: None,
            sogar: Default::default(),
            jrl_file: String::new().into(),
            debug: Default::default(),
        }
    }

    #[rstest]
    fn test_files_moved_to_registry(mut conf: Conf) {
        let files_dir_name = "dir_with_file1";
        let file_name = "test1.txt";
        let file_path = format!("{}/{}", files_dir_name, file_name);

        let path_buf = PathBuf::from("test_registry1/test_image1").join(registry::ARTIFACTS_DIR);
        create_file_and_registry(String::from(files_dir_name), file_path.clone(), path_buf.as_path());

        conf.sogar.serve_as_registry = true;
        conf.sogar.push_files = false;
        conf.sogar.keep_files = false;
        conf.sogar.registry_name = String::from("test_registry1");
        conf.sogar.registry_image = String::from("test_image1");

        let registry = Registry::new(Arc::new(conf));

        assert_eq!(path_buf.exists(), true);
        assert_eq!(path_buf.is_dir(), true);

        tokio_test::block_on(registry.manage_files(
            String::from("tag"),
            String::from("test1"),
            Path::new(files_dir_name),
        ));

        assert_eq!(path_buf.join("tag").exists(), true);
        assert_eq!(path_buf.join("sha256").exists(), true);
        assert_eq!(
            path_buf
                .join("sha256")
                .join("71f98783dc1d803d41c0e7586a636a8cbaac8b6fc739681123a8f674d3d0f544")
                .exists(),
            true
        );
        assert_eq!(PathBuf::from(file_path.as_str()).exists(), false);

        fs::remove_dir_all(Path::new("test_registry1")).unwrap();
        fs::remove_dir_all(Path::new(files_dir_name)).unwrap();
    }

    #[rstest]
    fn test_files_not_removed(mut conf: Conf) {
        let files_dir_name = "dir_with_file2";
        let file_name = "test2.txt";
        let file_path = format!("{}/{}", files_dir_name, file_name);

        let path_buf = PathBuf::from("test_registry2/test_image2").join(registry::ARTIFACTS_DIR);
        create_file_and_registry(String::from(files_dir_name), file_path.clone(), path_buf.as_path());

        conf.sogar.serve_as_registry = true;
        conf.sogar.push_files = false;
        conf.sogar.keep_files = true;
        conf.sogar.keep_time = None;
        conf.sogar.registry_name = String::from("test_registry2");
        conf.sogar.registry_image = String::from("test_image2");

        let registry = Registry::new(Arc::new(conf));

        assert_eq!(path_buf.exists(), true);
        assert_eq!(path_buf.is_dir(), true);

        tokio_test::block_on(registry.manage_files(
            String::from("tag"),
            String::from("test2"),
            Path::new(files_dir_name),
        ));

        assert_eq!(path_buf.join("tag").exists(), true);
        assert_eq!(path_buf.join("sha256").exists(), true);
        assert_eq!(
            path_buf
                .join("sha256")
                .join("71f98783dc1d803d41c0e7586a636a8cbaac8b6fc739681123a8f674d3d0f544")
                .exists(),
            true
        );
        assert_eq!(PathBuf::from(file_path.as_str()).exists(), true);

        fs::remove_dir_all(Path::new("test_registry2")).unwrap();
        fs::remove_dir_all(Path::new(files_dir_name)).unwrap();
    }

    #[rstest]
    fn test_files_removed_after_timeout(mut conf: Conf) {
        let files_dir_name = "dir_with_file3";
        let file_name = "test3.txt";
        let file_path = format!("{}/{}", files_dir_name, file_name);

        let path_buf = PathBuf::from("test_registry3/test_image3").join(registry::ARTIFACTS_DIR);
        create_file_and_registry(String::from(files_dir_name), file_path.clone(), path_buf.as_path());

        conf.sogar.serve_as_registry = true;
        conf.sogar.push_files = false;
        conf.sogar.keep_files = true;
        conf.sogar.keep_time = Some(1);
        conf.sogar.registry_name = String::from("test_registry3");
        conf.sogar.registry_image = String::from("test_image3");

        let registry = Registry::new(Arc::new(conf));

        assert_eq!(path_buf.exists(), true);
        assert_eq!(path_buf.is_dir(), true);

        tokio_test::block_on(registry.manage_files(
            String::from("tag"),
            String::from("test3"),
            Path::new(files_dir_name),
        ));

        assert_eq!(path_buf.join("tag").exists(), true);
        assert_eq!(path_buf.join("sha256").exists(), true);
        assert_eq!(
            path_buf
                .join("sha256")
                .join("71f98783dc1d803d41c0e7586a636a8cbaac8b6fc739681123a8f674d3d0f544")
                .exists(),
            true
        );
        assert_eq!(PathBuf::from(file_path.as_str()).exists(), true);

        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(PathBuf::from(file_path.as_str()).exists(), false);

        fs::remove_dir_all(Path::new("test_registry3")).unwrap();
        fs::remove_dir_all(Path::new(files_dir_name)).unwrap();
    }

    fn create_file_and_registry(files_dir_name: String, file_path: String, registry: &Path) {
        let path_buf = PathBuf::from(files_dir_name);
        fs::create_dir_all(path_buf.as_path()).unwrap();
        let mut file = File::create(file_path.as_str()).unwrap();
        file.write_all(b"Some text!").unwrap();

        if !registry.exists() {
            fs::create_dir_all(registry).unwrap();
        }
    }
}
