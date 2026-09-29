use camino::Utf8PathBuf;
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;

use super::{UpdaterError, set_file_dacl, update_json_dacl};

#[test]
fn permission_errors_preserve_the_path_and_windows_cause() {
    let path = std::env::temp_dir().join(format!("gateway-missing-acl-{}", uuid::Uuid::new_v4()));
    let path = Utf8PathBuf::from_path_buf(path).expect("test path is valid UTF-8");
    let error = set_file_dacl(&path, &update_json_dacl("S-1-5-20")).expect_err("file does not exist");
    assert!(error.to_string().contains(path.as_str()));
    match error {
        UpdaterError::SetFilePermissions { source, .. } => {
            assert_eq!(source.code(), ERROR_FILE_NOT_FOUND.to_hresult());
        }
        error => panic!("unexpected error: {error}"),
    }
}
