use windows::core::HRESULT;
use windows::Foundation::Uri;
use windows::Management::Deployment::*;
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CLEANBOOT};

use crate::Error;

fn is_clean_boot() -> bool {
    // SAFETY: `GetSystemMetrics` requires no setup or context to call
    // `SM_CLEANBOOT` is a valid parameter, guaranteed by the constant from the `windows` crate
    unsafe { GetSystemMetrics(SM_CLEANBOOT) > 0 }
}

pub fn register_sparse_package(external_location: Uri, sparse_package_path: Uri) -> anyhow::Result<()>
{
    if !is_clean_boot() {
        error!("not a clean boot")
    }

    let add_package_options = AddPackageOptions::new()?;
    add_package_options.SetExternalLocationUri(&external_location)?;

    let package_manager = PackageManager::new()?;

    let deploy_operation = package_manager.AddPackageByUriAsync(&sparse_package_path, &add_package_options)?;
    let deploy_result = deploy_operation.get()?;
    let deploy_result_err = deploy_result.ExtendedErrorCode()?;

    if deploy_result_err != HRESULT(0) {
        return Err(Error::from_hresult(deploy_result_err).into())
    }

    Ok(())
}