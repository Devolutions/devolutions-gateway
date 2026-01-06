#[cfg(target_os = "windows")]
fn generate_version_rc() -> String {
    use std::env;

    let output_name = "DevolutionsPedmShellExt";
    let filename = format!("{}.dll", output_name);
    let company_name = "Devolutions Inc.";
    let legal_copyright = format!("Copyright 2020-2024 {}", company_name);

    let version_number = env::var("CARGO_PKG_VERSION").unwrap() + ".0";
    let version_commas = version_number.replace('.', ",");
    let file_description = output_name;
    let file_version = version_number.clone();
    let internal_name = filename.clone();
    let original_filename = filename;
    let product_name = output_name;
    let product_version = version_number;
    let vs_file_version = version_commas.clone();
    let vs_product_version = version_commas;

    let version_rc = format!(
        r#"#include <winresrc.h>
VS_VERSION_INFO VERSIONINFO
    FILEVERSION {vs_file_version}
    PRODUCTVERSION {vs_product_version}
    FILEFLAGSMASK 0x3fL
#ifdef _DEBUG
    FILEFLAGS 0x1L
#else
    FILEFLAGS 0x0L
#endif
    FILEOS 0x40004L
    FILETYPE VFT_DLL
    FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "{company_name}"
            VALUE "FileDescription", "{file_description}"
            VALUE "FileVersion", "{file_version}"
            VALUE "InternalName", "{internal_name}"
            VALUE "LegalCopyright", "{legal_copyright}"
            VALUE "OriginalFilename", "{original_filename}"
            VALUE "ProductName", "{product_name}"
            VALUE "ProductVersion", "{product_version}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END"#,
        vs_file_version = vs_file_version,
        vs_product_version = vs_product_version,
        company_name = company_name,
        file_description = file_description,
        file_version = file_version,
        internal_name = internal_name,
        legal_copyright = legal_copyright,
        original_filename = original_filename,
        product_name = product_name,
        product_version = product_version
    );

    version_rc
}

#[cfg(target_os = "windows")]
fn main() -> Result<(), Box<dyn core::error::Error>> {
    use std::path::PathBuf;
    use std::{env, fs};

    use devolutions_pedm_shared::build::target_dir;
    use fs_extra::dir::CopyOptions;

    let target = target_dir()?;
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let options = CopyOptions {
        overwrite: true,
        copy_inside: true,
        ..Default::default()
    };

    fs_extra::dir::copy(crate_dir.join("Assets"), &target, &options)?;

    fs::copy(crate_dir.join("AppxManifest.xml"), target.join("AppxManifest.xml"))?;

    let out_dir = env::var("OUT_DIR").unwrap();
    let version_rc_file = format!("{}/version.rc", out_dir);
    let version_rc_data = generate_version_rc();
    fs::write(&version_rc_file, version_rc_data).unwrap();

    embed_resource::compile(&version_rc_file, embed_resource::NONE)
        .manifest_required()
        .unwrap();
    embed_resource::compile("resources.rc", embed_resource::NONE)
        .manifest_required()
        .unwrap();

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn main() {}
