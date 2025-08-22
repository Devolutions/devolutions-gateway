fn main() {
    #[cfg(target_os = "windows")]
    win::embed_version_rc();
}

#[cfg(target_os = "windows")]
mod win {
    use std::{env, fs};

    pub(super) fn embed_version_rc() {
        let out_dir = env::var("OUT_DIR").expect("failed to get OUT_DIR");
        let version_rc_file = format!("{out_dir}/version.rc");
        let version_rc_data = generate_version_rc();
        fs::write(&version_rc_file, version_rc_data).expect("failed to write version.rc");

        embed_resource::compile(&version_rc_file, embed_resource::NONE)
            .manifest_required()
            .expect("failed to compile version.rc");
    }

    fn generate_version_rc() -> String {
        let output_name = "DevolutionsSession";
        let filename = format!("{output_name}.exe");
        let company_name = "Devolutions Inc.";
        let legal_copyright = format!("Copyright 2020-2024 {company_name}");

        let mut version_number = env::var("CARGO_PKG_VERSION").expect("failed to get CARGO_PKG_VERSION");
        version_number.push_str(".0");
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
    FILETYPE 0x1L
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
}
