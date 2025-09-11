fn main() {
    #[cfg(target_os = "windows")]
    win::embed_version_rc();

    #[cfg(target_os = "windows")]
    win::embed_devolutions_gateway_mc();
}

#[cfg(target_os = "windows")]
mod win {
    use std::{env, fs};

    pub(super) fn embed_version_rc() {
        let out_dir = env::var("OUT_DIR").unwrap();
        let version_rc_file = format!("{}/version.rc", out_dir);
        let version_rc_data = generate_version_rc();
        fs::write(&version_rc_file, version_rc_data).unwrap();

        embed_resource::compile(&version_rc_file, embed_resource::NONE)
            .manifest_required()
            .unwrap();
    }

    fn generate_version_rc() -> String {
        let output_name = "DevolutionsGateway";
        let filename = format!("{}.exe", output_name);
        let company_name = "Devolutions Inc.";
        let legal_copyright = format!("Copyright 2020-2023 {}", company_name);

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

    pub(super) fn embed_devolutions_gateway_mc() {
        use std::env;
        use std::path::PathBuf;
        use std::process::Command;

        // --- gate: only release builds -------------------------------------
        let profile = env::var("PROFILE").unwrap_or_default();
        if profile != "release" {
            return;
        }

        // --- gate: ignore with a warning when mc is not found --------------
        let mc_exe_path = match find_mc() {
            Some(path) => path,
            None => {
                println!("cargo:warning=Did not find mc.exe");
                return;
            }
        };

        // --- inputs/paths ---------------------------------------------------
        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
        let mc_file = manifest_dir.join("devolutions-gateway.mc"); // adjust if stored elsewhere

        // Always tell Cargo to re-run if the .mc changes
        println!("cargo:rerun-if-changed={}", mc_file.display());

        // --- prepare OUT_DIR ------------------------------------------------
        let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
        // We'll run mc.exe with current_dir = OUT_DIR so the generated .rc lands in OUT_DIR.
        let rc_path = out_dir.join("devolutions-gateway.rc");

        // --- run mc.exe -----------------------------------------------------
        // Requires Windows SDK tools in PATH (use a "x64 Native Tools Command Prompt for VS").
        // Flags:
        //   -u : Unicode
        //   -m : Generate message resource .bin files
        //   -h <dir> : header output dir (we put it in OUT_DIR; the header is unused by Rust)
        //   -r <dir> : message .bin output dir (OUT_DIR)
        let status = Command::new(mc_exe_path)
            .current_dir(&out_dir)
            .arg("-um")
            .arg("-h")
            .arg(".")
            .arg("-r")
            .arg(".")
            .arg(mc_file.canonicalize().expect("failed to canonicalize .mc path"))
            .status()
            .expect("failed to spawn mc.exe");
        if !status.success() {
            panic!("mc.exe failed with status {status}");
        }

        // --- compile the generated .rc via embed-resource -------------------
        if !rc_path.exists() {
            panic!("mc.exe did not produce expected .rc file at {}", rc_path.display());
        }

        // Compile/link the .rc into the final binary.
        // This will call rc.exe under the hood.
        embed_resource::compile(rc_path, embed_resource::NONE)
            .manifest_required()
            .unwrap();

        // Optional: make Cargo re-run if locale bins change (paranoid but harmless)
        // These are standard names emitted by mc.exe for EN/FR/DE in our .mc.
        for loc in &["MSG00409.bin", "MSG0040c.bin", "MSG00407.bin"] {
            let p = out_dir.join(loc);
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }

    fn find_mc() -> Option<std::path::PathBuf> {
        if let Ok(sdk_bin) = env::var("WindowsSdkVerBinPath") {
            let p = std::path::Path::new(&sdk_bin).join("mc.exe");
            if p.exists() {
                return Some(p);
            }
        }

        if let Ok(sdk_dir) = env::var("WindowsSdkDir") {
            // e.g. C:\Program Files (x86)\Windows Kits\10\
            let candidate = std::path::Path::new(&sdk_dir).join("bin").join("x64").join("mc.exe");
            if candidate.exists() {
                return Some(candidate);
            }
        }

        None
    }
}
