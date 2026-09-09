fn main() {
    generate_psu_agent_proto();

    #[cfg(target_os = "windows")]
    win::embed_version_rc();

    #[cfg(target_os = "windows")]
    win::embed_devolutions_agent_mc();
}

fn generate_psu_agent_proto() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("failed to locate vendored protoc");
    // SAFETY: Build scripts run single-threaded for this crate before prost-build reads PROTOC.
    unsafe { std::env::set_var("PROTOC", protoc) };

    tonic_build::configure()
        .build_transport(false)
        .compile_protos(&["proto/psu_agent.proto"], &["proto"])
        .expect("failed to compile PSU agent proto");
}

#[cfg(target_os = "windows")]
mod win {
    use std::{env, fs};

    pub(super) fn embed_version_rc() {
        let out_dir = env::var("OUT_DIR").expect("BUG: failed to get OUT_DIR");
        let version_rc_file = format!("{}/version.rc", out_dir);
        let version_rc_data = generate_version_rc();
        fs::write(&version_rc_file, version_rc_data).expect("BUG: failed to write version.rc");

        embed_resource::compile(&version_rc_file, embed_resource::NONE)
            .manifest_required()
            .expect("BUG: failed to embed version.rc");
        embed_resource::compile("resources.rc", embed_resource::NONE)
            .manifest_required()
            .expect("BUG: failed to embed resources.rc");
    }

    fn generate_version_rc() -> String {
        let output_name = "DevolutionsAgent";
        let filename = format!("{}.exe", output_name);
        let company_name = "Devolutions Inc.";
        let legal_copyright = format!("Copyright 2020-2024 {}", company_name);

        let mut version_number = env::var("CARGO_PKG_VERSION").expect("BUG: failed to get CARGO_PKG_VERSION");
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

    pub(super) fn embed_devolutions_agent_mc() {
        use std::path::PathBuf;
        use std::process::Command;

        let profile = env::var("PROFILE").unwrap_or_default();
        if !matches!(profile.as_str(), "release" | "production") {
            return;
        }

        let mc_exe = find_mc().unwrap_or_else(|| {
            panic!(
                "mc.exe is required to embed the Devolutions Agent Event Log catalog; \
                 use a Visual Studio developer shell or set WindowsSdkVerBinPath or WindowsSdkDir"
            )
        });
        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
        let catalog = manifest_dir.join("devolutions-agent.mc");
        println!("cargo:rerun-if-changed={}", catalog.display());

        let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
        let status = Command::new(mc_exe)
            .current_dir(&out_dir)
            .args(["-um", "-h", ".", "-r", "."])
            .arg(catalog.canonicalize().expect("canonicalize Agent message catalog"))
            .status()
            .expect("run mc.exe");
        assert!(status.success(), "mc.exe failed with status {status}");

        let resource = out_dir.join("devolutions-agent.rc");
        assert!(resource.is_file(), "mc.exe did not generate {}", resource.display());
        embed_resource::compile(resource, embed_resource::NONE)
            .manifest_required()
            .expect("BUG: failed to embed devolutions-agent.rc");
    }

    fn find_mc() -> Option<std::path::PathBuf> {
        if let Ok(sdk_bin) = env::var("WindowsSdkVerBinPath") {
            let sdk_bin = std::path::Path::new(&sdk_bin);
            for candidate in [sdk_bin.join("mc.exe"), sdk_bin.join("x64").join("mc.exe")] {
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }

        let bin_dir = std::path::PathBuf::from(env::var_os("WindowsSdkDir")?).join("bin");
        let direct = bin_dir.join("x64").join("mc.exe");
        if direct.is_file() {
            return Some(direct);
        }

        let mut versions: Vec<_> = fs::read_dir(bin_dir)
            .ok()?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect();
        versions.sort_by_key(|path| {
            std::cmp::Reverse(
                path.file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| {
                        name.split('.')
                            .map(str::parse::<u32>)
                            .collect::<Result<Vec<_>, _>>()
                            .ok()
                    })
                    .unwrap_or_default(),
            )
        });
        versions
            .into_iter()
            .map(|directory| directory.join("x64").join("mc.exe"))
            .find(|path| path.is_file())
    }
}
