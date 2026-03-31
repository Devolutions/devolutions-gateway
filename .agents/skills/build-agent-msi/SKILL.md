---
name: build-agent-msi
description: Build the Devolutions Agent Windows MSI installer locally. Use when asked to build, compile, or rebuild the agent MSI.
---

# Build Devolutions Agent MSI Locally

## Required Tools

- **MSBuild** — VS 2022: `C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe`
- **MakeAppx.exe** — Windows SDK: `C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\MakeAppx.exe`
- **Rust/cargo**

## Important Notes

- **Static CRT is required.** Local builds do NOT link the CRT statically by default, but CI does.
  Without `+crt-static`, the binary fails at runtime with exit code `-1073741515` (`0xC0000135`, DLL not found)
  on any machine that doesn't have the MSVC redistributable installed — including fresh VMs.
  Always set `$Env:RUSTFLAGS = "-C target-feature=+crt-static"` before `cargo build`.

- **`devolutions-agent-updater` is NOT a separate package.** It is a `[[bin]]` target inside the
  `devolutions-agent` package (see `devolutions-agent/Cargo.toml`). Building `-p devolutions-agent`
  produces both `devolutions-agent.exe` and `devolutions-agent-updater.exe`. Do NOT use
  `-p devolutions-agent-updater` — it will fail with "package ID specification did not match any packages".

- **PEDM shell extension MSIX only builds in debug profile.** The MakeAppx step is not wired into the
  release build. Always point `DAGENT_PEDM_SHELL_EXT_MSIX` at `target\debug\DevolutionsPedmShellExt.msix`
  even when building a release MSI.

- **MSI version encoding.** The MSI product version must have a major component < 256, so the year prefix
  `20` must be stripped: `2026.1.0` → `26.1.0`. The registry decoder adds 2000 back.

- **MSBuild output filename.** MSBuild writes `Release\DevolutionsAgent.msi`. Rename it to the versioned
  form (`DevolutionsAgent-x86_64-<version>.msi`) after the build if needed for distribution.

## Step 1 — Build Rust Binaries

```powershell
cd D:\devolutions-gateway
$Env:PATH += ";C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64"  # needed for PEDM MSIX
$Env:RUSTFLAGS = "-C target-feature=+crt-static"                              # required — matches CI
cargo build --release -p devolutions-agent -p devolutions-session
cargo build -p devolutions-pedm-shell-ext  # debug only — MSIX step not wired into release profile
# devolutions-agent-updater.exe is produced automatically alongside devolutions-agent.exe
```

## Step 2 — Download tun2socks and wintun

```powershell
cd D:\devolutions-gateway
pwsh ci/download-tun2socks.ps1
# Produces: tun2socks.exe and wintun.dll in the repo root
```

## Step 3 — Build the .NET DesktopAgent

```powershell
cd D:\devolutions-gateway\dotnet\DesktopAgent
dotnet build
# Output: bin\Debug\net48\DevolutionsDesktopAgent.exe
```

## Step 4 — Build the MSI

```powershell
cd D:\devolutions-gateway\package\AgentWindowsManaged

$base = "D:\devolutions-gateway"
$Env:DAGENT_EXECUTABLE          = "$base\target\release\devolutions-agent.exe"
$Env:DAGENT_UPDATER_EXECUTABLE  = "$base\target\release\devolutions-agent-updater.exe"
$Env:DAGENT_PEDM_SHELL_EXT_DLL  = "$base\target\release\devolutions_pedm_shell_ext.dll"
$Env:DAGENT_PEDM_SHELL_EXT_MSIX = "$base\target\debug\DevolutionsPedmShellExt.msix"  # always debug
$Env:DAGENT_SESSION_EXECUTABLE  = "$base\target\release\devolutions-session.exe"
$Env:DAGENT_TUN2SOCKS_EXE       = "$base\tun2socks.exe"
$Env:DAGENT_WINTUN_DLL          = "$base\wintun.dll"
$Env:DAGENT_DESKTOP_AGENT_PATH  = "$base\dotnet\DesktopAgent\bin\Debug\net48"
$version = (Get-Content "$base\VERSION" -Raw).Trim()
if ($version.StartsWith("20")) { $version = $version.Substring(2) }  # strip century: 2026.1.0 → 26.1.0
$Env:DAGENT_VERSION  = $version
$Env:DAGENT_PLATFORM = "x64"

& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" DevolutionsAgent.sln /t:clean,restore,build /p:Configuration=Release /verbosity:minimal
```

**Output:** `package/AgentWindowsManaged/Release/DevolutionsAgent.msi`

Optionally rename to a versioned filename and compute the SHA-256 (needed for `productinfo.json`):

```powershell
$msi = "D:\devolutions-gateway\package\AgentWindowsManaged\Release\DevolutionsAgent.msi"
$versioned = "D:\devolutions-gateway\package\AgentWindowsManaged\Release\DevolutionsAgent-x86_64-20$($Env:DAGENT_VERSION).0.msi"
Copy-Item $msi $versioned -Force
$hash = (Get-FileHash $versioned -Algorithm SHA256).Hash
$hash | Set-Content "$([System.IO.Path]::ChangeExtension($versioned, 'sha'))"
```

## Installing the MSI

**Always install with administrator rights.** Double-clicking the MSI from Explorer runs the installer
under an impersonated (non-elevated) token, which causes `Error code 5` or silent failures in custom
actions that require elevation.

Install from an **already-elevated** PowerShell prompt:

```powershell
# Option 1 — msiexec with log (recommended for debugging)
msiexec /i "C:\path\to\DevolutionsAgent-x86_64-2026.1.0.0.msi" /l*v "C:\path\to\log.log"

# Option 2 — silent install
msiexec /i "C:\path\to\DevolutionsAgent-x86_64-2026.1.0.0.msi" /quiet
```

## Common Build Failures

### Missing `WixSharp.wix.bin` NuGet Package

```powershell
cd D:\devolutions-gateway\package\AgentWindowsManaged
dotnet add package WixSharp.wix.bin --prerelease
# Must match the WixSharp version (3.14.1)
```

### MakeAppx Not Found During PEDM Shell Ext Build

```powershell
$Env:PATH += ";C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64"
```

### `0xC0000135` / Exit Code `-1073741515` at Runtime

The binary was built without static CRT. Rebuild with `$Env:RUSTFLAGS = "-C target-feature=+crt-static"`
(see Step 1). This matches the CI build and eliminates the dependency on the MSVC redistributable.
