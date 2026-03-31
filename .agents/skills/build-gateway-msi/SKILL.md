---
name: build-gateway-msi
description: Build the Devolutions Gateway Windows MSI installer locally. Use when asked to build, compile, or rebuild the gateway MSI.
---

# Build Devolutions Gateway MSI Locally

## Required Tools

- **MSBuild** — VS 2022: `C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe`
- **Rust/cargo**
- **pnpm** — for building the web app
- **PowerShell 7+** (`pwsh`)
- **dotnet** — for the PowerShell module build

## Important Notes

- **Static CRT is required for CI-matching builds.** Without `+crt-static`, the binary fails at runtime
  with exit code `-1073741515` (`0xC0000135`, DLL not found) on machines without the MSVC redistributable.
  Always set `$Env:RUSTFLAGS = "-C target-feature=+crt-static"` before `cargo build --release`.
  For a local debug build this is optional, but release builds must use it.

- **Version stripping.** The MSI product version must have a major component < 256, so the century
  prefix `20` must be stripped: `2026.1.0` → `26.1.0`. This matches what `ci/Build/Build.psm1` does
  via `$version.Substring(2)`.

- **MSBuild output filename.** MSBuild writes `Release\DevolutionsGateway.msi`. Rename it to the
  versioned form if needed for distribution.

- **Web app build is slow** (~5-10 min). Skip it on repeated builds by reusing the existing
  `webapp\dist\` output; only rebuild if webapp source changed.

- **`download-cadeau.ps1` runs from `ci/`** and always writes to `../native-libs/`, which resolves to
  the repo root's `native-libs\` directory. The file you need is `native-libs\xmf.dll`.

## Step 1 — Build Rust Binary

```powershell
cd D:\devolutions-gateway
$Env:RUSTFLAGS = "-C target-feature=+crt-static"  # required for CI-matching release build
cargo build --release -p devolutions-gateway
# Output: target\release\devolutions-gateway.exe
```

For a quick local debug build (no static CRT required, faster):

```powershell
cd D:\devolutions-gateway
cargo build -p devolutions-gateway
# Output: target\debug\devolutions-gateway.exe
```

## Step 2 — Download Cadeau (xmf.dll)

```powershell
cd D:\devolutions-gateway
pwsh ci/download-cadeau.ps1 -Platform win -Architecture x64
# Output: native-libs\xmf.dll
```

## Step 3 — Build PowerShell Module

```powershell
cd D:\devolutions-gateway
pwsh powershell/build.ps1
# Output: powershell\package\DevolutionsGateway\
```

## Step 4 — Build Web App

`@devolutions/*` packages are hosted on a private JFrog Artifactory registry.
Before running `pnpm install` for the first time, configure authentication:

1. Log in: `npm login --registry=https://devolutions.jfrog.io/devolutions/api/npm/npm/`
2. Add these lines to `%USERPROFILE%\.npmrc` (they won't be added by `npm login` automatically):
   ```
   @devolutions:registry=https://devolutions.jfrog.io/devolutions/api/npm/npm/
   registry=https://registry.npmjs.org
   //devolutions.jfrog.io/artifactory/api/npm/npm/:_authToken=<same token as above>
   ```
   The third line is needed because the lockfile contains some package tarballs
   at `/artifactory/` paths (different from `/devolutions/`), so a second token entry is required.

Then build:

```powershell
cd D:\devolutions-gateway\webapp
pnpm install

# Build in dependency order: shadow-player → multi-video-player → apps
pnpm --filter '@devolutions/shadow-player' build       # packages/shadow-player
pnpm --filter '@devolutions/multi-video-player' build  # packages/multi-video-player (depends on shadow-player)
pnpm --filter './apps/gateway-ui' build
pnpm --filter './apps/recording-player' build          # depends on multi-video-player and shadow-player
# Outputs:
#   webapp\dist\gateway-ui\
#   webapp\dist\recording-player\
```

> **Note:** `pnpm build:libs` and `pnpm build:apps` may report "No projects matched" depending
> on pnpm version/workspace state. Use the explicit `--filter` commands above instead.

## Step 5 — Build the MSI

```powershell
cd D:\devolutions-gateway\package\WindowsManaged

$msbuild = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
$base = "D:\devolutions-gateway"

# Point at release binary (or replace with target\debug\devolutions-gateway.exe for debug build)
$Env:DGATEWAY_EXECUTABLE     = "$base\target\release\devolutions-gateway.exe"
$Env:DGATEWAY_LIB_XMF_PATH   = "$base\native-libs\xmf.dll"
$Env:DGATEWAY_PSMODULE_PATH  = "$base\powershell\package\DevolutionsGateway"
$Env:DGATEWAY_WEBCLIENT_PATH = "$base\webapp\dist\gateway-ui"
$Env:DGATEWAY_WEBPLAYER_PATH = "$base\webapp\dist\recording-player"
$version = (Get-Content "$base\VERSION" -Raw).Trim()
if ($version.StartsWith("20")) { $version = $version.Substring(2) }  # strip century: 2026.1.0 → 26.1.0
$Env:DGATEWAY_VERSION = $version

& $msbuild DevolutionsGateway.sln /t:clean,restore,build /p:Configuration=Release /verbosity:minimal
```

**Output:** `package/WindowsManaged/Release/DevolutionsGateway.msi`

Optionally rename to a versioned filename and compute the SHA-256:

```powershell
$msi = "D:\devolutions-gateway\package\WindowsManaged\Release\DevolutionsGateway.msi"
$versioned = "D:\devolutions-gateway\package\WindowsManaged\Release\DevolutionsGateway-x86_64-20$($Env:DGATEWAY_VERSION).0.msi"
Copy-Item $msi $versioned -Force
$hash = (Get-FileHash $versioned -Algorithm SHA256).Hash
$hash | Set-Content "$([System.IO.Path]::ChangeExtension($versioned, 'sha'))"
```

## Alternative — Use the Packaging Script

The `ci/package-gateway-windows.ps1` script sets env vars and runs MSBuild for you:

```powershell
$base = "D:\devolutions-gateway"
New-Item -ItemType Directory -Force -Path "$base\output\msi" | Out-Null

pwsh "$base\ci\package-gateway-windows.ps1" `
  -Exe        "$base\target\release\devolutions-gateway.exe" `
  -LibxmfFile "$base\native-libs\xmf.dll" `
  -PsModuleDir "$base\powershell\package\DevolutionsGateway" `
  -WebClientDir "$base\webapp\dist\gateway-ui" `
  -WebPlayerDir "$base\webapp\dist\recording-player" `
  -OutputDir  "$base\output\msi"
# Copies MSI to output\msi\DevolutionsGateway.msi
```

Note: the script requires `MSBuild.exe` to be on `$Env:PATH`. If it isn't, prepend it:

```powershell
$Env:PATH = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin;$Env:PATH"
```

## Installing the MSI

**Always install with administrator rights.** Double-clicking from Explorer runs the installer under an
impersonated (non-elevated) token, which causes `Error code 5` or silent failures in custom actions.

Install from an **already-elevated** PowerShell prompt:

```powershell
# Option 1 — msiexec with log (recommended for debugging)
msiexec /i "C:\path\to\DevolutionsGateway.msi" /l*v "C:\path\to\log.log"

# Option 2 — silent install
msiexec /i "C:\path\to\DevolutionsGateway.msi" /quiet
```

## Common Build Failures

### Missing `WixSharp.wix.bin` NuGet Package

```
error MSB4018: The "MSBuild" task failed unexpectedly.
```

```powershell
cd D:\devolutions-gateway\package\WindowsManaged
dotnet add package WixSharp.wix.bin --prerelease
```

### `0xC0000135` / Exit Code `-1073741515` at Runtime

The binary was built without static CRT. Rebuild with `$Env:RUSTFLAGS = "-C target-feature=+crt-static"`
(see Step 1). This matches CI and eliminates the dependency on the MSVC redistributable.

### `DGATEWAY_EXECUTABLE` Not Found

Program.cs checks that the file exists at MSBuild time. Ensure `cargo build` completed successfully
and the path in `$Env:DGATEWAY_EXECUTABLE` is correct (debug vs. release).

### `DGATEWAY_PSMODULE_PATH` Not Found / Empty

Run `pwsh powershell/build.ps1` first. The output directory is `powershell\package\DevolutionsGateway`.
If the build fails due to a missing NuGet source, the script adds `api.nuget.org` automatically; ensure
internet access or restore from cache.

### `DGATEWAY_WEBCLIENT_PATH` / `DGATEWAY_WEBPLAYER_PATH` Not Found

Run `pnpm install && pnpm build:libs && pnpm build:apps` in `webapp/`. Both `gateway-ui` and
`recording-player` must exist under `webapp\dist\` before the MSI build starts.

### `pnpm install` Fails with `ERR_PNPM_FETCH_404` for `@devolutions/icons`

`@devolutions/icons` is a private package not available on the public npm registry. It requires
access to a private npm registry (JFrog Artifactory). Fix:

1. Log in: `npm login --registry=https://devolutions.jfrog.io/devolutions/api/npm/npm/`
2. Append to `%USERPROFILE%\.npmrc`:
   ```
   @devolutions:registry=https://devolutions.jfrog.io/devolutions/api/npm/npm/
   registry=https://registry.npmjs.org
   //devolutions.jfrog.io/artifactory/api/npm/npm/:_authToken=<same token as the /devolutions/ line>
   ```
   The `/artifactory/` token entry is needed because some packages in the lockfile resolve
   to that URL path rather than `/devolutions/`.

### `pnpm build:libs` / `pnpm build:apps` — "No projects matched"

Use explicit `--filter` calls instead (see Step 4). The glob filters in `package.json` scripts
may not resolve depending on pnpm version.

The workspace library packages (`shadow-player`, `multi-video-player`) are in `packages/` and
must be built before the apps that consume them. Build order: `shadow-player` → `multi-video-player`
→ `gateway-ui` and `recording-player`.
