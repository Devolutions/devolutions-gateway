$VSINSTALLDIR = $(vswhere.exe -latest -requires Microsoft.VisualStudio.Component.VC.Llvm.Clang -property installationPath)
$Env:LIBCLANG_PATH="$VSINSTALLDIR\VC\Tools\Llvm\x64\bin"
$Env:PATH+=";$Env:ProgramFiles\NASM"

Enter-VsDevShell

$PackageVersion = "2024.08.22"
$StagingPath = Join-Path $Env:TEMP "staging"
$SymbolsPath = Join-Path $Env:TEMP "symbols"
New-Item -ItemType Directory $StagingPath -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory $SymbolsPath -ErrorAction SilentlyContinue | Out-Null

$TargetPlatform = "windows"
$TargetArch = "x86_64"
$TargetOutputPath = Join-Path $StagingPath $TargetPlatform $TargetArch
New-Item -ItemType Directory $TargetOutputPath -ErrorAction SilentlyContinue | Out-Null
$ExecutableFileName = "DevolutionsAgent_$TargetPlatform_${PackageVersion}_$TargetArch"
$ExecutableFileName = "$($ExecutableFileName).exe"

$PackageFileName = "DevolutionsAgent-$TargetArch-${PackageVersion}.msi"
$DAgentPackage = Join-Path $TargetOutputPath $PackageFileName
$DAgentExecutable = Join-Path $TargetOutputPath $ExecutableFileName
$DAgentPedmDesktopExecutable = Join-Path $TargetOutputPath "DevolutionsPedmDesktop.exe"
$DAgentPedmShellExtDll = Join-Path $TargetOutputPath "DevolutionsPedmShellExt.dll"
$DAgentPedmShellExtMsix = Join-Path $TargetOutputPath "DevolutionsPedmShellExt.msix"
$DAgentPedmHook = Join-Path $TargetOutputPath "devolutions_pedm_hook.dll"
$DAgentSessionExecutable = Join-Path $TargetOutputPath "DevolutionsSession.exe"

$DAgentPedmShellExtMsix = "C:\core\DevolutionsPedmShellExt.msix"

$Env:TARGET_OUTPUT_PATH=$TargetOutputPath
$Env:DAGENT_EXECUTABLE=$DAgentExecutable
$Env:DAGENT_PEDM_DESKTOP_EXECUTABLE = $DAgentPedmDesktopExecutable
$Env:DAGENT_PEDM_HOOK = $DAgentPedmHook
$Env:DAGENT_PEDM_SHELL_EXT_DLL = $DAgentPedmShellExtDll
$Env:DAGENT_PEDM_SHELL_EXT_MSIX = $DAgentPedmShellExtMsix
$Env:DAGENT_SESSION_EXECUTABLE = $DAgentSessionExecutable

./ci/tlk.ps1 build -Product agent -Platform $TargetPlatform -Architecture $TargetArch -CargoProfile 'release'
./ci/tlk.ps1 package -Product agent -Platform $TargetPlatform -Architecture $TargetArch -CargoProfile 'release'