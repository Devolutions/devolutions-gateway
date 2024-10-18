
# global initialization

if (-Not (Test-Path 'variable:global:IsWindows')) {
    $global:IsWindows = $true; # Windows PowerShell 5.1 or earlier
}

if ($IsWindows) {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
}

function Get-DotEnvFile {
    param(
        [Parameter(Position=0,Mandatory=$true)]
        [string] $InputFile
    )

    $DotEnv = @{}
    $InputValue = Get-Content -Path $InputFile -Encoding UTF8 -ErrorAction Stop
    $($InputValue | Select-String -AllMatches -Pattern "^(.+)=`"(.+)`"$").Matches | ForEach-Object {
        $DotEnv.Add($_.Groups[1].Value, $_.Groups[2].Value)
    }
    return $DotEnv
}
function Merge-Tokens
{
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$true,ParameterSetName="TemplateValue")]
        [string] $TemplateValue,
        [Parameter(Mandatory=$true,ParameterSetName="TemplateFile")]
        [string] $TemplateFile,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [Hashtable] $Tokens,
        [string] $OutputFile
    )

    if ($TemplateFile) {
        $TemplateValue = Get-Content -Path $TemplateFile -Raw -Encoding UTF8
    }

    $TokenPattern = '{{([^}]+)}}'
    $OutputValue = [regex]::Replace($TemplateValue, $TokenPattern, { param($Match)
        $TokenName = $Match.Groups[1].Value.Trim()
        $Tokens[$TokenName]
    })

    if ($OutputFile) {
        $AsByteStream = if ($PSEdition -Eq 'Core') { @{AsByteStream = $true} } else { @{'Encoding' = 'Byte'} }
        $OutputBytes = $([System.Text.Encoding]::UTF8).GetBytes($OutputValue)
        Set-Content -Path $OutputFile -Value $OutputBytes @AsByteStream
    }

    $OutputValue
}

function New-ModulePackage
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $InputPath,
        [Parameter(Mandatory=$true,Position=1)]
        [string] $OutputPath,
        [string] $TempPath
    )

    $UniqueId = New-Guid

    if ([string]::IsNullOrEmpty($TempPath)) {
        $TempPath = [System.IO.Path]::GetTempPath()
    }

    $PSRepoName = "psrepo-$UniqueId"
    $PSRepoPath = Join-Path $TempPath $UniqueId

    if (-Not (Test-Path -Path $InputPath -PathType 'Container')) {
        throw "`"$InputPath`" does not exist"
    }

    $PSModulePath = $InputPath
    $PSManifestFile = $(@(Get-ChildItem -Path $PSModulePath -Depth 1 -Filter "*.psd1")[0]).FullName
    $PSManifest = Import-PowerShellDataFile -Path $PSManifestFile
    $PSModuleName = $(Get-Item $PSManifestFile).BaseName
    $PSModuleVersion = $PSManifest.ModuleVersion

    New-Item -Path $PSRepoPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

    $Params = @{
        Name = $PSRepoName;
        SourceLocation = $PSRepoPath;
        PublishLocation = $PSRepoPath;
        InstallationPolicy = "Trusted";
    }

    Register-PSRepository @Params | Out-Null

    $OutputFileName = "${PSModuleName}.${PSModuleVersion}.nupkg"
    $PSModulePackage = Join-Path $PSRepoPath $OutputFileName
    Remove-Item -Path $PSModulePackage -ErrorAction 'SilentlyContinue'
    Publish-Module -Path $PSModulePath -Repository $PSRepoName

    Unregister-PSRepository -Name $PSRepoName | Out-Null

    New-Item -Path $OutputPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
    $OutputFile = Join-Path $OutputPath $OutputFileName
    Copy-Item $PSModulePackage $OutputFile

    Remove-Item $PSmodulePackage
    Remove-Item -Path $PSRepoPath

    $OutputFile
}

function Get-DestinationSymbolFile {
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $DestinationExecutable,
        [Parameter(Mandatory=$true,Position=1)]
        [TlkTarget] $Target
    )

    $DestinationSymbolsName = $(Split-Path $DestinationExecutable -LeafBase) + ".$($Target.SymbolsExtension)"
    $DestinationDirectory  = Split-Path $DestinationExecutable -Parent

    Join-Path $DestinationDirectory $DestinationSymbolsName
}

function Get-TlkPlatform {
    param(
        [Parameter(Position=0)]
        [string] $Platform
    )

    if (-Not $Platform) {
        $Platform = if ($IsWindows) {
            'windows'
        } elseif ($IsMacOS) {
            'macos'
        } elseif ($IsLinux) {
            'linux'
        }
    }

    $Platform
}

function Get-TlkArchitecture {
    param(
        [Parameter(Position=0)]
        [string] $Architecture
    )

    if (-Not $Architecture) {
        $Architecture = 'x86_64'
    }

    $Architecture
}

function Get-TlkProduct {
    param(
        [Parameter(Position=0)]
        [string] $Product
    )

    if (-Not $Product) {
        $Product = 'gateway'
    }

    $Product
}

class TlkTarget
{
    [string] $Platform
    [string] $Architecture
    [string] $CargoProfile
    [string] $ExecutableExtension
    [string] $LibraryExtension
    [string] $SymbolsExtension

    TlkTarget() {
        $this.Init()
    }

    [void] Init() {
        $this.Platform = Get-TlkPlatform
        $this.Architecture = Get-TlkArchitecture

        if ($this.IsWindows()) {
            $this.ExecutableExtension = 'exe'
            $this.SymbolsExtension = 'pdb'
            $this.LibraryExtension = 'dll'
        } else {
            $this.ExecutableExtension = ''
            $this.SymbolsExtension = ''

            if ($this.IsMacOS()) {
                $this.LibraryExtension = 'dylib'
            } else {
                $this.LibraryExtension = 'so'
            }
        }
    }

    [bool] IsWindows() {
        return $this.Platform -Eq 'Windows'
    }

    [bool] IsMacOS() {
        return $this.Platform -Eq 'macOS'
    }

    [bool] IsLinux() {
        return $this.Platform -Eq 'Linux'
    }

    [string] CargoTarget() {

        $CargoArchitecture = `
        switch ($this.Architecture) {
            "x86" { "i686" }
            "x86_64" { "x86_64" }
            "x64" { "x86_64" }
            "aarch64" { "aarch64" }
            "arm64" { "aarch64" }
        }

        $CargoPlatform = `
        switch ($this.Platform.ToLower()) {
            "windows" { "pc-windows-msvc" }
            "macos" { "apple-darwin" }
            "ios" { "apple-ios" }
            "linux" { "unknown-linux-gnu" }
            "android" { "linux-android" }
        }

        return "${CargoArchitecture}-${CargoPlatform}"
    }

    [string] WindowsArchitecture() {

        $WindowsArchitecture = `
        switch ($this.Architecture) {
            "x86" { "x86" }
            "x86_64" { "x64" }
            "aarch64" { "ARM64" }
        }

        return $WindowsArchitecture
    }

    [string] DebianArchitecture() {
        # https://wiki.debian.org/Multiarch/Tuples

        $DebianArchitecture = `
        switch ($this.Architecture) {
            "x86" { "i386" }
            "x86_64" { "amd64" }
            "arm64" { "arm64" }
        }

        return $DebianArchitecture
    }
}

class TlkPackage
{
    [string] $Name
    [string] $Path
    [bool] $IsLibrary

    TlkPackage(
        [string] $Name,
        [string] $Path,
        [bool] $IsLibrary
    ) {
        $this.Init($Name, $Path, $IsLibrary)
    }

    [void] Init(
        [string] $Name,
        [string] $Path,
        [bool] $IsLibrary
    ) {
        $this.Name = $Name
        $this.Path = $Path
        $this.IsLibrary = $IsLibrary
    }

    [string] BinaryFileName([TlkTarget] $Target) {
        $SrcBinaryName, $SrcBinaryExtension = if ($this.IsLibrary) {
            $this.Name.Replace('-', '_'), $Target.LibraryExtension
        } else {
            $this.Name, $Target.ExecutableExtension
        }

        return $SrcBinaryName, $SrcBinaryExtension -ne '' -Join '.'
    }

    [string] SymbolsFileName([TlkTarget] $Target) {
        return $this.Name.Replace('-', '_'), $Target.SymbolsExtension -ne '' -Join '.'
    }
}

class TlkRecipe
{
    [string] $Product
    [string] $Version
    [string] $SourcePath
    [bool] $Verbose
    [TlkTarget] $Target

    static [object[]] $PackageLanguages = @(
        [PSCustomObject]@{
            Name = "en-US";
            LCID = 1033;
        },
        [PSCustomObject]@{
            Name = "fr-FR";
            LCID = 1036;
        }
    )

    TlkRecipe() {
        $this.Init()
    }

    [void] Init() {
        $this.SourcePath = $($PSScriptRoot | Get-Item).Parent.FullName
        $this.Version = $(Get-Content -Path "$($this.SourcePath)/VERSION").Trim()
        $this.Verbose = $true
        $this.Target = [TlkTarget]::new()
        $this.Product = Get-TlkProduct
    }

    [TlkPackage[]] CargoPackages() {
        $CargoPackages = `
        switch ($this.Product) {
            "gateway" { @([TlkPackage]::new("devolutions-gateway", "devolutions-gateway", $false)) }
            "agent" {
                $agentPackages = @([TlkPackage]::new("devolutions-agent", "devolutions-agent", $false))

                if ($this.Target.IsWindows()) {
                    $agentPackages += [TlkPackage]::new("devolutions-pedm-shell-ext", "crates/devolutions-pedm-shell-ext", $true)
                    $agentPackages += [TlkPackage]::new("devolutions-session", "devolutions-session", $false)
                }

                $agentPackages
            }
            "jetsocat" { @([TlkPackage]::new("jetsocat", "jetsocat", $false)) }
        }
        return $CargoPackages
    }

    [string] PackageName() {
        $PackageName = switch ($this.Product) {
            "gateway" { "DevolutionsGateway" }
            "agent" { "DevolutionsAgent" }
            "jetsocat" { "jetsocat" }
        }

        return $PackageName
    }

    [void] Cargo([string[]]$CargoArgs) {
        $CargoTarget = $this.Target.CargoTarget()
        $CargoProfile = $this.Target.CargoProfile

        $CargoArgs += @('--profile', $CargoProfile)
        $CargoArgs += @('--target', $CargoTarget)
        if (Test-Path Env:CARGO_NO_DEFAULT_FEATURES) {
            $CargoArgs += @('--no-default-features')
        }
        if (Test-Path Env:CARGO_FEATURES) {
            $CargoArgs += @('--features', $Env:CARGO_FEATURES)
        }

        $CargoCmd = $(@('cargo') + $CargoArgs) -Join ' '
        Write-Host $CargoCmd
        & cargo $CargoArgs | Out-Host
        if (!$?) {
            throw "cargo failed: $CargoArgs, cwd: $(Get-Location)"
        }
    }

    [void] Build() {
        $BuildStagingDirectory = Join-Path $this.SourcePath "artifacts"

        if (Test-Path Env:TARGET_OUTPUT_PATH) {
            $BuildStagingDirectory = $Env:TARGET_OUTPUT_PATH
        }

        if ($this.Target.IsWindows()) {
            $Env:RUSTFLAGS = "-C target-feature=+crt-static"
        }

        $OutputPath = "${BuildStagingDirectory}/$($this.Target.Platform)/$($this.Target.Architecture)"
        New-Item -Path $OutputPath -ItemType 'Directory' -Force | Out-Null

        Push-Location
        Set-Location $this.SourcePath

        $CargoPackages = $this.CargoPackages()
        $CargoTarget = $this.Target.CargoTarget()
        $CargoProfile = $this.Target.CargoProfile

        $CargoOutputPath = "$($this.SourcePath)/target/${CargoTarget}/${CargoProfile}"

        foreach ($CargoPackage in $CargoPackages) {
            Push-Location
            Set-Location -Path $CargoPackage.Path

            $this.Cargo(@('build'))

            $SrcBinaryPath = "${CargoOutputPath}/$($CargoPackage.BinaryFileName($this.Target))"

            $DestinationExecutable = switch ($this.Product) {
                "gateway" {
                    if (Test-Path Env:DGATEWAY_EXECUTABLE) {
                        $Env:DGATEWAY_EXECUTABLE
                    } else {
                        $null
                    }
                }
                "agent" {
                    if ($CargoPackage.Name -Eq "devolutions-agent" -And (Test-Path Env:DAGENT_EXECUTABLE)) {
                        $Env:DAGENT_EXECUTABLE
                    } elseif ($CargoPackage.Name -Eq "devolutions-pedm-shell-ext" -And (Test-Path Env:DAGENT_PEDM_SHELL_EXT_DLL)) {
                        $Env:DAGENT_PEDM_SHELL_EXT_DLL
                    } elseif ($CargoPackage.Name -Eq "devolutions-session" -And (Test-Path Env:DAGENT_SESSION_EXECUTABLE)) {
                        $Env:DAGENT_SESSION_EXECUTABLE
                    } else {
                        $null
                    }
                }
                "jetsocat" {
                    if (Test-Path Env:JETSOCAT_EXECUTABLE) {
                        $Env:JETSOCAT_EXECUTABLE
                    } else {
                        $null
                    }
                }
                Default {
                    $null
                }
            }

            if ($this.Target.IsWindows() -And $DestinationExecutable) {
                $SrcSymbolsPath = "${CargoOutputPath}/$($CargoPackage.SymbolsFileName($this.Target))"
                Copy-Item $SrcSymbolsPath -Destination $(Get-DestinationSymbolFile $DestinationExecutable $this.Target)
            } elseif (!$this.Target.IsWindows()) {
                $StripExecutable = 'strip'
                if (Test-Path Env:STRIP_EXECUTABLE) {
                    $StripExecutable = $Env:STRIP_EXECUTABLE
                }

                & $StripExecutable $SrcBinaryPath | Out-Host
            }

            if ($DestinationExecutable) {
                Copy-Item -Path $SrcBinaryPath -Destination $DestinationExecutable
            }

            if ($CargoPackage.Name -Eq 'devolutions-pedm-shell-ext') {
                if ($Null -Eq (Get-Command "MakeAppx.exe" -ErrorAction SilentlyContinue)) {
                    throw 'MakeAppx was not found in the PATH'
                }

                $CargoPackagePath = Get-Location

                Push-Location
                Set-Location $CargoOutputPath

                $MakeAppxOutput = & 'MakeAppx.exe' 'pack' '/f' "${CargoPackagePath}/mapping.txt" '/p' "./DevolutionsPedmShellExt.msix" '/nv' '/o'
                if (!$?) {
                    throw "MakeAppx package creation failed: ${MakeAppxOutput}"
                }

                Pop-Location

                if (Test-Path Env:DAGENT_PEDM_SHELL_EXT_MSIX) {
                    Copy-Item -Path $(Join-Path $CargoOutputPath "DevolutionsPedmShellExt.msix") -Destination $Env:DAGENT_PEDM_SHELL_EXT_MSIX
                }
            }

            Pop-Location
        }

        if ($this.Product -Eq "agent" -And $this.Target.IsWindows()) {
            & './crates/devolutions-pedm/DevolutionsPedmDesktop/build.ps1' | Out-Host

            if (Test-Path Env:DAGENT_PEDM_DESKTOP_EXECUTABLE) {
                $builtDesktopExe = Get-ChildItem -Recurse -Include 'DevolutionsPedmDesktop.exe' | Select-Object -First 1
                $builtDesktopPdb = Get-ChildItem -Recurse -Include 'DevolutionsPedmDesktop.pdb' | Select-Object -First 1

                Copy-Item -Path $builtDesktopExe -Destination $Env:DAGENT_PEDM_DESKTOP_EXECUTABLE
                Copy-Item -Path $builtDesktopPdb -Destination $(Get-DestinationSymbolFile $Env:DAGENT_PEDM_DESKTOP_EXECUTABLE $this.Target)

            }

            if (Test-Path Env:DAGENT_SESSION_EXECUTABLE) {
                $sessionExe = Get-ChildItem -Recurse -Include 'devolutions-session.exe' | Select-Object -First 1

                Copy-Item -Path $sessionExe -Destination $Env:DAGENT_SESSION_EXECUTABLE
            }
        }

        Pop-Location
    }

    [string[]] Package_Windows_Prepare_Ps1Module() {
        $PackageVersion = $this.Version

        if (Test-Path Env:DGATEWAY_PSMODULE_PATH) {
            $DGatewayPSModulePath = $Env:DGATEWAY_PSMODULE_PATH
        } else {
            throw ("Specify DGATEWAY_PSMODULE_PATH environment variable")
        }

        $PSManifestFile = $(@(Get-ChildItem -Path $DGatewayPSModulePath -Depth 1 -Filter "*.psd1")[0]).FullName
        $PSManifest = Import-PowerShellDataFile -Path $PSManifestFile
        $PSModuleName = $(Get-Item $PSManifestFile).BaseName
        $PSModuleVersion = $PSManifest.ModuleVersion

        if ($PackageVersion -ne $PSModuleVersion) {
            Write-Warning "PowerShell module version mismatch: $PSModuleVersion (expected: $PackageVersion)"
        }

        $PSModuleParentPath = Split-Path $DGatewayPSModulePath -Parent
        $PSModuleZipFilePath = Join-Path $PSModuleParentPath "$PSModuleName-ps-$PSModuleVersion.zip"
        Compress-Archive -Path $DGatewayPSModulePath -Destination $PSModuleZipFilePath -Update

        New-ModulePackage $DGatewayPSModulePath $PSModuleParentPath

        $DGatewayPSModuleStagingPath = Join-Path $Env:Temp "DevolutionsGateway"
        New-Item -Force -Type Directory $DGatewayPSModuleStagingPath
        Copy-Item -Force -Recurse $DGatewayPSModulePath/* $DGatewayPSModuleStagingPath
        $DotNetRid = "win-x64"
        Get-Item "$DGatewayPSModuleStagingPath\bin\*\*DevolutionsPicky*" | ? { $_.Directory.Name -ne $DotNetRid } | % { Remove-Item $_.Directory -Recurse }
        Remove-Item $(Join-Path $DGatewayPSModuleStagingPath "src") -Recurse  -ErrorAction SilentlyContinue

        return $DGatewayPSModulePath, $DGatewayPSModuleStagingPath
    }

    [void] Package_Windows_Managed_Assemble() {
        Push-Location

        $InputPackagePathPrefix = switch ($this.Product) {
            "gateway" { "" }
            "agent" { "Agent" }
        }

        Set-Location "$($this.SourcePath)/package/$($InputPackagePathPrefix)$($this.Target.Platform)Managed"

        $TargetConfiguration = "Release"

        # Build the base (en-US) MSI
        & ".\$TargetConfiguration\Build_$($this.PackageName()).cmd"

        $BaseMsi = Join-Path $TargetConfiguration "$($this.PackageName()).msi"

        foreach ($PackageLanguage in $([TlkRecipe]::PackageLanguages | Select-Object -Skip 1)) {
            # Build the localized MSI
            & ".\$TargetConfiguration\$($PackageLanguage.Name)\Build_$($this.PackageName()).cmd"
            $LangDir = Join-Path $TargetConfiguration $PackageLanguage.Name
            $LangMsi = Join-Path $LangDir "$($this.PackageName()).msi"
            $Transform = Join-Path $TargetConfiguration "$($PackageLanguage.Name).mst"
            # Generate a language transform
            & 'torch.exe' "$BaseMsi" "$LangMsi" "-o" "$Transform" | Out-Host
            # Embed the transform in the base MSI
            & 'cscript.exe' "/nologo" "../Windows/WiSubStg.vbs" "$BaseMsi" "$Transform" "$($PackageLanguage.LCID)" | Out-Host
        }

        # Set the complete language list on the base MSI
        $LCIDs = ([TlkRecipe]::PackageLanguages | ForEach-Object { $_.LCID }) -join ','
        & 'cscript.exe' "/nologo" "../Windows/WiLangId.vbs" "$BaseMsi" "Package" "$LCIDs" | Out-Host

        switch ($this.Product) {
            "gateway" {
                if (Test-Path Env:DGATEWAY_PACKAGE) {
                    $DGatewayPackage = $Env:DGATEWAY_PACKAGE
                    Copy-Item -Path "$BaseMsi" -Destination $DGatewayPackage
                }
            }
            "agent" {
                if (Test-Path Env:DAGENT_PACKAGE) {
                    $DAgentPackage = $Env:DAGENT_PACKAGE
                    Copy-Item -Path "$BaseMsi" -Destination $DAgentPackage
                }
            }
        }

        Pop-Location
    }

    [void] Package_Windows_Managed_Gateway([bool] $SourceOnlyBuild) {
        $ShortVersion = $this.Version.Substring(2) # msi version

        $Env:DGATEWAY_VERSION="$ShortVersion"

        Push-Location
        Set-Location "$($this.SourcePath)/package/$($this.Target.Platform)Managed"

        if (Test-Path Env:DGATEWAY_EXECUTABLE) {
            $DGatewayExecutable = $Env:DGATEWAY_EXECUTABLE
        } else {
            throw ("Specify DGATEWAY_EXECUTABLE environment variable")
        }

        $PSModulePaths = $this.Package_Windows_Prepare_Ps1Module()
        $DGatewayPSModulePath = $PSModulePaths[0]
        $DGatewayPSModuleStagingPath = $PSModulePaths[1]

        $TargetConfiguration = "Release"

        if ($SourceOnlyBuild) {
            $Env:DGATEWAY_MSI_SOURCE_ONLY_BUILD = "1"
        }

        & 'MSBuild.exe' "DevolutionsGateway.sln" "/t:restore,build" "/p:Configuration=$TargetConfiguration" | Out-Host

        if ($SourceOnlyBuild) {
            foreach ($PackageLanguage in $([TlkRecipe]::PackageLanguages | Select-Object -Skip 1)) {
                $Env:DGATEWAY_MSI_LANG_ID = $PackageLanguage.Name
                & 'MSBuild.exe' "DevolutionsGateway.sln" "/t:restore,build" "/p:Configuration=$TargetConfiguration" | Out-Host
            }
        }

        $Env:DGATEWAY_MSI_SOURCE_ONLY_BUILD = ""
        $Env:DGATEWAY_MSI_LANG_ID = ""

        if (!$SourceOnlyBuild -And (Test-Path Env:DGATEWAY_PSMODULE_CLEAN)) {
            # clean up the extracted PowerShell module directory
            Remove-Item -Path $DGatewayPSModulePath -Recurse
            Remove-Item -Path $DGatewayPSModuleStagingPath -Recurse
        }

        if (!$SourceOnlyBuild -And (Test-Path Env:DGATEWAY_PACKAGE)) {
            $DGatewayPackage = $Env:DGATEWAY_PACKAGE
            $MsiPath = Join-Path "Release" "$($this.PackageName()).msi"
            Copy-Item -Path "$MsiPath" -Destination $DGatewayPackage
        }

        Pop-Location
    }

    [void] Package_Windows_Managed_Agent([bool] $SourceOnlyBuild) {
        $ShortVersion = $this.Version.Substring(2) # msi version

        $Env:DAGENT_VERSION="$ShortVersion"

        Push-Location
        Set-Location "$($this.SourcePath)/package/Agent$($this.Target.Platform)Managed"

        if (Test-Path Env:DAGENT_EXECUTABLE) {
            $DGatewayExecutable = $Env:DAGENT_EXECUTABLE
        } else {
            throw ("Specify DAGENT_EXECUTABLE environment variable")
        }

        $TargetConfiguration = "Release"

        if ($SourceOnlyBuild) {
            $Env:DAGENT_MSI_SOURCE_ONLY_BUILD = "1"
        }

        & 'MSBuild.exe' "DevolutionsAgent.sln" "/t:restore,build" "/p:Configuration=$TargetConfiguration" | Out-Host

        if ($SourceOnlyBuild) {
            foreach ($PackageLanguage in $([TlkRecipe]::PackageLanguages | Select-Object -Skip 1)) {
                $Env:DAGENT_MSI_LANG_ID = $PackageLanguage.Name
                & 'MSBuild.exe' "DevolutionsAgent.sln" "/t:restore,build" "/p:Configuration=$TargetConfiguration" | Out-Host
            }
        }

        $Env:DAGENT_MSI_SOURCE_ONLY_BUILD = ""
        $Env:DAGENT_MSI_LANG_ID = ""

        if (!$SourceOnlyBuild -And (Test-Path Env:DAGENT_PACKAGE)) {
            $DAgentPackage = $Env:DAGENT_PACKAGE
            $MsiPath = Join-Path "Release" "$($this.PackageName()).msi"
            Copy-Item -Path "$MsiPath" -Destination $DAgentPackage
        }

        Pop-Location
    }

    [void] Package_Windows_Managed([bool] $SourceOnlyBuild) {
        if ((Get-Command "MSBuild.exe" -ErrorAction SilentlyContinue) -Eq $Null) {
            throw 'MSBuild was not found in the PATH'
        }

        if ($this.Product -eq 'gateway') {
            $this.Package_Windows_Managed_Gateway($SourceOnlyBuild)
        } elseif ($this.Product -eq 'agent') {
            $this.Package_Windows_Managed_Agent($SourceOnlyBuild)
        } else {
            throw "Managed packaging for $($this.Product) is not supported"
        }
    }

    [void] Package_Windows() {
        if ($this.Product -ne 'gateway') {
            throw "Legacy packaging for $($this.Product) is not supported"
        }

        $ShortVersion = $this.Version.Substring(2) # msi version
        $TargetArch = $this.Target.WindowsArchitecture()

        Push-Location
        Set-Location "$($this.SourcePath)/package/$($this.Target.Platform)"

        if (Test-Path Env:DGATEWAY_EXECUTABLE) {
            $DGatewayExecutable = $Env:DGATEWAY_EXECUTABLE
        } else {
            throw ("Specify DGATEWAY_EXECUTABLE environment variable")
        }

        $PSModulePaths = $this.Package_Windows_Prepare_Ps1Module()
        $DGatewayPSModulePath = $PSModulePaths[0]
        $DGatewayPSModuleStagingPath = $PSModulePaths[1]

        $TargetConfiguration = "Release"
        $ActionsProjectPath = Join-Path $(Get-Location) 'Actions'

        if ((Get-Command "MSBuild.exe" -ErrorAction SilentlyContinue) -Eq $Null) {
            throw 'MSBuild was not found in the PATH'
        }

        & 'MSBuild.exe' "$(Join-Path $ActionsProjectPath 'DevolutionsGateway.Installer.Actions.sln')" "/p:Configuration=$TargetConfiguration" "/p:Platform=$TargetArch" | Out-Host

        $HeatArgs = @('dir', "$DGatewayPSModuleStagingPath",
            '-dr', 'D.DGATEWAYPSROOTDIRECTORY',
            '-cg', 'CG.DGatewayPSComponentGroup',
            '-var', 'var.DGatewayPSSourceDir',
            '-nologo', '-srd', '-suid', '-scom', '-sreg', '-sfrag', '-gg')

        & 'heat.exe' $HeatArgs + @('-t', 'HeatTransform64.xslt', '-o', "$($this.PackageName())-$TargetArch.wxs") | Out-Host

        $WixExtensions = @('WixUtilExtension', 'WixUIExtension', 'WixFirewallExtension')
        $WixExtensions += $(Join-Path $(Get-Location) 'WixUserPrivilegesExtension.dll')

        $WixArgs = @($WixExtensions | ForEach-Object { @('-ext', $_) }) + @(
            "-dDGatewayPSSourceDir=$DGatewayPSModuleStagingPath",
            "-dDGatewayExecutable=$DGatewayExecutable",
            "-dVersion=$ShortVersion",
            "-dActionsLib=$(Join-Path $ActionsProjectPath $TargetArch $TargetConfiguration 'DevolutionsGateway.Installer.Actions.dll')",
            "-v")

        $WixFiles = Get-ChildItem -Include '*.wxs' -Recurse

        $InputFiles = $WixFiles | Foreach-Object { Resolve-Path $_.FullName -Relative }
        $ObjectFiles = $WixFiles | ForEach-Object { $_.BaseName + '.wixobj' }

        $Cultures = @('en-US', 'fr-FR')

        foreach ($Culture in $Cultures) {
            & 'candle.exe' '-nologo' $InputFiles $WixArgs "-dPlatform=$TargetArch" | Out-Host
            $OutputFile = "$($this.PackageName())_${Culture}.msi"

            if ($Culture -Eq 'en-US') {
                $OutputFile = "$($this.PackageName()).msi"
            }

            & 'light.exe' "-nologo" $ObjectFiles "-cultures:${Culture}" "-loc" "$($this.PackageName)_${Culture}.wxl" `
                "-out" $OutputFile $WixArgs "-dPlatform=$TargetArch" "-sice:ICE61" | Out-Host
        }

        foreach ($Culture in $($Cultures | Select-Object -Skip 1)) {
            & 'torch.exe' "$($this.PackageName()).msi" "$($this.PackageName())_${Culture}.msi" "-o" "${Culture}_$TargetArch.mst" | Out-Host
            & 'cscript.exe' "/nologo" "WiSubStg.vbs" "$($this.PackageName()).msi" "${Culture}_$TargetArch.mst" "1036" | Out-Host
            & 'cscript.exe' "/nologo" "WiLangId.vbs" "$($this.PackageName()).msi" "Package" "1033,1036" | Out-Host
        }

        if (Test-Path Env:DGATEWAY_PSMODULE_CLEAN) {
            # clean up the extracted PowerShell module directory
            Remove-Item -Path $DGatewayPSModulePath -Recurse
            Remove-Item -Path $DGatewayPSModuleStagingPath -Recurse
        }

        if (Test-Path Env:DGATEWAY_PACKAGE) {
            $DGatewayPackage = $Env:DGATEWAY_PACKAGE
            Copy-Item -Path "$($this.PackageName()).msi" -Destination $DGatewayPackage
        }

        Pop-Location
    }

    [void] Package_Linux() {
        $DebianArchitecture = $this.Target.DebianArchitecture()
        $Packager = "Devolutions Inc."
        $Email = "support@devolutions.net"
        $Website = "https://devolutions.net"
        $PackageVersion = $this.Version
        $DistroCodeName = "focal" # Ubuntu 20.04
        $Dependencies = @('liblzma5', 'liblz4-1')

        if ($this.Target.DebianArchitecture() -Eq 'arm64') {
            $Dependencies += @("libc6 (>= 2.29)", "libgcc-s1 (>= 4.2)")
        } else {
            $Dependencies += @('${shlibs:Depends}', '${misc:Depends}')
        }

        $Env:DEBFULLNAME = $Packager
        $Env:DEBEMAIL = $Email

        $DGatewayExecutable = $null
        $DGatewayWebClient = $null
        $DGatewayLibXmf = $null
        $DAgentExecutable = $null

        switch ($this.Product) {
            "gateway" {
                if (Test-Path Env:DGATEWAY_EXECUTABLE) {
                    $DGatewayExecutable = $Env:DGATEWAY_EXECUTABLE
                } else {
                    throw ("Specify DGATEWAY_EXECUTABLE environment variable")
                }

                if (Test-Path Env:DGATEWAY_WEBCLIENT_PATH) {
                    $DGatewayWebClient = $Env:DGATEWAY_WEBCLIENT_PATH
                } else {
                    throw ("Specify DGATEWAY_WEBCLIENT_PATH environment variable")
                }

                if (Test-Path Env:DGATEWAY_LIB_XMF_PATH) {
                    $DGatewayLibXmf = $Env:DGATEWAY_LIB_XMF_PATH
                } else {
                    throw ("Specify DGATEWAY_LIB_XMF_PATH environment variable")
                }
            }
            "agent" {
                if (Test-Path Env:DAGENT_EXECUTABLE) {
                    $DAgentExecutable = $Env:DAGENT_EXECUTABLE
                } else {
                    throw ("Specify DAGENT_EXECUTABLE environment variable")
                }
            }
        }

        $InputPackagePathPrefix = switch ($this.Product) {
            "gateway" { "" }
            "agent" { "Agent" }
        }

        $InputPackagePath = Join-Path $this.SourcePath "package/$($InputPackagePathPrefix)Linux"

        $OutputPath = Join-Path $this.SourcePath "output"
        New-Item -Path $OutputPath -ItemType 'Directory' -Force | Out-Null

        $OutputPackagePath = Join-Path $OutputPath "$($this.Product)"
        $OutputDebianPath = Join-Path $OutputPackagePath "debian"

        @($OutputPath, $OutputPackagePath, $OutputDebianPath) | % {
            New-Item -Path $_ -ItemType 'Directory' -Force | Out-Null
        }

        Push-Location
        Set-Location $OutputPackagePath

        $DebPkgName = "devolutions-$($this.Product)"
        $PkgNameVersion = "${DebPkgName}_$($this.Version).0"
        $PkgNameTarget = "${PkgNameVersion}_${DebianArchitecture}"
        $CopyrightFile = Join-Path $InputPackagePath "$($this.Product)/copyright"

        # dh_make

        $DhMakeArgs = @('-e', $Email,
            '-n', '-s', '-p', $PkgNameVersion,
            '-y', '-c', 'custom',
            "--copyrightfile=$CopyrightFile")

        & 'dh_make' $DhMakeArgs | Out-Host

        # debian/docs
        Set-Content -Path "$OutputDebianPath/docs" -Value ""

        # debian/compat
        Set-Content -Path "$OutputDebianPath/compat" -Value "9"

        # debian/README.debian
        Remove-Item -Path "$OutputDebianPath/README.debian" -ErrorAction 'SilentlyContinue'

        # debian/rules
        $RulesFile = Join-Path $OutputDebianPath "rules"
        $RulesTemplate = Join-Path $InputPackagePath "$($this.Product)/template/rules"

        $DhShLibDepsOverride = "";
        if ($this.Target.DebianArchitecture() -Eq "amd64") {
            $DhShLibDepsOverride = "dh_shlibdeps"
        }

        switch ($this.Product) {
            "gateway" {
                Merge-Tokens -TemplateFile $RulesTemplate -Tokens @{
                    root_path = $this.SourcePath
                    dgateway_executable = $DGatewayExecutable
                    dgateway_webclient = $DGatewayWebClient
                    dgateway_libxmf = $DGatewayLibXmf
                    platform_dir = $InputPackagePath
                    dh_shlibdeps = $DhShLibDepsOverride
                } -OutputFile $RulesFile
            }
            "agent" {
                Merge-Tokens -TemplateFile $RulesTemplate -Tokens @{
                    dagent_executable = $DAgentExecutable
                    platform_dir = $InputPackagePath
                    dh_shlibdeps = $DhShLibDepsOverride
                } -OutputFile $RulesFile
            }
        }

        # debian/control
        $ControlFile = Join-Path $OutputDebianPath "control"
        $ControlTemplate = Join-Path $InputPackagePath "$($this.Product)/template/control"
        Merge-Tokens -TemplateFile $ControlTemplate -Tokens @{
            arch = $DebianArchitecture
            deps = $($Dependencies -Join ", ")
            email = $Email
            package = $Packager
            website = $Website
        } -OutputFile $ControlFile

        # debian/copyright
        $CopyrightFile = Join-Path $OutputDebianPath "copyright"
        $CopyrightTemplate = Join-Path $InputPackagePath "template/copyright"

        Merge-Tokens -TemplateFile $CopyrightTemplate -Tokens @{
            package = $DebPkgName
            packager = $Packager
            year = $(Get-Date).Year
            website = $Website
        } -OutputFile $CopyrightFile

        # debian/changelog
        $ChangelogFile = Join-Path $OutputDebianPath "changelog"
        $ChangelogTemplate = Join-Path $InputPackagePath "template/changelog"

        Merge-Tokens -TemplateFile $ChangelogTemplate -Tokens @{
            package = $DebPkgName
            distro = $DistroCodeName
            email = $Email
            packager = $Packager
            version = "${PackageVersion}.0"
            date = $($(Get-Date -UFormat "%a, %d %b %Y %H:%M:%S %Z00") -Replace '\.','')
        } -OutputFile $ChangelogFile

        @('postinst', 'prerm', 'postrm') | % {
            $InputFile = Join-Path $InputPackagePath "$($this.Product)/debian/$_"
            $OutputFile = Join-Path $OutputDebianPath $_
            Copy-Item $InputFile $OutputFile
        }

        $DpkgBuildPackageArgs = @('-b', '-us', '-uc')

        if ($this.Target.DebianArchitecture() -Eq 'arm64') {
            $DpkgBuildPackageArgs += @('-a', $this.Target.DebianArchitecture())
        }

        & 'dpkg-buildpackage' $DpkgBuildPackageArgs | Out-Host

        if (Test-Path Env:TARGET_OUTPUT_PATH) {
            $TargetOutputPath = $Env:TARGET_OUTPUT_PATH
            New-Item -Path $TargetOutputPath -ItemType 'Directory' -Force | Out-Null
            Copy-Item "$OutputPath/${PkgNameTarget}.deb" "$TargetOutputPath/${PkgNameTarget}.deb"
            Copy-Item "$OutputPath/${PkgNameTarget}.changes" "$TargetOutputPath/${PkgNameTarget}.changes"
        }

        Pop-Location
    }

    [void] Package([string]$PackageOption) {
        if ($this.Product -Eq 'jetsocat') {
            throw "Packaging for $($this.Product) is not supported"
        }

        if ($this.Target.IsWindows()) {
            if (-Not $PackageOption ) {
                $this.Package_Windows_Managed($false)
                return
            }

            switch ($PackageOption) {
                "legacy" {
                    $this.Package_Windows()
                }
                "generate" {
                    $this.Package_Windows_Managed($true)
                }
                "assemble" {
                    $this.Package_Windows_Managed_Assemble()
                }
                default {
                    throw "unrecognized package command: $PackageOption"
                }
            }
        } elseif ($this.Target.IsLinux()) {
            $this.Package_Linux()
        }
    }

    [void] Test() {
        Push-Location
        Set-Location $this.SourcePath

        $CargoArgs = @('test')

        if (Test-Path Env:CARGO_PACKAGE) {
            $CargoPackage = $Env:CARGO_PACKAGE
            Set-Location -Path $CargoPackage
        } else {
            $CargoArgs += '--workspace'
        }

        $CargoArgs += '--verbose'
        $CargoArgs += '--locked'

        $CargoTarget = $this.Target.CargoTarget()
        $CargoProfile = $this.Target.CargoProfile

        $this.Cargo($CargoArgs)

        Pop-Location
    }
}

function Invoke-TlkStep {
	param(
        [Parameter(Position=0,Mandatory=$true)]
		[ValidateSet('build','package','test')]
		[string] $TlkVerb,
        [ValidateSet('legacy', 'generate', 'assemble')]
        [string] $PackageOption,
		[ValidateSet('windows','macos','linux')]
		[string] $Platform,
		[ValidateSet('x86','x86_64','arm64')]
		[string] $Architecture,
        [ValidateSet('dev', 'release', 'production')]
        [string] $CargoProfile,
        [ValidateSet('gateway', 'agent', 'jetsocat')]
        [string] $Product
	)

    if (-Not $Platform) {
        $Platform = Get-TlkPlatform
    }

    if (-Not $Architecture) {
        $Architecture = Get-TlkArchitecture
    }

    if (-Not $CargoProfile) {
        $CargoProfile = 'release'
    }

    if (-Not $Product) {
        Write-Warning "`[LEGACY] Product` parameter is not specified, defaulting to 'gateway'"
        $Product = 'gateway'
    }

    $RootPath = Split-Path -Parent $PSScriptRoot

    $tlk = [TlkRecipe]::new()
    $tlk.SourcePath = $RootPath
    $tlk.Target.Platform = $Platform
    $tlk.Target.Architecture = $Architecture
    $tlk.Target.CargoProfile = $CargoProfile
    $tlk.Product = $Product

    switch ($TlkVerb) {
        "build" { $tlk.Build() }
        "package" { $tlk.Package($PackageOption) }
        "test" { $tlk.Test() }
    }
}

Invoke-TlkStep @args
