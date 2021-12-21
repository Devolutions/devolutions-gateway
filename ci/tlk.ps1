
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
        $AsByteStream = if ($PSEdition -eq 'Core') { @{AsByteStream = $true} } else { @{'Encoding' = 'Byte'} }
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

class TlkTarget
{
    [string] $Platform
    [string] $Architecture
    [string] $CargoProfile
    [string] $ExecutableExtension

    TlkTarget() {
        $this.Init()
    }

    [void] Init() {
        $this.Platform = Get-TlkPlatform
        $this.Architecture = Get-TlkArchitecture

        if ($this.IsWindows()) {
            $this.ExecutableExtension = 'exe'
        } else {
            $this.ExecutableExtension = ''
        }
    }

    [bool] IsWindows() {
        return $this.Platform -eq 'Windows'
    }

    [bool] IsMacOS() {
        return $this.Platform -eq 'macOS'
    }

    [bool] IsLinux() {
        return $this.Platform -eq 'Linux'
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
            "aarch64" { "arm64" }
        }
        
        return $DebianArchitecture
    }
}

class TlkRecipe
{
    [string] $PackageName
    [string] $Version
    [string] $SourcePath
    [bool] $Verbose
    [TlkTarget] $Target

    TlkRecipe() {
        $this.Init()
    }

    [void] Init() {
        $this.SourcePath = $($PSScriptRoot | Get-Item).Parent.FullName
        $this.PackageName = "DevolutionsGateway"
        $this.Version = $(Get-Content -Path "$($this.SourcePath)/VERSION").Trim()
        $this.Verbose = $true
        $this.Target = [TlkTarget]::new()
    }

    [void] BootstrapOpenSSL() {
        $OPENSSL_VERSION = '1.1.1l'
        $ConanPackage = "openssl/${OPENSSL_VERSION}@devolutions/stable"
        $ConanProfile = "$($this.Target.Platform)-$($this.Target.Architecture)"

        Write-Host "conan profile: $ConanProfile"


        & 'conan' 'install' $ConanPackage '-g' 'virtualenv' '-pr' $ConanProfile '-s' 'build_type=Release'
        $dotenv = Get-DotEnvFile ".\environment.sh.env"
    
        Get-ChildItem 'conanbuildinfo.*' | Remove-Item
        Get-ChildItem 'environment.*.env' | Remove-Item
        Get-ChildItem '*activate.*' | Remove-Item
    
        $OPENSSL_DIR = $dotenv['OPENSSL_DIR']
        $Env:OPENSSL_DIR = $OPENSSL_DIR
    }

    [void] Cargo([string[]]$CargoArgs) {
        $CargoTarget = $this.Target.CargoTarget()
        Write-Host "CargoTarget: $CargoTarget"

        $CargoProfile = $this.Target.CargoProfile
        Write-Host "CargoProfile: $CargoProfile"

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
        Invoke-Expression $CargoCmd
    }

    [void] Build() {
        $this.BootstrapOpenSSL()

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

        $CargoPackage = "devolutions-gateway"
        if (Test-Path Env:CARGO_PACKAGE) {
            $CargoPackage = $Env:CARGO_PACKAGE
        }
        Set-Location -Path $CargoPackage

        $CargoTarget = $this.Target.CargoTarget()
        Write-Host "CargoTarget: $CargoTarget"

        $CargoProfile = $this.Target.CargoProfile
        Write-Host "CargoProfile: $CargoProfile"

        $this.Cargo(@('build'))

        $SrcExecutableName = $CargoPackage, $this.Target.ExecutableExtension -ne '' -Join '.'
        $SrcExecutablePath = "$($this.SourcePath)/target/${CargoTarget}/${CargoProfile}/${SrcExecutableName}"

        if (-Not $this.Target.IsWindows()) {
            & 'strip' $SrcExecutablePath
        }

        if (Test-Path Env:DGATEWAY_EXECUTABLE) {
            $DGatewayExecutable = $Env:DGATEWAY_EXECUTABLE
            $DestinationExecutable = $DGatewayExecutable
        } elseif (Test-Path Env:JETSOCAT_EXECUTABLE) {
            $JetsocatExecutable = $Env:JETSOCAT_EXECUTABLE
            $DestinationExecutable = $JetsocatExecutable
        } else {
            $DestinationExecutable = $null
        }

        if ($DestinationExecutable) {
            Copy-Item -Path $SrcExecutablePath -Destination $DestinationExecutable

            if (Test-Path Env:SIGNTOOL_NAME) {
                $SignToolName = $Env:SIGNTOOL_NAME
                $TimestampServer = 'http://timestamp.comodoca.com/?td=sha256'
                $SignToolArgs = @(
                    'sign', '/fd', 'SHA256', '/v',
                    '/n', $SignToolName,
                    '/tr', $TimestampServer,
                    '/td', 'sha256',
                    $DestinationExecutable
                )
                & 'signtool' $SignToolArgs
            }
        }

        Pop-Location
    }

    [void] Package_Windows() {
        $PackageVersion = $this.Version
        $ShortVersion = $this.Version.Substring(2) # msi version
        $TargetArch = $this.Target.WindowsArchitecture()

        Push-Location
        Set-Location "$($this.SourcePath)/package/$($this.Target.Platform)"
        
        if (Test-Path Env:DGATEWAY_EXECUTABLE) {
            $DGatewayExecutable = $Env:DGATEWAY_EXECUTABLE
        } else {
            throw ("Specify DGATEWAY_EXECUTABLE environment variable")
        }

        if (Test-Path Env:DGATEWAY_PSMODULE_PATH) {
            $DGatewayPSModulePath = $Env:DGATEWAY_PSMODULE_PATH
        } else {
            throw ("Specify DGATEWAY_PSMODULE_PATH environment variable")
        }
        
        Write-Host $DGatewayExecutable
        Write-Host $DGatewayPSModulePath

        $PSManifestFile = $(@(Get-ChildItem -Path $DGatewayPSModulePath -Depth 1 -Filter "*.psd1")[0]).FullName
        Write-Host $PSManifestFile
        $PSManifest = Import-PowerShellDataFile -Path $PSManifestFile
        $PSModuleName = $(Get-Item $PSManifestFile).BaseName
        $PSModuleVersion = $PSManifest.ModuleVersion

        if ($PackageVersion -ne $PSModuleVersion) {
            Write-Warning "PowerShell module version mismatch: $PSModuleVersion (expected: $PackageVersion)"
        }

        $PSModuleParentPath = Split-Path $DGatewayPSModulePath -Parent
        $PSModuleZipFilePath = Join-Path $PSModuleParentPath "$PSModuleName-ps-$PSModuleVersion.zip"
        Compress-Archive -Path $DGatewayPSModulePath -Destination $PSModuleZipFilePath

        New-ModulePackage $DGatewayPSModulePath $PSModuleParentPath

        $WixExtensions = @('WixUtilExtension', 'WixUIExtension', 'WixFirewallExtension')
        $WixExtensions += $(Join-Path $(Get-Location) 'WixUserPrivilegesExtension.dll')
        
        $WixArgs = @($WixExtensions | ForEach-Object { @('-ext', $_) }) + @(
            "-dDGatewayPSSourceDir=$DGatewayPSModulePath",
            "-dDGatewayExecutable=$DGatewayExecutable",
            "-dVersion=$ShortVersion", "-v")
        
        $WixFiles = @('DevolutionsGateway', "DevolutionsGateway-$TargetArch", "WixUI_CustomInstallDir")
        
        $HeatArgs = @('dir', "$DGatewayPSModulePath",
            "-dr", "DGATEWAYPSROOTDIRECTORY",
            "-cg", "DGatewayPSComponentGroup",
            '-var', 'var.DGatewayPSSourceDir',
            '-nologo', '-srd', '-suid', '-scom', '-sreg', '-sfrag', '-gg')
        
        & 'heat.exe' $HeatArgs + @('-t', 'HeatTransform64.xslt', '-o', "$($this.PackageName)-$TargetArch.wxs")
        
        $InputFiles = $WixFiles | ForEach-Object { "$_.wxs" }
        $ObjectFiles = $WixFiles | ForEach-Object { "$_.wixobj" }

        $Cultures = @('en-US', 'fr-FR')
        
        foreach ($Culture in $Cultures) {
            & 'candle.exe' "-nologo" $InputFiles $WixArgs "-dPlatform=$TargetArch"
            $OutputFile = "$($this.PackageName)_${Culture}.msi"
        
            if ($Culture -eq 'en-US') {
                $OutputFile = "$($this.PackageName).msi"
            }
        
            & 'light.exe' "-v" "-nologo" $ObjectFiles "-cultures:${Culture}" "-loc" "$($this.PackageName)_${Culture}.wxl" `
                "-out" $OutputFile $WixArgs "-dPlatform=$TargetArch" "-sice:ICE61"
        }
        
        foreach ($Culture in $($Cultures | Select-Object -Skip 1)) {
            & 'torch.exe' "-v" "$($this.PackageName).msi" "$($this.PackageName)_${Culture}.msi" "-o" "${Culture}_$TargetArch.mst"
            & 'cscript.exe' "/nologo" "WiSubStg.vbs" "$($this.PackageName).msi" "${Culture}_$TargetArch.mst" "1036"
            & 'cscript.exe' "/nologo" "WiLangId.vbs" "$($this.PackageName).msi" "Package" "1033,1036"
        }

        if (Test-Path Env:DGATEWAY_PSMODULE_CLEAN) {
            # clean up the extracted PowerShell module directory
            Remove-Item -Path $DGatewayPSModulePath -Recurse
        }

        if (Test-Path Env:DGATEWAY_PACKAGE) {
            $DGatewayPackage = $Env:DGATEWAY_PACKAGE
            Copy-Item -Path "$($this.PackageName).msi" -Destination $DGatewayPackage

            if (Test-Path Env:SIGNTOOL_NAME) {
                $SignToolName = $Env:SIGNTOOL_NAME
                $TimestampServer = 'http://timestamp.comodoca.com/?td=sha256'
                $SignToolArgs = @(
                    'sign', '/fd', 'SHA256', '/v',
                    '/n', $SignToolName,
                    '/tr', $TimestampServer,
                    '/td', 'sha256',
                    $DGatewayPackage
                )
                & 'signtool' $SignToolArgs
            }
        }

        Pop-Location
    }

    [void] Package_Linux() {
        $DebianArchitecture = $this.Target.DebianArchitecture()
        $Packager = "Devolutions Inc."
        $Email = "support@devolutions.net"
        $Website = "http://wayk.devolutions.net"
        $PackageVersion = $this.Version
        $DistroCodeName = "xenial" # Ubuntu 16.04
        $Dependencies = @('liblzma5', 'liblz4-1', '${shlibs:Depends}', '${misc:Depends}')

        $Env:DEBFULLNAME = $Packager
        $Env:DEBEMAIL = $Email

        if (Test-Path Env:DGATEWAY_EXECUTABLE) {
            $DGatewayExecutable = $Env:DGATEWAY_EXECUTABLE
        } else {
            throw ("Specify DGATEWAY_EXECUTABLE environment variable")
        }

        $InputPackagePath = Join-Path $this.SourcePath "package/Linux"

        $OutputPath = Join-Path $this.SourcePath "output"
        New-Item -Path $OutputPath -ItemType 'Directory' -Force | Out-Null

        $OutputPackagePath = Join-Path $OutputPath "gateway"
        $OutputDebianPath = Join-Path $OutputPackagePath "debian"

        @($OutputPath, $OutputPackagePath, $OutputDebianPath) | % {
            New-Item -Path $_ -ItemType 'Directory' -Force | Out-Null
        }

        Push-Location
        Set-Location $OutputPackagePath

        $DebPkgName = "devolutions-gateway"
        $PkgNameVersion = "${DebPkgName}_$($this.Version).0"
        $PkgNameTarget = "${PkgNameVersion}_${DebianArchitecture}"
        $CopyrightFile = Join-Path $InputPackagePath "gateway/copyright"

        # dh_make

        $DhMakeArgs = @('-e', $Email,
            '-n', '-s', '-p', $PkgNameVersion,
            '-y', '-c', 'custom',
            "--copyrightfile=$CopyrightFile")

        & 'dh_make' $DhMakeArgs

        # debian/docs
        Set-Content -Path "$OutputDebianPath/docs" -Value ""

        # debian/compat
        Set-Content -Path "$OutputDebianPath/compat" -Value "9"

        # debian/README.debian
        Remove-Item -Path "$OutputDebianPath/README.debian" -ErrorAction 'SilentlyContinue'

        # debian/rules
        $RulesFile = Join-Path $OutputDebianPath "rules"
        $RulesTemplate = Join-Path $InputPackagePath "gateway/template/rules"
        Merge-Tokens -TemplateFile $RulesTemplate -Tokens @{
            dgateway_executable = $DGatewayExecutable
            platform_dir = $InputPackagePath
        } -OutputFile $RulesFile

        # debian/control
        $ControlFile = Join-Path $OutputDebianPath "control"
        $ControlTemplate = Join-Path $InputPackagePath "gateway/template/control"
        Merge-Tokens -TemplateFile $ControlTemplate -Tokens @{
            arch = $DebianArchitecture
            deps = $($Dependencies -Join ",")
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
            $InputFile = Join-Path $InputPackagePath "gateway/debian/$_"
            $OutputFile = Join-Path $OutputDebianPath $_
            Copy-Item $InputFile $OutputFile
        }

        $DpkgBuildPackageArgs = @('-b', '-us', '-uc')
        & 'dpkg-buildpackage' $DpkgBuildPackageArgs

        if (Test-Path Env:TARGET_OUTPUT_PATH) {
            $TargetOutputPath = $Env:TARGET_OUTPUT_PATH
            New-Item -Path $TargetOutputPath -ItemType 'Directory' -Force | Out-Null
            Copy-Item "$OutputPath/${PkgNameTarget}.deb" "$TargetOutputPath/${PkgNameTarget}.deb"
            Copy-Item "$OutputPath/${PkgNameTarget}.changes" "$TargetOutputPath/${PkgNameTarget}.changes"
        }

        Pop-Location
    }

    [void] Package() {
        if ($this.Target.IsWindows()) {
            $this.Package_Windows()
        } elseif ($this.Target.IsLinux()) {
            $this.Package_Linux()
        }
    }

    [void] Test() {
        $this.BootstrapOpenSSL()
    
        Push-Location
        Set-Location $this.SourcePath

        $CargoArgs = @('test')

        if (Test-Path Env:CARGO_PACKAGE) {
            $CargoPackage = $Env:CARGO_PACKAGE
            Set-Location -Path $CargoPackage
        } else {
            $CargoArgs += '--workspace'
        }

        $CargoTarget = $this.Target.CargoTarget()
        Write-Host "CargoTarget: $CargoTarget"

        $CargoProfile = $this.Target.CargoProfile
        Write-Host "CargoProfile: $CargoProfile"

        $this.Cargo($CargoArgs)

        Pop-Location
    }
}

function Invoke-TlkStep {
	param(
        [Parameter(Position=0,Mandatory=$true)]
		[ValidateSet('build','package','test')]
		[string] $TlkVerb,
		[ValidateSet('windows','macos','linux')]
		[string] $Platform,
		[ValidateSet('x86','x86_64','arm64')]
		[string] $Architecture,
        [ValidateSet('release', 'production')]
        [string] $CargoProfile
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

    $RootPath = Split-Path -Parent $PSScriptRoot

    $tlk = [TlkRecipe]::new()
    $tlk.SourcePath = $RootPath
    $tlk.Target.Platform = $Platform
    $tlk.Target.Architecture = $Architecture
    $tlk.Target.CargoProfile = $CargoProfile

    switch ($TlkVerb) {
        "build" { $tlk.Build() }
        "package" { $tlk.Package() }
        "test" { $tlk.Test() }
    }
}

Invoke-TlkStep @args
