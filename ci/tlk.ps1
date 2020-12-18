
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
            "aarch64" { "aarch64" }
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

    [void] Build() {
        $OPENSSL_VERSION = '1.1.1b-5'
        $ConanPackage = "openssl/${OPENSSL_VERSION}@devolutions/stable"
        $ConanProfile = "$($this.Target.Platform)-$($this.Target.Architecture)"
    
        $BuildStagingDirectory = Join-Path $this.SourcePath "artifacts"

        if (Test-Path Env:TARGET_OUTPUT_PATH) {
            $BuildStagingDirectory = $Env:TARGET_OUTPUT_PATH
        }

        if (-Not $this.Target.IsMacOS()) {
            # FIXME: this fails on CI build machines for macOS, maybe conan is outdated?
            
            & 'conan' 'install' $ConanPackage '-g' 'virtualenv' '-pr' $ConanProfile
            $dotenv = Get-DotEnvFile ".\environment.sh.env"
        
            Get-ChildItem 'conanbuildinfo.*' | Remove-Item
            Get-ChildItem 'environment.*.env' | Remove-Item
            Get-ChildItem '*activate.*' | Remove-Item
        
            $OPENSSL_DIR = $dotenv['OPENSSL_DIR']
            $Env:OPENSSL_DIR = $OPENSSL_DIR
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

        $CargoTarget = $this.Target.CargoTarget()

        $CargoArgs = @('build', '--release')
        $CargoArgs += @('--package', $CargoPackage)
        $CargoArgs += @('--target', $CargoTarget)

        & 'cargo' $CargoArgs

        $SrcExecutableName = $CargoPackage, $this.Target.ExecutableExtension -ne '' -Join '.'
        $SrcExecutablePath = "$($this.SourcePath)/target/${CargoTarget}/release/${SrcExecutableName}"

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
                $TimestampServer = 'http://timestamp.verisign.com/scripts/timstamp.dll'
                $SignToolArgs = @(
                    'sign', '/fd', 'SHA256', '/v',
                    '/n', $SignToolName,
                    '/t', $TimestampServer,
                    $DestinationExecutable
                )
                & 'signtool' $SignToolArgs
            }
        }

        Pop-Location
    }

    [void] Package() {
        $ShortVersion = $this.Version.Substring(2) # msi version
        $TargetArch = if ($this.Target.Architecture -eq 'x86_64') { 'x64' } else { 'x86' }
        
        $ModuleName = "DevolutionsGateway"
        $ModuleVersion = "2020.3.1" # both versions should match

        Push-Location
        Set-Location "$($this.SourcePath)/package/$($this.Target.Platform)"
        
        if (Test-Path Env:DGATEWAY_EXECUTABLE) {
            $DGatewayExecutable = $Env:DGATEWAY_EXECUTABLE
        } else {
            throw ("Specify DGATEWAY_EXECUTABLE environment variable")
        }
        
        Save-Module -Name $ModuleName -Force -RequiredVersion $ModuleVersion -Repository 'PSGallery' -Path '.'
        Remove-Item -Path "${ModuleName}/${ModuleVersion}/PSGetModuleInfo.xml" -ErrorAction 'SilentlyContinue'
        
        $WixExtensions = @('WixUtilExtension', 'WixUIExtension', 'WixFirewallExtension')
        $WixExtensions += $(Join-Path $(Get-Location) 'WixUserPrivilegesExtension.dll')
        
        $WixArgs = @($WixExtensions | ForEach-Object { @('-ext', $_) }) + @(
            "-dDGatewayPSSourceDir=${ModuleName}/${ModuleVersion}",
            "-dDGatewayExecutable=$DGatewayExecutable",
            "-dVersion=$ShortVersion", "-v")
        
        $WixFiles = @('DevolutionsGateway', "DevolutionsGateway-$TargetArch")
        
        $HeatArgs = @('dir', "${ModuleName}/${ModuleVersion}",
            "-dr", "DGATEWAYPSROOTDIRECTORY",
            "-cg", "DGatewayPSComponentGroup",
            '-var', 'var.DGatewayPSSourceDir',
            '-nologo', '-srd', '-suid', '-scom', '-sreg', '-sfrag', '-gg')
        
        & 'heat.exe' $HeatArgs + @('-t', 'HeatTransform64.xslt', '-o', "$($this.PackageName)-$TargetArch.wxs")
        
        $InputFiles = $WixFiles | ForEach-Object { "$_.wxs" }
        $ObjectFiles = $WixFiles | ForEach-Object { "$_.wixobj" }
        
        $Cultures = @('en-US', 'fr-FR')
        
        foreach ($Culture in $Cultures) {
            & 'candle.exe' "-nologo" $InputFiles $WixArgs "-dPlatform=$TargetArch" `
                "-dWixUILicenseRtf=$($this.PackageName)_EULA_${Culture}.rtf"
        
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

        if (Test-Path Env:DGATEWAY_PACKAGE) {
            $DGatewayPackage = $Env:DGATEWAY_PACKAGE
            Copy-Item -Path "$($this.PackageName).msi" -Destination $DGatewayPackage

            if (Test-Path Env:SIGNTOOL_NAME) {
                $SignToolName = $Env:SIGNTOOL_NAME
                $TimestampServer = 'http://timestamp.verisign.com/scripts/timstamp.dll'
                $SignToolArgs = @(
                    'sign', '/fd', 'SHA256', '/v',
                    '/n', $SignToolName,
                    '/t', $TimestampServer,
                    $DGatewayPackage
                )
                & 'signtool' $SignToolArgs
            }
        }

        Pop-Location
    }
}

function Invoke-TlkStep {
	param(
        [Parameter(Position=0,Mandatory=$true)]
		[ValidateSet('build','package')]
		[string] $TlkVerb,
		[ValidateSet('windows','macos','linux')]
		[string] $Platform,
		[ValidateSet('x86','x86_64','arm64')]
		[string] $Architecture
	)

    if (-Not $Platform) {
        $Platform = Get-TlkPlatform
    }

    if (-Not $Architecture) {
        $Architecture = Get-TlkArchitecture
    }

    $RootPath = Split-Path -Parent $PSScriptRoot

    $tlk = [TlkRecipe]::new()
    $tlk.SourcePath = $RootPath
    $tlk.Target.Platform = $Platform
    $tlk.Target.Architecture = $Architecture

    switch ($TlkVerb) {
        "build" { $tlk.Build() }
        "package" {$tlk.Package() }
    }
}

Invoke-TlkStep @args
