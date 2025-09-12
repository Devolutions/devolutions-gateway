#
# Module manifest for module 'DevolutionsGateway'
#

@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'DevolutionsGateway.psm1'

    # Version number of this module.
    ModuleVersion = '2025.3.0'

    # Supported PSEditions
    CompatiblePSEditions = 'Desktop', 'Core'

    # ID used to uniquely identify this module
    GUID = 'cebec825-bc84-4a8a-a006-ab4be9bb6f87'

    # Author of this module
    Author = 'Devolutions'

    # Company or vendor of this module
    CompanyName = 'Devolutions'

    # Copyright statement for this module
    Copyright = '(c) 2019-2024 Devolutions Inc. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Devolutions Gateway PowerShell Module'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'
    
    # Name of the PowerShell host required by this module
    # PowerShellHostName = ''
    
    # Minimum version of the PowerShell host required by this module
    # PowerShellHostVersion = ''
    
    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    DotNetFrameworkVersion = '4.7.2'
    
    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    CLRVersion = '4.0'
    
    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''
    
    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()
    
    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @('bin\Devolutions.Picky.dll')
    
    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()
    
    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()
    
    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()
    
    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @('bin\DevolutionsGateway.dll')
    
    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        'Find-DGatewayConfig', 'Enter-DGatewayConfig', 'Exit-DGatewayConfig',
        'Set-DGatewayConfig', 'Get-DGatewayConfig',
        'New-DGatewayNgrokConfig', 'New-DGatewayNgrokTunnel',
        'Set-DGatewayHostname', 'Get-DGatewayHostname',
        'New-DGatewayListener', 'Get-DGatewayListeners', 'Set-DGatewayListeners',
        'Get-DGatewayPath', 'Get-DGatewayRecordingPath',
        'Set-DGatewayRecordingPath', 'Reset-DGatewayRecordingPath',
        'New-DGatewayCertificate', 'Import-DGatewayCertificate',
        'New-DGatewayProvisionerKeyPair', 'Import-DGatewayProvisionerKey',
        'New-DGatewayDelegationKeyPair', 'Import-DGatewayDelegationKey',
        'New-DGatewayToken',
        'New-DGatewayWebAppConfig',
        'Set-DGatewayUser', 'Remove-DGatewayUser', 'Get-DGatewayUser',
        'Start-DGateway', 'Stop-DGateway', 'Restart-DGateway',
        'Get-DGatewayVersion', 'Get-DGatewayPackage',
        'Install-DGatewayPackage', 'Uninstall-DGatewayPackage')
    
    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = @()
    
    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = @()
    
    # DSC resources to export from this module
    # DscResourcesToExport = @()
    
    # List of all modules packaged with this module
    # ModuleList = @()
    
    # List of all files packaged with this module
    # FileList = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = 'Devolutions', 'Gateway', 'RDM', 'DVLS', 'Hub', 'Windows', 'macOS', 'Linux', 'RemoteDesktop', 'VPN', 'Proxy'

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/Devolutions/devolutions-gateway/tree/master/powershell/LICENSE-MIT'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/Devolutions/devolutions-gateway/tree/master/powershell/'

            # A URL to an icon representing this module.
            IconUri = 'https://raw.githubusercontent.com/Devolutions/devolutions-gateway/master/powershell/logo.png'

            # ReleaseNotes of this module
            # ReleaseNotes = ''

            # Prerelease string of this module
            #Prerelease = 'rc1'

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            # RequireLicenseAcceptance = $false

            # External dependent modules of this module
            # ExternalModuleDependencies = @()

        } # End of PSData hashtable

    } # End of PrivateData hashtable
    # HelpInfo URI of this module
    # HelpInfoURI = ''
    
    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
    
    }
