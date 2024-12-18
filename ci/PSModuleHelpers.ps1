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
    $PSModulePrerelease = $PSManifest.PrivateData.PSData.Prerelease

    # https://docs.microsoft.com/en-us/nuget/concepts/package-versioning#normalized-version-numbers
    $NugetVersion = $PSModuleVersion -Replace "^(\d+)\.(\d+)\.(\d+)(\.0)$", "`$1.`$2.`$3"
    $NugetVersion = (@($NugetVersion, $PSModulePrerelease) | Where-Object { $_ }) -Join '-'

    New-Item -Path $PSRepoPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

    $Params = @{
        Name = $PSRepoName;
        SourceLocation = $PSRepoPath;
        PublishLocation = $PSRepoPath;
        InstallationPolicy = "Trusted";
    }

    Register-PSRepository @Params | Out-Null

    $OutputFileName = "${PSModuleName}.${NugetVersion}.nupkg"
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

function Repair-ModulePackage
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $PackageFile,
        [string] $UnpackedDir
    )

    if (-Not (Test-Path -Path $PackageFile)) {
        throw "`"$PackageFile`" does not exist"
    }

    if (-Not $PackageFile.EndsWith('.nupkg')) {
        throw "`"$PackageFile`" does not have .nupkg file extension"
    }

    $PackageFileItem = $(Get-Item $PackageFile)
    $OutputDirectory = $PackageFileItem.Directory.FullName
    if ([string]::IsNullOrEmpty($UnpackedDir)) {
        $UnpackedDir = Join-Path $OutputDirectory $PackageFileItem.BaseName
    }

    Remove-Item -Path $UnpackedDir -Recurse -ErrorAction SilentlyContinue | Out-Null
    Expand-Archive -Path $PackageFile -Destination $UnpackedDir

    $nuspecPath = Get-ChildItem -Path $UnpackedDir -Filter "*.nuspec" -File
    [xml]$nuspecXml = Get-Content -Path $nuspecPath
    $ns = $nuspecXml.DocumentElement.NamespaceURI
    $nsManager = New-Object System.Xml.XmlNamespaceManager($nuspecXml.NameTable)
    $nsManager.AddNamespace("ns", $ns)
    $idNode = $nuspecXml.SelectSingleNode("//ns:metadata/ns:id", $nsManager)
    $titleNode = $nuspecXml.SelectSingleNode("//ns:metadata/ns:title", $nsManager)
    if ($titleNode) {
        $titleNode.InnerText = $idNode.InnerText
    } else {
        $titleNode = $nuspecXml.CreateElement("title", $nuspecXml.package.NamespaceURI)
        $titleNode.InnerText = $idNode.InnerText
        $nuspecXml.package.metadata.InsertAfter($titleNode, $idNode)
    }
    $nuspecXml.Save($nuspecPath)

    Remove-Item $PackageFile -ErrorAction SilentlyContinue | Out-Null
    & nuget pack $UnpackedDir -OutputDirectory $OutputDirectory
    Remove-Item -Path $UnpackedDir -Recurse -ErrorAction SilentlyContinue | Out-Null
}

Add-Type -Assembly System.IO.Compression.FileSystem

function Test-ModulePackage
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [System.IO.FileInfo] $PackageFile
    )

    Process {
        $PackageFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PackageFile.FullName)

        if (-Not (Test-Path -Path $PackageFile)) {
            throw "`"$PackageFile`" does not exist"
        }

        if (-Not $PackageFile.FullName.EndsWith('.nupkg')) {
            throw "`"$PackageFile`" does not have .nupkg file extension"
        }

        $ZipArchive = $null
        try {
            $ZipArchive = [System.IO.Compression.ZipFile]::OpenRead($PackageFile)
            $NuspecEntry = $zipArchive.Entries | Where-Object { $_.Name -like "*.nuspec" -and $_.FullName -eq $_.Name } | Select-Object -First 1

            if (-Not $NuspecEntry) {
                throw "`"$PackageFile`" does not contain .nuspec file in the root directory"
            }
        } finally {
            if ($ZipArchive) {
                $ZipArchive.Dispose()
            }
        }
    }
}