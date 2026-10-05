#Requires -Version 5.1
<#
.SYNOPSIS
    Regenerates the installer localization files from their JSON sources.

.DESCRIPTION
    Runs the T4 template `Resources/Strings.g.tt` of each installer project.
    The template reads `Resources/Strings_<culture>.json` and writes `<Product>_<culture>.wxl` and `Strings.g.cs`.
    Never edit the generated files by hand: change the JSON and run this script.

.PARAMETER Product
    The installer to regenerate: `agent`, `gateway`, or `all` (default).

.PARAMETER TextTransformPath
    Path to `TextTransform.exe`.
    Defaults to the copy shipped with the latest Visual Studio found by `vswhere`.
#>
param(
    [ValidateSet('agent', 'gateway', 'all')]
    [string] $Product = 'all',
    [string] $TextTransformPath
)

$ErrorActionPreference = 'Stop'

if (-not $TextTransformPath) {
    $vswhere = Join-Path ${Env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'

    if (-not (Test-Path $vswhere)) {
        throw 'vswhere.exe not found. Install Visual Studio or pass -TextTransformPath.'
    }

    $TextTransformPath = & $vswhere -latest -products * -find 'Common7\IDE\TextTransform.exe' | Select-Object -First 1

    if (-not $TextTransformPath) {
        throw 'TextTransform.exe not found. Install the Visual Studio text templating component or pass -TextTransformPath.'
    }
}

$projects = switch ($Product) {
    'agent' { @('AgentWindowsManaged') }
    'gateway' { @('WindowsManaged') }
    default { @('AgentWindowsManaged', 'WindowsManaged') }
}

foreach ($project in $projects) {
    $resources = Join-Path $PSScriptRoot "$project\Resources"
    $template = Join-Path $resources 'Strings.g.tt'
    $newtonsoft = Join-Path $resources 'Newtonsoft.Json.dll'

    # TextTransform.exe does not expand the `$(SolutionDir)` macro that Visual Studio resolves.
    # Use a temporary copy of the template (it must live next to the original: outputs are written beside the template).
    $temporaryTemplate = Join-Path $resources "_Strings.$([guid]::NewGuid().ToString('N')).tt"
    $text = [IO.File]::ReadAllText($template).Replace('$(SolutionDir)Resources\Newtonsoft.Json.dll', $newtonsoft)
    [IO.File]::WriteAllText($temporaryTemplate, $text)

    # T4 drops the byte order mark that some existing files carry; keep each file as it was.
    $hadBom = @{}
    Get-ChildItem $resources -Include '*.wxl', 'Strings.g.cs' -File -Recurse | ForEach-Object {
        $bytes = [IO.File]::ReadAllBytes($_.FullName)
        $hadBom[$_.FullName] = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    }

    try {
        & $TextTransformPath $temporaryTemplate -out (Join-Path $resources 'Strings.g.cs')

        if ($LASTEXITCODE -ne 0) {
            throw "TextTransform failed for $project"
        }
    }
    finally {
        Remove-Item $temporaryTemplate -ErrorAction SilentlyContinue
    }

    # The repository stores these files with LF line endings, while T4 emits mixed endings.
    Get-ChildItem $resources -Include '*.wxl', 'Strings.g.cs' -File -Recurse | ForEach-Object {
        $content = [IO.File]::ReadAllText($_.FullName).Replace("`r`n", "`n")
        [IO.File]::WriteAllText($_.FullName, $content, (New-Object Text.UTF8Encoding($hadBom[$_.FullName] -eq $true)))
    }

    Write-Output "Regenerated localization files for $project"
}
