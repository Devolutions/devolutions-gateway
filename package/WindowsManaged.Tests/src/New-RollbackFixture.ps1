[CmdletBinding()]
param([Parameter(Mandatory)][string] $OutputDirectory)

$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$destination = [IO.Path]::GetFullPath($OutputDirectory)
if ($destination.StartsWith($repository + '\', [StringComparison]::OrdinalIgnoreCase) -or $destination -eq $repository) {
    throw 'Generate the fault-injection source outside the repository'
}
if (Test-Path -LiteralPath $destination) { throw 'The fixture output directory must not exist' }
$files = @(& git -C $repository ls-files -- package/WindowsManaged powershell/DevolutionsGateway/Public/DGateway.ps1 powershell/DevolutionsGateway/Private/Msi.ps1)
if ($LASTEXITCODE -ne 0 -or -not $files.Count) { throw 'Could not enumerate installer source' }
foreach ($file in $files) {
    $relative = $file.Replace('/', '\')
    $target = Join-Path $destination $relative
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $repository $relative) -Destination $target
}
Copy-Item -LiteralPath "$PSScriptRoot\RollbackFaultActions.cs" -Destination "$destination\package\WindowsManaged\Actions\RollbackFaultActions.cs"
$programPath = "$destination\package\WindowsManaged\Program.cs"
$program = [IO.File]::ReadAllText($programPath)
$replacements = @{
    'project.Actions = GatewayActions.Actions;' = 'project.Actions = RollbackFaultActions.Inject(GatewayActions.Actions);'
    'project.Properties = GatewayProperties.Properties.Select(x => x.ToWixSharpProperty()).ToArray();' =
        'project.Properties = GatewayProperties.Properties.Select(x => x.ToWixSharpProperty()).Concat(new[] { new Property("DGWLAB_ROLLBACK_FIXTURE", "1") }).ToArray();'
}
foreach ($anchor in $replacements.Keys) {
    if ([regex]::Matches($program, [regex]::Escape($anchor)).Count -ne 1) { throw "Installer source anchor changed: $anchor" }
    $program = $program.Replace($anchor, $replacements[$anchor])
}
[IO.File]::WriteAllText($programPath, $program, [Text.UTF8Encoding]::new($false))
[pscustomobject]@{
    Source = $destination
    TestOnly = $true
    FailureProperty = 'DGWLAB_FAILURE_PHASE'
    FailurePoints = @('after-remove', 'after-service', 'after-permissions')
}
