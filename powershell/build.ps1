
$ModuleName = 'DevolutionsGateway'
Push-Location $PSScriptRoot

if (Test-Path Env:PSMODULE_OUTPUT_PATH) {
    $PSModuleOutputPath = $Env:PSMODULE_OUTPUT_PATH
} else {
    $PSModuleOutputPath = Join-Path $PSScriptRoot 'package'
}

Remove-Item -Path "$PSModuleOutputPath\$ModuleName" -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path "$PSModuleOutputPath\$ModuleName" -ItemType 'Directory' -Force | Out-Null

@('bin', 'Public', 'Private') | % {
    New-Item -Path "$PSModuleOutputPath\$ModuleName\$_" -ItemType 'Directory' -Force | Out-Null
}

$Env:NUGET_CERT_REVOCATION_MODE='offline' 

& dotnet nuget add source "https://api.nuget.org/v3/index.json" -n "nuget.org" | Out-Null

& dotnet restore "$PSScriptRoot\$ModuleName\src" 2>&1>$null

& dotnet publish "$PSScriptRoot\$ModuleName\src" -f netstandard2.0 -c Release -o "$PSScriptRoot\$ModuleName\bin"

Copy-Item "$PSScriptRoot\$ModuleName\bin" -Destination "$PSModuleOutputPath\$ModuleName" -Recurse -Force

Copy-Item "$PSScriptRoot\$ModuleName\Private" -Destination "$PSModuleOutputPath\$ModuleName" -Recurse -Force
Copy-Item "$PSScriptRoot\$ModuleName\Public" -Destination "$PSModuleOutputPath\$ModuleName" -Recurse -Force

Copy-Item "$PSScriptRoot\$ModuleName\$ModuleName.psd1" -Destination "$PSModuleOutputPath\$ModuleName" -Force
Copy-Item "$PSScriptRoot\$ModuleName\$ModuleName.psm1" -Destination "$PSModuleOutputPath\$ModuleName" -Force

Pop-Location
