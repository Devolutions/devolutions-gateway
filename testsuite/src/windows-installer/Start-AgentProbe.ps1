param(
    [Parameter(Mandatory)][string] $Executable,
    [Parameter(Mandatory)][string] $Directory
)
$ErrorActionPreference = 'Stop'
$env:DAGENT_CONFIG_PATH = $Directory
$process = Start-Process -FilePath $Executable -ArgumentList 'run' -PassThru `
    -RedirectStandardOutput "$Directory\stdout.log" -RedirectStandardError "$Directory\stderr.log"
$process.Id | Set-Content -LiteralPath "$Directory\process.id"
$process.WaitForExit()
exit $process.ExitCode
