#!/bin/env pwsh

param(
    [Parameter(Mandatory=$true)]
    [string] $RepoName,
    [Parameter(Mandatory=$true)]
    [int] $PullRequestId,
    [Parameter(Mandatory=$true)]
    [string] $Branch,
    [Parameter(Mandatory=$true)]
    [string] $TemplatePath
)

$ErrorActionPreference = "Stop"

$MyInvocation.MyCommand.Parameters `
    | Format-Table -AutoSize `
        @{ Label = "Argument"; Expression = { $_.Key }; },
        @{ Label = "Value"; Expression = { try { (Get-Variable -Name $_.Key).Value } catch { "" } }; }
Write-Host

function Invoke-Cmd
{
    param(
        [Parameter(Mandatory=$true)]
        [string] $Name,
        [Parameter(Mandatory=$true)]
        [string[]] $Args,
        [switch] $IgnoreFailure
    )    

    Write-Host ">> Invoke '${Name}' $($Args | Join-String -FormatString '''{0}''' -Separator ' ')"

    # Workaround: temporary change error action preferance because until v7.2 stderr redirection (>2) is redirected to the PowerShell error stream
    $ErrorActionPreference = "Continue"
    & $Name $Args 2>&1
    $ErrorActionPreference = "Stop"

    $failed = $LastExitCode -ne 0

    if ($failed -and (-not $IgnoreFailure))
    {
        throw "${Name} invocation failed"
    }
}

Write-Host ">> Read template file at $TemplatePath"

$body = Get-Content -Raw -Path "$TemplatePath"

Write-Host '>> Create new comment'

$args = @(
    'api',
    '-H', 'Accept: application/vnd.github.v3+json',
    '-f', "body=$body",
    '--method', 'POST',
    "/repos/$RepoName/issues/$PullRequestId/comments"
)

Invoke-Cmd 'gh' $args | Out-Null

