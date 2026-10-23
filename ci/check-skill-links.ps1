#!/bin/env pwsh
#Requires -Version 7.0

# Checks that `.claude/skills` holds exactly one symlink per skill in `.agents/skills`,
# each pointing at `../../.agents/skills/<name>`, because Claude Code discovers skills only there.
# Reads the git index rather than the working tree,
# so the result does not depend on whether the checkout created real symlinks.

param(
    # Root of the repository to check.
    [string] $Root = (Join-Path $PSScriptRoot '..')
)

$ErrorActionPreference = 'Stop'

$SkillsDir = '.agents/skills'
$LinksDir = '.claude/skills'
# Files in the links folder that are not skill links.
$Exempt = @("$LinksDir/README.md")

function Get-IndexEntries([string] $Path) {
    $Lines = & git -C $Root ls-files --stage -z -- $Path
    if ($LASTEXITCODE -ne 0) {
        throw "git ls-files failed for $Path"
    }
    ($Lines -join '') -split "`0" | Where-Object { $_ } | ForEach-Object {
        $Meta, $EntryPath = $_ -split "`t", 2
        $Mode, $Blob, $null = $Meta -split ' '
        [pscustomobject]@{ Mode = $Mode; Blob = $Blob; Path = $EntryPath }
    }
}

$Skills = @(Get-IndexEntries $SkillsDir | ForEach-Object {
    if ($_.Path -match "^$([regex]::Escape($SkillsDir))/([^/]+)/SKILL\.md$") {
        $Matches[1]
    }
})

$Links = @{}
$Violations = [System.Collections.Generic.List[string]]::new()

foreach ($Entry in Get-IndexEntries $LinksDir) {
    if ($Entry.Path -in $Exempt) {
        continue
    }

    if ($Entry.Path -notmatch "^$([regex]::Escape($LinksDir))/([^/]+)$" -or $Entry.Mode -ne '120000') {
        $Violations.Add("$($Entry.Path) is not a symlink directly under $LinksDir")
        continue
    }

    $Name = $Matches[1]
    $Target = & git -C $Root cat-file blob $Entry.Blob
    if ($LASTEXITCODE -ne 0) {
        throw "git cat-file failed for $($Entry.Path)"
    }

    $Expected = "../../$SkillsDir/$Name"
    if ($Target -cne $Expected) {
        $Violations.Add("$($Entry.Path) points to '$Target' instead of '$Expected'")
    } elseif ($Name -cnotin $Skills) {
        $Violations.Add("$($Entry.Path) points to $SkillsDir/$Name, which has no SKILL.md")
    }

    $Links[$Name] = $true
}

foreach ($Name in $Skills) {
    if (-not $Links.ContainsKey($Name)) {
        $Violations.Add("$SkillsDir/$Name has no link at $LinksDir/$Name")
    }
}

if ($Violations.Count -eq 0) {
    Write-Host "$LinksDir links all $($Skills.Count) skills in $SkillsDir"
    exit 0
}

foreach ($Violation in $Violations) {
    if ($Env:GITHUB_ACTIONS) {
        Write-Host "::error::$Violation"
    } else {
        Write-Host $Violation
    }
}
Write-Host "Fix: New-Item -ItemType SymbolicLink -Path $LinksDir/<name> -Target ../../$SkillsDir/<name>"
exit 1
