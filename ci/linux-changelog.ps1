#!/bin/env pwsh

# This script contains functions for generating Linux package changelogs from a CHANGELOG.md file. `New-Changelog` generates upstream and packaging changelogs for Debian and RPM-based systems.
#
# Upstream changelogs are derived from the root CHANGELOG.md.
# Change notes for all products are included in each upstream changelog.
#
# Packaging changelogs are derived from package/Linux/gateway/CHANGELOG.md for
# Gateway and package/AgentLinux/CHANGELOG.md for Agent.
#
# ## Debian
# The upstream changelog is included as changelog.gz.
# The packaging changelog is included as changelog.Debian.gz.
#
# ## RPM-based systems
#
# The upstream changelog is included as ChangeLog.
# The packaging changelog is embedded in the spec file.
#
# The date used in the changelog is the date of the release in CHANGELOG.md.


function Format-EntryLine {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        # The input string to format.
        $Line
    )

    <#
        .SYNOPSIS
        Formats a line of text from an entry CHANGELOG.md.

        .DESCRIPTION
        This function removes Markdown formatting such as links, links, boldface, and italics.

        .OUTPUTS
        [string] - The formatted line of text.

        .EXAMPLE
        PS> Format-EntryLine -Line "*Hello** _world_ ([link](url))"
        Hello world
    #>
    
    # remove markdown links enclosed in parantheses
    $Line = $Line -replace '\(\[.+?\]\(.*?\)\)', ''
    # remove links
    $Line = $Line -replace '\[.*?\]\(.*?\)', ''
    # remove bold
    $Line = $Line -replace '\*\*(.*?)\*\*', '$1'
    # remove italics
    $Line = $Line -replace '_(.*?)_', '$1'
    $Line = $Line -replace '\*(.*?)\*', '$1'
    # remove monospace
    $Line = $Line -replace '`(.*?)`', '$1'
    # remove blockquote marker
    $Line = $Line -replace '> ', ''

    # remove 
    return $Line
}


function Format-DebEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        # The package version.
        $Version,

        [Parameter(Mandatory = $true)]
        [string]
        # The entry release date in "yyyy-MM-dd" format.
        $Date,

        [Parameter(Mandatory = $true)]
        [string]
        # The packager's name.
        $Packager,

        [Parameter(Mandatory = $true)]
        [string]
        # The packager's email address.
        $Email,

        [Parameter(Mandatory = $true)]
        [string]
        # The package name.
        $PackageName,

        [Parameter(Mandatory = $true)]
        [string]
        # The target distribution.
        $Distro,

        [Parameter(Mandatory = $true)]
        [string]
        # The changelog body text, already formatted and indented.
        $Body
    )

    <#
        .SYNOPSIS
        Formats an entry from CHANGELOG.md into the Debian style.

        .EXAMPLE
        PS> Format-DebEntry -Version "0.1.0" -Date "2025-01-01" -Packager "Maurice" -Email "maurice@foo.example" -PackageName "mypackage" -Distro "focal" -Body "- Bug fixes"
        mypackage (0.1.0-1) focal; urgency=medium

          * Bug fixes
        
         -- Maurice <maurice@foo.example>  Wed, 01 Jan 2025 00:00:00 +0000
        #>

    # Remove the trailing newline.
    $bdy = $Body.SubString(0, $Body.Length - 1)

    $dt = [datetime]::ParseExact($Date, "yyyy-MM-dd", $null)
    $dt = $dt.ToString("ddd, dd MMM yyyy 00:00:00 +0000")

    return @"
$PackageName ($Version-1) $Distro; urgency=medium

$bdy

 -- $Packager <$Email>  $dt
"@
}


function Format-RpmUpstreamEntry {
    param(
        [Parameter(Mandatory = $true)]
        # The package version.
        $Version,

        [Parameter(Mandatory = $true)]
        [string]
        # The entry release date in "yyyy-MM-dd" format.
        $Date,

        [Parameter(Mandatory = $true)]
        [string]
        # The packager's name.
        $Packager,

        [Parameter(Mandatory = $true)]
        [string]
        # The packager's email address.
        $Email,

        [Parameter(Mandatory = $true)]
        [string]
        # The changelog body text, already formatted and indented.
        $Body
    )

    <#
        .SYNOPSIS
        Formats an entry from CHANGELOG.md into a custom style for RPM.

        .OUTPUTS
        [string] - A formatted Debian changelog entry.

        .EXAMPLE
        PS> Format-RpmUpstreamEntry -Version "0.1.0" -Date "2025-01-01" -Packager "Maurice" -Email "maurice@foo.example" -Body "- Bug fixes"
        0.1.0 (2025-01-01) Maurice <maurice@foo.example>

        * Bug fixes
    #>

    # Remove the trailing newline.
    $bdy = $Body.SubString(0, $Body.Length - 1)

    return @"
$Version ($Date) $Packager <$Email>

$bdy
"@
}


function Format-RpmPackagingEntry {
    param(
        [Parameter(Mandatory = $true)]
        # The package version.
        $Version,

        [Parameter(Mandatory = $true)]
        [string]
        # The entry release date in "yyyy-MM-dd" format.
        $Date,

        [Parameter(Mandatory = $true)]
        [string]
        # The packager's name.
        $Packager,

        [Parameter(Mandatory = $true)]
        [string]
        # The packager's email address.
        $Email,

        [Parameter(Mandatory = $true)]
        [string]
        # The changelog body text, already formatted and indented.
        $Body
    )

    <#
        .SYNOPSIS
        Formats an entry from CHANGELOG.md into the packaging changelog style for RPM.

        .OUTPUTS
        [string] - A formatted Debian changelog entry.

        .EXAMPLE
        PS> Format-RpmPackagingEntry -Version "0.1.0" -Date "2025-01-01" -Packager "Maurice" -Email "maurice@foo.example" -Body "- Removed dependency"
        * Wed Jan 01 00:00:00 2025 Maurice <maurice@foo.example> - 0.1.0-1
        - Removed dependency
    #>

    # Remove the trailing newline.
    $bdy = $Body.SubString(0, $Body.Length - 1)

    $dt = [datetime]::ParseExact($Date, "yyyy-MM-dd", $null)
    $dt = $dt.ToString("ddd MMM dd 00:00:00 yyyy")

    return @"
* $dt $Packager <$Email> - $Version-1
$bdy
"@
}


function New-Changelog {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Deb", "RpmPackaging", "RpmUpstream")]
        [string]
        # The package format.
        $Format,
        
        [Parameter(Mandatory = $true)]
        [string]
        # The path to CHANGELOG.md.
        $InputFile,

        [Parameter(Mandatory = $true)]
        [string]
        # The packager's name.
        $Packager,
        
        [Parameter(Mandatory = $true)]
        [string]
        # The packager's email address.
        $Email,

        [string]
        # The package name. Required for Debian.
        $PackageName,

        [string]
        # The target distribution. Required for Debian.
        $Distro
    )

    <#
        .SYNOPSIS
        Generates an upstream changelog from CHANGELOG.md.

        .DESCRIPTION
        This function reads CHANGELOG.md and generates an upstream changelog for the desired package format.
    #>

    if ($Format -eq "Deb") {
        if (-not $PackageName) {
            throw '`PackageName` is required for deb format'
        }
        if (-not $Distro) {
            throw '`Distro` is required for deb format'
        }
    }

    if (-not (Test-Path $InputFile)) {
        throw "Input file not found: $InputFile"
    }

    $versionRe = '## (\d+\.\d+\.\d+) \((\d{4}-\d{2}-\d{2})\)'

    # whether or not the line is part of a section (like `### Features`)
    $inSection = $false
    $currVersion = $null
    $currDate = $null
    # body of the current entry
    $body = $null

    foreach ($line in Get-Content -Path $InputFile) {
        if ($line -match $versionRe) {
            # Reading a new entry; line like `## 2024.3.5 (2024-11-12)`
            $version = [Version]$matches[1]
            $date = $matches[2]

            # Append the current entry.
            if ($currVersion) {
                if ($Format -eq 'Deb') {
                    $output += Format-DebEntry -Version $currVersion -Date $currDate -Packager $Packager -Email $Email -PackageName $PackageName -Distro $Distro -Body $body
                }
                elseif ($Format -eq 'RpmUpstream') {
                    $output += Format-RpmUpstreamEntry -Version $currVersion -Date $currDate -Packager $Packager -Email $Email -Body $body
                }
                elseif ($Format -eq 'RpmPackaging') {
                    $output += Format-RpmPackagingEntry -Version $currVersion -Date $currDate -Packager $Packager -Email $Email -Body $body
                }

                # Add a blank line between entries.
                $output += "`n`n"
            }
            # Start processing a new entry.
            $currVersion = $version
            $currDate = $date
            $inSection = $false
            $body = ''

        }
        elseif ($line.StartsWith('### ')) {
            if ($Format -eq 'Deb') {
                # Reading a section header; line like `### Features`
                $sectionHeader = $line -replace '^### ', '  * '

                $body += "$sectionHeader`n"
                $inSection = $true
            }
            else {
                # Omit section headers.
                continue
            }
        }
        elseif ($currVersion) {
            # Reading a section list item
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $line = "$(Format-EntryLine -Line $line)";

            if ($Format -eq 'Deb') {
                if ($inSection) {
                    # A nested list-item. Add indent.
                    $body += "    $line"
                }
                else {
                    # A first-level list item in Markdown
                    $line = $line -replace '^- ', '  * '
                    $body += "$line"
                }
            }
            elseif ($Format -eq 'RpmUpstream') {
                $line = $line -replace '^- ', '* '
                $body += "$line"
            }
            elseif ($Format -eq 'RpmPackaging') {
                # strip leading whitespace
                $line = $line -replace '^\s+', ''
                $body += "$line"
            }

            $body += "`n"
        }
    }

    # Append the final entry.
    if ($Format -eq 'Deb') {
        $output += Format-DebEntry -Version $currVersion -Date $currDate -Packager $Packager -Email $Email -PackageName $PackageName -Distro $Distro -Body $body
    }
    elseif ($Format -eq 'RpmUpstream') {
        $output += Format-RpmUpstreamEntry -Version $currVersion -Date $currDate -Packager $Packager -Email $Email -Body $body
    }
    elseif ($Format -eq 'RpmPackaging') {
        $output += Format-RpmPackagingEntry -Version $currVersion -Date $currDate -Packager $Packager -Email $Email -Body $body
    }
    
    if ([string]::IsNullOrWhiteSpace($output)) {
        throw 'No output'
    }
    
    return $output
}
