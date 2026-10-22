#!/bin/env pwsh
#Requires -Version 7.0

# Checks the oracle markers defined in `.agents/skills/test-oracle-reviewer/SKILL.md`
# in the tracked Rust, C#, and PowerShell files of the working tree, as `ci/check-oracle-markers.intent.md` requires.
# With -Base, it also requires a marker on every test added since that revision.
# With -DriftReport, it instead reports, for each marker pinned to a commit of a repository,
# whether the cited section still reads the same on that repository's default branch.

param(
    # Revision to compare against, such as `origin/master`; tests added since then must carry a marker.
    [string] $Base,

    # Root of the repository to check.
    [string] $Root = (Join-Path $PSScriptRoot '..'),

    # Report drift of pinned sections instead of checking.
    [switch] $DriftReport,

    # Calls the GitHub REST API: takes an endpoint and an Accept header, returns its status and body.
    # UNTESTED: the tests replace this block, so nothing checks that it sends the token and returns
    # an error status instead of throwing; after changing it, run a pinned marker against a public repository
    # with a valid token, an invalid one, and none.
    [scriptblock] $GitHubApi = {
        param([string] $Endpoint, [string] $Accept)
        $Headers = @{ Accept = $Accept; 'X-GitHub-Api-Version' = '2022-11-28' }
        $Token = if ($Env:GH_TOKEN) { $Env:GH_TOKEN } else { $Env:GITHUB_TOKEN }
        if ($Token) {
            $Headers.Authorization = "Bearer $Token"
        }
        $Response = Invoke-WebRequest -Uri "https://api.github.com/$Endpoint" -Headers $Headers -SkipHttpErrorCheck
        [pscustomobject]@{
            Status = [int] $Response.StatusCode
            Body = [System.Text.Encoding]::UTF8.GetString($Response.RawContentStream.ToArray())
        }
    }
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Root = (Resolve-Path -LiteralPath $Root).Path
# Git writes UTF-8, and decoding it with another console code page breaks `§`.
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
# A marker is a line comment of its language; a `//` or `#` inside a word, as in a URL, does not open one.
$MarkerPatterns = @{
    '.rs' = '(?:^|\s)//\s*oracle:(?<rest>.*)$'
    '.cs' = '(?:^|\s)//\s*oracle:(?<rest>.*)$'
    '.ps1' = '(?:^|\s)#\s*oracle:(?<rest>.*)$'
}
$Kinds = @('spec', 'contract', 'intent', 'regression', 'reference', 'property', 'mutant', 'scaffold')
$Laws = @('round-trip', 'idempotent', 'involution', 'commutative', 'associative', 'monotonic')
$AnchorPattern = '<a\s+id="(?<id>[^"]+)"\s*>\s*</a>'
# `<owner>/<repo>@<sha>:<path>`; a reference with `<owner>/<repo>:` but no valid pin is rejected.
$CrossRepositoryPattern = '^(?<owner>[\w.-]+)/(?<repo>[\w.-]+)(?:@(?<pin>[^:\s]*))?:(?<path>\S+)$'
$TestAttributePatterns = @{
    '.rs' = '^\s*#\[(?:test|tokio::test|rstest)\b'
    '.cs' = '^\s*\[(?:Fact|Theory)\b'
}
# A Rust or C# test is named by the function its attributes decorate, and a Pester test by the name its `It` gives;
# the git forms match the same declarations.
$DeclarationPatterns = @{
    '.rs' = '\bfn\s+(?<name>\w+)'
    '.cs' = '\b(?:void|Task|ValueTask)\s+(?<name>\w+)\s*\('
    '.ps1' = '^\s*It\s+(?:-Name\s+)?(?:''(?<name>(?:[^'']|'''')*)''|"(?<name>(?:[^"]|"")*)")'
}
$GitDeclarationPatterns = @{
    '.rs' = 'fn[[:space:]]+[A-Za-z0-9_]+'
    '.cs' = '(void|Task|ValueTask)[[:space:]]+[A-Za-z0-9_]+[[:space:]]*\('
    '.ps1' = '^[[:space:]]*It[[:space:]]+(-Name[[:space:]]+)?(''([^'']|'''')*''|"([^"]|"")*")'
}
# Lines that can sit between a marker and the declaration it heads.
$PrefixPatterns = @{
    '.rs' = '^\s*(//|#\[)'
    '.cs' = '^\s*(//|\[)'
    '.ps1' = '^\s*#'
}

$Violations = [System.Collections.Generic.List[object]]::new()
$PinnedMarkers = [System.Collections.Generic.List[object]]::new()
$SkippedReferences = [System.Collections.Generic.SortedSet[string]]::new()
# Paths are case-sensitive, so these caches compare keys ordinally, unlike `@{}`.
$OutlineCache = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
$RemoteFileCache = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
$ReadableRepositories = @{}
$DefaultHeads = @{}

function Add-Violation([string] $File, [int] $Line, [string] $Message) {
    $Violations.Add([pscustomobject]@{ File = $File; Line = $Line; Message = $Message })
}

function Invoke-Git {
    $Output = & git -C $Root -c core.quotePath=false @args
    if ($LASTEXITCODE -ne 0) {
        throw "git $args failed with exit code $LASTEXITCODE"
    }
    $Output
}

# Only tracked files count, because an ignored or uncommitted file exists locally but not in CI.
$TrackedFiles = [System.Collections.Generic.HashSet[string]]::new([string[]] @((Invoke-Git ls-files -z) -split "`0" -ne ''))

function Test-RepositoryFile([string] $Path) {
    $TrackedFiles.Contains($Path) -and (Test-Path -LiteralPath (Join-Path $Root $Path) -PathType Leaf)
}

# Lists the headings of a Markdown file, skipping fenced code, and maps each anchor to the heading it names:
# the heading on its line, or the next one when only blank lines and other anchors separate them.
# An anchor followed by anything else names no section.
function Get-Outline([string[]] $Lines) {
    $Headings = [System.Collections.Generic.List[object]]::new()
    $Anchors = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
    $Pending = [System.Collections.Generic.List[string]]::new()
    $Seen = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
    $Duplicates = [System.Collections.Generic.List[object]]::new()
    $Fence = $null
    for ($Index = 0; $Index -lt $Lines.Count; $Index++) {
        $Line = $Lines[$Index]
        # A fence closes only on its own character, repeated at least as often, so a shorter or other fence inside stays code.
        if ($Fence) {
            if ($Line -match '^ {0,3}(?<fence>`{3,}|~{3,})\s*$' -and $Matches.fence[0] -eq $Fence[0] -and $Matches.fence.Length -ge $Fence.Length) {
                $Fence = $null
            }
            continue
        }
        if ($Line -match '^ {0,3}(?<fence>`{3,}|~{3,})') {
            $Fence = $Matches.fence
            $Pending.Clear()
            continue
        }
        foreach ($Anchor in [regex]::Matches($Line, $AnchorPattern)) {
            $Id = $Anchor.Groups['id'].Value
            if ($Seen.ContainsKey($Id)) {
                $Duplicates.Add([pscustomobject]@{ Id = $Id; Index = $Index; First = $Seen[$Id] })
            } else {
                $Seen[$Id] = $Index
            }
            $Pending.Add($Id)
        }
        if ($Line -match '^(?<level>#{1,6})\s+(?<text>.*?)(?:\s+#+)?\s*$') {
            $Text = ($Matches.text -replace $AnchorPattern, '').Trim() -replace '\s+', ' '
            $Headings.Add([pscustomobject]@{ Index = $Index; Level = $Matches.level.Length; Text = $Text })
            foreach ($Id in $Pending) {
                $Anchors.TryAdd($Id, $Index) | Out-Null
            }
            $Pending.Clear()
        } elseif (($Line -replace $AnchorPattern, '').Trim()) {
            $Pending.Clear()
        }
    }
    [pscustomobject]@{ Lines = $Lines; Headings = $Headings; Anchors = $Anchors; Duplicates = $Duplicates }
}

# Resolves `§<section>`: an anchor whose id equals it, else a heading with the same text in any case,
# else a heading that starts with it as a number. Returns the section's heading and body, or $null.
function Find-Section($Outline, [string] $Section) {
    $Section = $Section.Trim() -replace '\s+', ' '
    $Heading = $null
    if ($Outline.Anchors.ContainsKey($Section)) {
        $HeadingIndex = $Outline.Anchors[$Section]
        $Heading = $Outline.Headings | Where-Object { $_.Index -eq $HeadingIndex } | Select-Object -First 1
    }
    if (-not $Heading) {
        $Heading = $Outline.Headings | Where-Object { $_.Text -ieq $Section } | Select-Object -First 1
    }
    if (-not $Heading -and $Section -match '^\d+(\.\d+)*\.?$') {
        $NumberPattern = "^$([regex]::Escape($Section.TrimEnd('.')))\.?(\s|$)"
        $Heading = $Outline.Headings | Where-Object { $_.Text -match $NumberPattern } | Select-Object -First 1
    }
    if (-not $Heading) {
        return $null
    }
    $Next = $Outline.Headings | Where-Object { $_.Index -gt $Heading.Index -and $_.Level -le $Heading.Level } | Select-Object -First 1
    $End = if ($Next) { $Next.Index } else { $Outline.Lines.Count }
    # The anchors and blank lines just above the next heading belong to it.
    while ($End - 1 -gt $Heading.Index -and -not ($Outline.Lines[$End - 1] -replace $AnchorPattern, '').Trim()) {
        $End--
    }
    $Body = if ($Heading.Index + 1 -lt $End) { $Outline.Lines[($Heading.Index + 1)..($End - 1)] -join "`n" } else { '' }
    [pscustomobject]@{ Heading = $Heading.Text; Body = $Body.Trim() }
}

function Get-LocalOutline([string] $Path) {
    if (-not $OutlineCache.ContainsKey($Path)) {
        $OutlineCache[$Path] = Get-Outline @(Get-Content -LiteralPath (Join-Path $Root $Path))
    }
    $OutlineCache[$Path]
}

# Any status outside $Expect, such as 401 for a bad token or a rate limit, stops the check,
# because treating it as missing access would let every pin pass with only a syntax check.
function Invoke-GitHub([string] $Endpoint, [int[]] $Expect, [switch] $Raw) {
    $Accept = if ($Raw) { 'application/vnd.github.raw' } else { 'application/vnd.github+json' }
    $Response = & $GitHubApi $Endpoint $Accept
    $RateLimited = $Response.Status -in 403, 429 -and $Response.Body -match 'rate limit'
    if ($RateLimited -or $Response.Status -notin $Expect) {
        $Message = "$($Response.Body)"
        throw "GitHub API $Endpoint returned $($Response.Status): $($Message.Substring(0, [Math]::Min(200, $Message.Length)))"
    }
    $Response
}

# GitHub answers 404 both for a missing repository and for a private one the token cannot read,
# and 403 for an organization that has not authorized the token,
# so readability is asked of the repository before a missing commit or file counts as an error.
function Test-RepositoryReadable([string] $Repository) {
    if (-not $ReadableRepositories.ContainsKey($Repository)) {
        $ReadableRepositories[$Repository] = (Invoke-GitHub "repos/$Repository" -Expect 200, 403, 404).Status -eq 200
    }
    $ReadableRepositories[$Repository]
}

# Returns the full SHA of the commit a ref names, or $null.
function Resolve-Commit([string] $Repository, [string] $Ref) {
    $Response = Invoke-GitHub "repos/$Repository/commits/$Ref" -Expect 200, 404, 422
    if ($Response.Status -eq 200) { ($Response.Body | ConvertFrom-Json).sha }
}

# Fetches a file at a pinned commit; the result is cached, since a commit never changes.
# State is ok, skipped (the token cannot read the repository), no-commit, or no-file.
function Get-RemoteFile([string] $Repository, [string] $Pin, [string] $Path) {
    $Key = "$Repository@${Pin}:$Path"
    if (-not $RemoteFileCache.ContainsKey($Key)) {
        $RemoteFileCache[$Key] = if (-not (Test-RepositoryReadable $Repository)) {
            [pscustomobject]@{ State = 'skipped' }
        } else {
            $Sha = Resolve-Commit $Repository $Pin
            # A branch or tag that merely looks like hex resolves to a commit the pin does not start.
            if (-not $Sha -or -not $Sha.StartsWith($Pin)) {
                [pscustomobject]@{ State = 'no-commit' }
            } else {
                $EscapedPath = ($Path -split '/' | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/'
                $Response = Invoke-GitHub "repos/$Repository/contents/${EscapedPath}?ref=$Sha" -Expect 200, 404 -Raw
                if ($Response.Status -eq 200) {
                    [pscustomobject]@{ State = 'ok'; Sha = $Sha; Outline = Get-Outline @($Response.Body -split "`r?`n") }
                } else {
                    [pscustomobject]@{ State = 'no-file'; Sha = $Sha }
                }
            }
        }
    }
    $RemoteFileCache[$Key]
}

function Test-DocumentName([string] $File, [int] $Line, [string] $Kind, [string] $Document) {
    $Name = Split-Path -Leaf $Document
    if ($Kind -ceq 'contract' -and $Name -cnotlike 'CONTRACT*.md') {
        Add-Violation $File $Line "contract '$Document' is not a CONTRACT*.md file"
        return $false
    }
    if ($Kind -ceq 'intent' -and $Name -cnotlike 'INTENT*.md' -and $Name -cnotlike '*.intent*.md') {
        Add-Violation $File $Line "intent '$Document' is not an INTENT*.md or *.intent*.md file"
        return $false
    }
    $true
}

function Test-CrossRepositoryReference([string] $File, [int] $Line, [string] $Kind, [string] $Reference, [hashtable] $Parts, [string] $Section) {
    $Repository = "$($Parts.owner)/$($Parts.repo)"
    $Pin = $Parts.pin
    $Path = $Parts.path
    if ($Pin -cnotmatch '^[0-9a-f]{12,40}$') {
        Add-Violation $File $Line "'$Kind' marker must pin a commit SHA of at least 12 hex digits, as '<owner>/<repo>@<sha>:<path>', because a branch or tag moves"
        return
    }
    if (-not (Test-DocumentName $File $Line $Kind $Path)) {
        return
    }

    $PinnedMarkers.Add([pscustomobject]@{
        File = $File; Line = $Line; Marker = "$Kind $Reference"
        Repository = $Repository; Pin = $Pin; Path = $Path; Section = $Section
    })
    $Remote = Get-RemoteFile $Repository $Pin $Path
    switch ($Remote.State) {
        'skipped' { $SkippedReferences.Add("$Repository@${Pin}:$Path") | Out-Null }
        'no-commit' { Add-Violation $File $Line "'$Pin' is not a commit of $Repository" }
        'no-file' { Add-Violation $File $Line "'$Path' does not exist in $Repository at $Pin" }
        'ok' {
            $Repeated = @($Remote.Outline.Duplicates | ForEach-Object { $_.Id } | Sort-Object -Unique)
            if ($Repeated.Count -gt 0) {
                Add-Violation $File $Line "'$Path' in $Repository at $Pin has more than one anchor '$($Repeated -join "', '")'"
            } elseif (-not (Find-Section $Remote.Outline $Section)) {
                Add-Violation $File $Line "'$Path' in $Repository at $Pin has no section '$Section'"
            }
        }
    }
}

function Test-SectionReference([string] $File, [int] $Line, [string] $Kind, [string] $Reference) {
    if ($Reference -notmatch '^(?<document>\S.*?)\s+§(?<section>\S.*)$') {
        Add-Violation $File $Line "'$Kind' marker needs '<document> §<section>'"
        return
    }
    $Document = $Matches.document
    $Section = $Matches.section

    if ($Document -match $CrossRepositoryPattern) {
        Test-CrossRepositoryReference $File $Line $Kind $Reference $Matches.Clone() $Section
        return
    }
    # A spec outside `docs/` is named, not given as a path, and cannot be resolved,
    # so a URL, a ref, or another path in its place would escape every check.
    if ($Kind -ceq 'spec' -and -not $Document.StartsWith('docs/')) {
        if ($Document -match '://|@' -or $Document -match '/[^/\s]*\.[A-Za-z0-9]+$' -or $Document -match '^[^/\s]+\.md$') {
            Add-Violation $File $Line "spec '$Document' looks like a URL or a path; name the spec, give a path under docs/, or pin it as '<owner>/<repo>@<sha>:<path>'"
        }
        return
    }
    if (-not (Test-DocumentName $File $Line $Kind $Document)) {
        return
    }
    if (-not (Test-RepositoryFile $Document)) {
        Add-Violation $File $Line "$Kind file '$Document' is not tracked; give its path from the repository root"
    } elseif (-not (Find-Section (Get-LocalOutline $Document) $Section)) {
        Add-Violation $File $Line "$Kind file '$Document' has no section '$Section'"
    }
}

function Test-Marker([string] $File, [int] $Line, [string] $Text) {
    $Kind, $Reference = $Text.Trim() -split '\s+', 2
    $Reference = "$Reference".Trim()

    if (-not $Kind) {
        Add-Violation $File $Line "marker has no kind"
        return
    }
    if ($Kind -cnotin $Kinds) {
        Add-Violation $File $Line "unknown oracle kind '$Kind'; expected one of: $($Kinds -join ', ')"
        return
    }
    if ($Kind -ceq 'scaffold') {
        Add-Violation $File $Line "'scaffold' marker must not merge; give what it marks a strong source, keep it as 'mutant', or delete it"
        return
    }
    if (-not $Reference) {
        Add-Violation $File $Line "'$Kind' marker has no reference"
        return
    }

    switch ($Kind) {
        { $_ -in 'spec', 'contract', 'intent' } {
            Test-SectionReference $File $Line $Kind $Reference
        }
        'property' {
            if ($Reference -cnotin $Laws) {
                Add-Violation $File $Line "'property $Reference' is not a well-known law; use one of: $($Laws -join ', '), or the kind of the document that states it"
            }
        }
        'regression' {
            $Token = ($Reference -split '\s+')[0]
            $IsIssue = $Token -cmatch '^(?:[A-Z][A-Z0-9]+-\d+|(?:[\w.-]+/[\w.-]+)?#\d+)$'
            $IsCrashFile = $Token.StartsWith('fuzz/') -and (Test-RepositoryFile $Token)
            if (-not $IsIssue -and -not $IsCrashFile) {
                Add-Violation $File $Line "regression reference '$Token' is not a Jira key, an issue such as '#123', or a tracked file under 'fuzz/'; fuzz/.gitignore ignores crash files, so commit one with 'git add -f'"
            }
        }
    }
}

# Lists the markers of a file with their lines, numbered from 1. Only a line comment holds one, matched case-sensitively,
# so marker-shaped text inside a string is data and `// ORACLE:` is no marker; a Rust doctest's `/// # // oracle:` is a comment.
function Get-FileMarkers([string] $File, [string[]] $Lines) {
    $Extension = [System.IO.Path]::GetExtension($File)
    $Pattern = $MarkerPatterns[$Extension]
    $Text = $Lines -join "`n"
    if ($Extension -eq '.ps1') {
        $Tokens = $null
        $Errors = $null
        [void] [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref] $Tokens, [ref] $Errors)
        foreach ($Token in $Tokens) {
            if ($Token.Kind -eq 'Comment' -and -not $Token.Text.StartsWith('<#') -and $Token.Text -cmatch $Pattern) {
                [pscustomobject]@{ Line = $Token.Extent.StartLineNumber; Rest = $Matches.rest }
            }
        }
        return
    }
    $Breaks = [System.Collections.Generic.List[int]]::new()
    foreach ($Break in [regex]::Matches($Text, "`n")) {
        $Breaks.Add($Break.Index)
    }
    foreach ($Literal in [regex]::Matches($Text, $LiteralPatterns[$Extension])) {
        if ($Literal.Value.StartsWith('//') -and $Literal.Value -cmatch $Pattern) {
            $Before = $Breaks.BinarySearch($Literal.Index)
            $Line = if ($Before -lt 0) { -$Before } else { $Before + 1 }
            [pscustomobject]@{ Line = $Line; Rest = $Matches.rest }
        }
    }
}

function Test-Markers {
    $Files = @(& git -C $Root -c core.quotePath=false grep -l -I -F 'oracle:' -- '*.rs' '*.cs' '*.ps1')
    if ($LASTEXITCODE -gt 1) {
        throw "git grep failed with exit code $LASTEXITCODE"
    }
    foreach ($File in $Files) {
        foreach ($Marker in @(Get-FileMarkers $File @(Get-Content -LiteralPath (Join-Path $Root $File)))) {
            Test-Marker $File $Marker.Line $Marker.Rest
        }
    }
}

# A file a marker may cite has each anchor id once, because a citation of a repeated id could resolve to either.
function Test-Anchors {
    $Citable = $TrackedFiles | Where-Object {
        $Name = Split-Path -Leaf $_
        $_.EndsWith('.md') -and ($_.StartsWith('docs/') -or $Name -clike 'CONTRACT*.md' -or $Name -clike 'INTENT*.md' -or $Name -clike '*.intent*.md')
    }
    foreach ($Path in $Citable | Sort-Object) {
        foreach ($Duplicate in (Get-LocalOutline $Path).Duplicates) {
            Add-Violation $Path ($Duplicate.Index + 1) "anchor '$($Duplicate.Id)' repeats the one on line $($Duplicate.First + 1)"
        }
    }
}

# Counts the declarations of each name, per file extension, at a revision or in the working tree.
# PowerShell command names ignore case, so `it` declares a Pester test as `It` does.
function Get-DeclarationCounts([string] $Revision) {
    $Counts = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
    foreach ($Extension in $GitDeclarationPatterns.Keys) {
        $Arguments = @('grep', '-h', '-o', '-I', '-E')
        if ($Extension -eq '.ps1') {
            $Arguments += '-i'
        }
        $Arguments += @('-e', $GitDeclarationPatterns[$Extension])
        if ($Revision) {
            $Arguments += $Revision
        }
        $Output = & git -C $Root -c core.quotePath=false @Arguments -- "*$Extension"
        if ($LASTEXITCODE -gt 1) {
            throw "git grep failed with exit code $LASTEXITCODE"
        }
        foreach ($Declaration in $Output) {
            if ($Declaration -match $DeclarationPatterns[$Extension]) {
                $Key = "${Extension}:$($Matches.name)"
                $Counts[$Key] = (Get-Count $Counts $Key) + 1
            }
        }
    }
    , $Counts
}

function Get-Count($Counts, [string] $Key) {
    if ($Counts.ContainsKey($Key)) { $Counts[$Key] } else { 0 }
}

# Comments and string and character literals, which may span lines.
# Rust block comments nest and C# ones do not; a C# interpolation hole is code that may hold its own literals and braces.
$InterpolationHole = '\{(?>[^{}"''\\]+|"(?:\\.|[^"\\])*"|''(?:\\.|[^''\\])''|\{(?<brace>)|\}(?<-brace>))*(?(brace)(?!))\}'
$LiteralPatterns = @{
    '.rs' = @(
        '/\*(?>/\*(?<depth>)|\*/(?<-depth>)|(?!/\*|\*/)[\s\S])*\*/(?(depth)(?!))'
        '//[^\n]*'
        '(?<![\w])b?r(?<hashes>#*)"[\s\S]*?"\k<hashes>'
        '"(?:\\[\s\S]|[^"\\])*"'
        "'(?:\\u\{[0-9a-fA-F]+\}|\\x[0-9a-fA-F]{2}|\\.|[^'\\\n])'"
    ) -join '|'
    '.cs' = @(
        '/\*[\s\S]*?\*/'
        '//[^\n]*'
        '(?<quotes>"{3,})[\s\S]*?\k<quotes>'
        "(?:\`$@|@\`$)`"(?:\{\{|\}\}|$InterpolationHole|`"`"|[^`"{}])*`""
        "\`$`"(?:\{\{|\}\}|$InterpolationHole|\\.|[^`"\\{}])*`""
        '@"(?:[^"]|"")*"'
        '"(?:\\.|[^"\\\n])*"'
        "'(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{1,4}|\\.|[^'\\\n])'"
    ) -join '|'
}

# Blanks comments and literals, keeping line breaks, so the brackets, braces, and semicolons left are code.
function Get-CodeLines([string[]] $Lines, [string] $Extension) {
    $Text = $Lines -join "`n"
    $Blanked = [regex]::Replace($Text, $LiteralPatterns[$Extension], [System.Text.RegularExpressions.MatchEvaluator] { param($Match) $Match.Value -replace '[^\n]', ' ' })
    , ($Blanked -split "`n")
}

# Returns the line on which the item declared at $From ends: where its braces balance again,
# or its first `;` outside parentheses and brackets when it has no body, such as an expression-bodied member.
function Get-ItemEnd([string[]] $Code, [int] $From) {
    $Depth = 0
    $Nesting = 0
    $Opened = $false
    for ($Index = $From; $Index -lt $Code.Count; $Index++) {
        foreach ($Token in [regex]::Matches($Code[$Index], '[{}()\[\];]')) {
            switch ($Token.Value) {
                '{' { $Depth++; $Opened = $true }
                '}' { $Depth-- }
                { $_ -in '(', '[' } { $Nesting++ }
                { $_ -in ')', ']' } { $Nesting-- }
                ';' { if (-not $Opened -and $Nesting -le 0) { return $Index } }
            }
            if ($Opened -and $Depth -eq 0) {
                return $Index
            }
        }
    }
    $Code.Count - 1
}

# Lists the tests of a file. A test is a block of comments and attributes, an attribute spanning
# several lines included, that holds a test attribute; it runs to the end of the item the block decorates,
# so a marker in its comments, attributes, or body belongs to it and one in a later item does not.
function Get-Tests([string[]] $Lines, [string] $Extension) {
    $Pattern = $TestAttributePatterns[$Extension]
    $Code = Get-CodeLines $Lines $Extension
    $Tests = [System.Collections.Generic.List[object]]::new()
    $Start = -1
    $Attribute = -1
    $Depth = 0
    for ($Index = 0; $Index -lt $Lines.Count; $Index++) {
        if ($Depth -gt 0 -or $Code[$Index] -match '^\s*(#\[|\[)') {
            if ($Start -lt 0) {
                $Start = $Index
            }
            if ($Depth -eq 0 -and $Attribute -lt 0 -and $Code[$Index] -match $Pattern) {
                $Attribute = $Index
            }
            $Rest = -1
            foreach ($Bracket in [regex]::Matches($Code[$Index], '[\[\]]')) {
                if ($Bracket.Value -eq '[') {
                    $Depth++
                } elseif (--$Depth -eq 0) {
                    $Rest = $Bracket.Index + 1
                }
            }
            # A declaration may follow its attributes on their line, as in `[Fact] public void A() { }`.
            if ($Depth -ne 0 -or $Rest -lt 0 -or -not $Code[$Index].Substring($Rest).Trim()) {
                continue
            }
        } elseif (-not $Code[$Index].Trim() -and $Lines[$Index].Trim()) {
            if ($Start -lt 0) {
                $Start = $Index
            }
            continue
        }
        if ($Attribute -ge 0 -and -not $Lines[$Index].Trim()) {
            continue
        }
        if ($Attribute -ge 0) {
            $End = Get-ItemEnd $Code $Index
            $Tests.Add([pscustomobject]@{ Start = $Start; Attribute = $Attribute; Declaration = $Index; End = $End })
            $Index = $End
        }
        $Start = -1
        $Attribute = -1
    }
    $Tests
}

# Lists the Pester tests of a file: each `It` command, from the comment lines directly above it to the end of its block,
# so a marker on its line, above it, in its cases, or in its body belongs to it.
# The PowerShell parser gives the extent, because the hashtables of `-ForEach` cases defeat brace counting.
function Get-PesterTests([string[]] $Lines) {
    $Tokens = $null
    $Errors = $null
    $Ast = [System.Management.Automation.Language.Parser]::ParseInput(($Lines -join "`n"), [ref] $Tokens, [ref] $Errors)
    $Commands = $Ast.FindAll({
            param($Node)
            $Node -is [System.Management.Automation.Language.CommandAst] -and $Node.GetCommandName() -eq 'It'
        }, $true)
    foreach ($Command in $Commands) {
        $Declaration = $Command.Extent.StartLineNumber - 1
        $Start = $Declaration
        while ($Start -gt 0 -and $Lines[$Start - 1] -match '^\s*#') {
            $Start--
        }
        [pscustomobject]@{ Start = $Start; Attribute = $Declaration; Declaration = $Declaration; End = $Command.Extent.EndLineNumber - 1 }
    }
}

# Lists the tests of a file with their name, whether a marker sits in them, and a fingerprint:
# their lines without indentation, markers included, so a moved test matches its base occurrence and an unmarked copy of a marked test does not.
function Get-FileTests([string] $File, [string[]] $Lines) {
    $Extension = [System.IO.Path]::GetExtension($File)
    $MarkerLines = @(Get-FileMarkers $File $Lines | ForEach-Object { $_.Line })
    $Tests = if ($Extension -eq '.ps1') { @(Get-PesterTests $Lines) } else { @(Get-Tests $Lines $Extension) }
    foreach ($Test in $Tests) {
        $Declaration = @($Lines[$Test.Declaration..$Test.End] -match $DeclarationPatterns[$Extension])[0]
        $Name = if ($Declaration -match $DeclarationPatterns[$Extension]) { $Matches.name }
        $Marked = @($MarkerLines | Where-Object { $_ -gt $Test.Start -and $_ -le $Test.End + 1 }).Count -gt 0
        $Fingerprint = @($Lines[$Test.Start..$Test.End] | ForEach-Object { $_.Trim() }) -join "`n"
        $Test | Add-Member -NotePropertyName File -NotePropertyValue $File
        $Test | Add-Member -NotePropertyName Name -NotePropertyValue $Name
        $Test | Add-Member -NotePropertyName Marked -NotePropertyValue $Marked
        $Test | Add-Member -NotePropertyName Fingerprint -NotePropertyValue $Fingerprint
        $Test
    }
}

# Returns the lines of a file the diff from the base adds, numbered from 1.
function Get-AddedLines([string] $File) {
    $Added = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($Line in Invoke-Git diff --no-color --no-ext-diff --unified=0 $Base -- $File) {
        if ($Line -match '^@@ -\S+ \+(?<start>\d+)(?:,(?<count>\d+))? @@') {
            $Count = if ($Matches.count) { [int] $Matches.count } else { 1 }
            for ($Number = [int] $Matches.start; $Number -lt [int] $Matches.start + $Count; $Number++) {
                $Added.Add($Number) | Out-Null
            }
        }
    }
    , $Added
}

# Returns the fingerprints of the tests a name declares at the base in the files the diff touches.
function Get-BaseFingerprints([string] $Extension, [string] $Name, $Touched) {
    $Escaped = $Name -replace '([\[\]\\^$.|?*+(){}])', '\$1'
    $Pattern = switch ($Extension) {
        '.rs' { "fn[[:space:]]+$Escaped([^A-Za-z0-9_]|$)" }
        '.cs' { "(void|Task|ValueTask)[[:space:]]+$Escaped[[:space:]]*\(" }
        '.ps1' { "It[[:space:]]+(-Name[[:space:]]+)?('$Escaped'|`"$Escaped`")" }
    }
    $Case = if ($Extension -eq '.ps1') { '-i' } else { '--no-ignore-case' }
    $Fingerprints = [System.Collections.Generic.List[string]]::new()
    foreach ($Entry in @(& git -C $Root -c core.quotePath=false grep -l -I -E $Case -e $Pattern $Base -- "*$Extension")) {
        $File = $Entry.Substring($Base.Length + 1)
        if (-not $Touched.Contains($File)) {
            continue
        }
        $Lines = @(Invoke-Git show "${Base}:$File")
        foreach ($Test in @(Get-FileTests $File $Lines)) {
            if ($Test.Name -ceq $Name) {
                $Fingerprints.Add($Test.Fingerprint)
            }
        }
    }
    , $Fingerprints
}

# A test the diff adds is new unless it exactly matches, marker included, a base occurrence of its name that the diff moved away,
# and each new test needs its own marker. When the check cannot tell a new test from an edited or moved one, it counts it as new,
# so the doubt costs a marker rather than letting an unmarked test through; a name declared no more often than at the base gains no test.
function Test-NewTests {
    $ChangedFiles = @(Invoke-Git diff --name-only --diff-filter=AMR $Base -- '*.rs' '*.cs' '*.ps1')
    if ($ChangedFiles.Count -eq 0) {
        return
    }
    $Touched = [System.Collections.Generic.HashSet[string]]::new([string[]] @(Invoke-Git diff --name-only --no-renames $Base -- '*.rs' '*.cs' '*.ps1'))
    $Before = Get-DeclarationCounts $Base
    $After = Get-DeclarationCounts

    $Added = [System.Collections.Generic.List[object]]::new()
    $Kept = [System.Collections.Generic.List[object]]::new()
    foreach ($File in $ChangedFiles) {
        $Lines = @(Get-Content -LiteralPath (Join-Path $Root $File))
        $AddedLines = Get-AddedLines $File
        foreach ($Test in @(Get-FileTests $File $Lines)) {
            if ($AddedLines.Contains($Test.Attribute + 1) -or $AddedLines.Contains($Test.Declaration + 1)) {
                $Added.Add($Test)
            } else {
                $Kept.Add($Test)
            }
        }
    }

    # Names compare ordinally, as the declaration counts do.
    foreach ($Group in $Added | Group-Object -CaseSensitive { "$([System.IO.Path]::GetExtension($_.File)):$($_.Name)" }) {
        $Extension = [System.IO.Path]::GetExtension($Group.Group[0].File)
        $Name = $Group.Group[0].Name
        $New = [System.Collections.Generic.List[object]]::new()
        if ($null -eq $Name) {
            # A test whose name cannot be found counts as new.
            $New.AddRange(@($Group.Group))
        } else {
            $Key = "${Extension}:$Name"
            $Gain = (Get-Count $After $Key) - (Get-Count $Before $Key)
            if ($Gain -le 0) {
                continue
            }
            # The tests added beyond the gain may be moves, each from a base occurrence no kept test still holds.
            $Moves = $Group.Count - $Gain
            $Vacated = if ($Moves -gt 0) { Get-BaseFingerprints $Extension $Name $Touched }
            if ($Moves -gt 0) {
                foreach ($Test in $Kept | Where-Object { $_.Name -ceq $Name -and [System.IO.Path]::GetExtension($_.File) -eq $Extension }) {
                    $Vacated.Remove($Test.Fingerprint) | Out-Null
                }
            }
            foreach ($Test in $Group.Group) {
                if ($Moves -gt 0 -and $Vacated.Remove($Test.Fingerprint)) {
                    $Moves--
                } else {
                    $New.Add($Test)
                }
            }
        }
        $Form = if ($Extension -eq '.ps1') { '# oracle:' } else { '// oracle:' }
        foreach ($Test in $New | Where-Object { -not $_.Marked } | Sort-Object File, Attribute) {
            Add-Violation $Test.File ($Test.Attribute + 1) "new test has no '$Form' marker"
        }
    }
}

# Names the test a marker sits in: the declaration below when the marker heads a test's attributes,
# otherwise the nearest one above.
function Get-TestName([string] $File, [int] $Line) {
    $Lines = @(Get-Content -LiteralPath (Join-Path $Root $File))
    $Extension = [System.IO.Path]::GetExtension($File)
    $Pattern = $DeclarationPatterns[$Extension]
    $Prefix = $PrefixPatterns[$Extension]
    $Marker = $Line - 1
    if ($Lines[$Marker] -match $Prefix) {
        $Index = $Marker + 1
        while ($Index -lt $Lines.Count -and $Lines[$Index] -match $Prefix) {
            $Index++
        }
        if ($Index -lt $Lines.Count -and $Lines[$Index] -match $Pattern) {
            return $Matches.name
        }
    }
    for ($Index = $Marker; $Index -ge 0; $Index--) {
        if ($Lines[$Index] -match $Pattern) {
            return $Matches.name
        }
    }
}

function Get-DefaultHead([string] $Repository) {
    if (-not $DefaultHeads.ContainsKey($Repository)) {
        $Branch = ((Invoke-GitHub "repos/$Repository" -Expect 200).Body | ConvertFrom-Json).default_branch
        $DefaultHeads[$Repository] = [pscustomobject]@{ Branch = $Branch; Sha = (Resolve-Commit $Repository $Branch) }
    }
    $DefaultHeads[$Repository]
}

function Get-DriftStatus($Marker) {
    $Pinned = Get-RemoteFile $Marker.Repository $Marker.Pin $Marker.Path
    if ($Pinned.State -eq 'skipped') {
        return 'skipped: the token cannot read this repository'
    }
    $PinnedSection = if ($Pinned.State -eq 'ok') { Find-Section $Pinned.Outline $Marker.Section }
    if (-not $PinnedSection) {
        return 'unresolved: the pin does not resolve; see the pull request check'
    }
    $Head = Get-DefaultHead $Marker.Repository
    if ($Pinned.Sha -eq $Head.Sha) {
        return "current: pinned to the head of $($Head.Branch)"
    }
    $Current = Get-RemoteFile $Marker.Repository $Head.Sha $Marker.Path
    if ($Current.State -eq 'no-file') {
        return "removed: '$($Marker.Path)' no longer exists on $($Head.Branch); re-check the test"
    }
    $CurrentSection = if ($Current.State -eq 'ok') { Find-Section $Current.Outline $Marker.Section }
    if (-not $CurrentSection) {
        return "removed: §$($Marker.Section) no longer resolves on $($Head.Branch); re-check the test"
    }
    if ($CurrentSection.Body -cne $PinnedSection.Body) {
        return "changed on $($Head.Branch); re-check the test against the new text"
    }
    if ($CurrentSection.Heading -cne $PinnedSection.Heading) {
        return "moved: the section is now '$($CurrentSection.Heading)' on $($Head.Branch); re-check the test"
    }
    "unchanged: bump the pin to $($Head.Sha.Substring(0, 12))"
}

function Write-DriftReport {
    $Report = [System.Collections.Generic.List[string]]::new()
    $Report.Add('## Oracle marker drift')
    if ($PinnedMarkers.Count -eq 0) {
        $Report.Add('')
        $Report.Add('No marker is pinned to a commit.')
    }
    foreach ($Group in $PinnedMarkers | Group-Object Repository | Sort-Object Name) {
        $Report.Add('')
        $Report.Add("### $($Group.Name)")
        $Report.Add('')
        $Report.Add('| Test | Marker | Status |')
        $Report.Add('| --- | --- | --- |')
        foreach ($Marker in $Group.Group) {
            $Status = Get-DriftStatus $Marker
            $Name = Get-TestName $Marker.File $Marker.Line
            $Test = "$($Marker.File):$($Marker.Line)" + $(if ($Name) { " ($Name)" })
            $Report.Add("| $Test | $($Marker.Marker -replace '\|', '\|') | $Status |")
            if ($Env:GITHUB_ACTIONS -eq 'true' -and $Status -match 're-check') {
                Write-Host "::warning file=$($Marker.File),line=$($Marker.Line)::$Status"
            }
        }
    }
    $Report
    if ($Env:GITHUB_STEP_SUMMARY) {
        $Report | Add-Content -LiteralPath $Env:GITHUB_STEP_SUMMARY
    }
}

Test-Markers

if ($DriftReport) {
    Write-DriftReport
    exit 0
}

Test-Anchors

if ($Base) {
    Test-NewTests
}

foreach ($Violation in $Violations) {
    $Location = "$($Violation.File):$($Violation.Line)"
    Write-Output "${Location}: $($Violation.Message)"
    if ($Env:GITHUB_ACTIONS -eq 'true') {
        Write-Host "::error file=$($Violation.File),line=$($Violation.Line)::$($Violation.Message)"
    }
}

if ($SkippedReferences.Count -gt 0) {
    $Notice = "Only the syntax of $($SkippedReferences.Count) pinned references was checked, because the token cannot read their repositories: $($SkippedReferences -join ', ')"
    Write-Host $(if ($Env:GITHUB_ACTIONS -eq 'true') { "::notice::$Notice" } else { $Notice })
}

if ($Violations.Count -gt 0) {
    Write-Host "Oracle marker check failed; markers are defined in .agents/skills/test-oracle-reviewer/SKILL.md"
    exit 1
}

# Without this, the exit code is that of the last git command, which is 1 when `git grep` finds no marker.
exit 0
