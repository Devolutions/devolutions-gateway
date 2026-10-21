#!/bin/env pwsh
#Requires -Version 7.0

# Checks the `// oracle:` markers defined in `.agents/skills/test-oracle-reviewer/SKILL.md`
# in the tracked Rust and C# files of the working tree.
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
# A `//` inside a word, as in a URL, does not open a comment.
$MarkerPattern = '(?:^|\s)//\s*oracle:(?<rest>.*)$'
$Kinds = @('spec', 'contract', 'intent', 'regression', 'reference', 'property', 'mutant', 'scaffold')
$Laws = @('round-trip', 'idempotent', 'involution', 'commutative', 'associative', 'monotonic')
$AnchorPattern = '<a\s+id="(?<id>[^"]+)"\s*>\s*</a>'
# `<owner>/<repo>@<sha>:<path>`; a reference with `<owner>/<repo>:` but no valid pin is rejected.
$CrossRepositoryPattern = '^(?<owner>[\w.-]+)/(?<repo>[\w.-]+)(?:@(?<pin>[^:\s]*))?:(?<path>\S+)$'
$TestAttributePatterns = @{
    '.rs' = '^\s*#\[(?:test|tokio::test|rstest)\b'
    '.cs' = '^\s*\[(?:Fact|Theory)\b'
}
# A test is named by the function its attributes decorate; the git forms match the same declarations.
$DeclarationPatterns = @{
    '.rs' = '\bfn\s+(?<name>\w+)'
    '.cs' = '\b(?:void|Task|ValueTask)\s+(?<name>\w+)\s*\('
}
$GitDeclarationPatterns = @{
    '.rs' = 'fn[[:space:]]+[A-Za-z0-9_]+'
    '.cs' = '(void|Task|ValueTask)[[:space:]]+[A-Za-z0-9_]+[[:space:]]*\('
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
$TrackedFiles = [System.Collections.Generic.HashSet[string]]::new([string[]] ((Invoke-Git ls-files -z) -split "`0"))

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
            $Pending.Add($Anchor.Groups['id'].Value)
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
    [pscustomobject]@{ Lines = $Lines; Headings = $Headings; Anchors = $Anchors }
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
            if (-not (Find-Section $Remote.Outline $Section)) {
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
        if ($Document -match '://|@' -or $Document -match '/[^/\s]*\.[A-Za-z0-9]+$') {
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

function Test-Markers {
    $Output = & git -C $Root -c core.quotePath=false grep --null -n -I -E '(^|[[:space:]])//[[:space:]]*oracle:' -- '*.rs' '*.cs'
    if ($LASTEXITCODE -gt 1) {
        throw "git grep failed with exit code $LASTEXITCODE"
    }
    foreach ($Entry in $Output) {
        $File, $Line, $Content = $Entry -split "`0", 3
        if ($Content -match $MarkerPattern) {
            Test-Marker $File ([int] $Line) $Matches.rest
        }
    }
}

# Counts the declarations of each function name, per file extension, at a revision or in the working tree.
function Get-DeclarationCounts([string] $Revision) {
    $Counts = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
    foreach ($Extension in $GitDeclarationPatterns.Keys) {
        $Arguments = @('grep', '-h', '-o', '-I', '-E', '-e', $GitDeclarationPatterns[$Extension])
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

# Blanks string and character literals and drops a line comment, so brackets and braces in them are not counted.
function Get-CodeText([string] $Line) {
    $Line -replace 'r#*"[^"]*"#*', '""' -replace '"(?:\\.|[^"\\])*"', '""' -replace "'(?:\\.|[^'\\])'", "''" -replace '//.*$', ''
}

# Returns the line on which the item declared at $From ends: where its braces balance again,
# or its first `;` when it has no body, such as an expression-bodied member.
function Get-ItemEnd([string[]] $Lines, [int] $From) {
    $Depth = 0
    $Opened = $false
    for ($Index = $From; $Index -lt $Lines.Count; $Index++) {
        $Code = Get-CodeText $Lines[$Index]
        foreach ($Token in [regex]::Matches($Code, '[{};]')) {
            switch ($Token.Value) {
                '{' { $Depth++; $Opened = $true }
                '}' { $Depth-- }
                ';' { if (-not $Opened) { return $Index } }
            }
            if ($Opened -and $Depth -eq 0) {
                return $Index
            }
        }
    }
    $Lines.Count - 1
}

# Lists the tests of a file. A test is a block of comments and attributes, an attribute spanning
# several lines included, that holds a test attribute; it runs to the end of the item the block decorates,
# so a marker in its comments, attributes, or body belongs to it and one in a later item does not.
function Get-Tests([string[]] $Lines, [string] $Extension) {
    $Pattern = $TestAttributePatterns[$Extension]
    $Tests = [System.Collections.Generic.List[object]]::new()
    $Start = -1
    $Attribute = -1
    $Depth = 0
    for ($Index = 0; $Index -lt $Lines.Count; $Index++) {
        $Line = $Lines[$Index]
        if ($Depth -gt 0 -or $Line -match '^\s*(#\[|\[)') {
            if ($Start -lt 0) {
                $Start = $Index
            }
            if ($Depth -eq 0 -and $Attribute -lt 0 -and $Line -match $Pattern) {
                $Attribute = $Index
            }
            $Code = Get-CodeText $Line
            $Depth += ([regex]::Matches($Code, '\[')).Count - ([regex]::Matches($Code, '\]')).Count
            continue
        }
        if ($Line -match '^\s*//') {
            if ($Start -lt 0) {
                $Start = $Index
            }
            continue
        }
        if ($Attribute -ge 0 -and $Line -match '^\s*$') {
            continue
        }
        if ($Attribute -ge 0) {
            $End = Get-ItemEnd $Lines $Index
            $Tests.Add([pscustomobject]@{ Start = $Start; Attribute = $Attribute; Declaration = $Index; End = $End })
            $Index = $End
        }
        $Start = -1
        $Attribute = -1
    }
    $Tests
}

# A test is added when its function name is declared more often than at the base,
# so moving a test, or editing its attributes or body, does not count.
function Test-NewTests {
    $ChangedFiles = @(Invoke-Git diff --name-only --diff-filter=AMR $Base -- '*.rs' '*.cs')
    if ($ChangedFiles.Count -eq 0) {
        return
    }
    $Before = Get-DeclarationCounts $Base
    $After = Get-DeclarationCounts

    foreach ($File in $ChangedFiles) {
        $Extension = [System.IO.Path]::GetExtension($File)
        $Lines = @(Get-Content -LiteralPath (Join-Path $Root $File))

        foreach ($Test in @(Get-Tests $Lines $Extension)) {
            $Declaration = @($Lines[$Test.Declaration..$Test.End] -match $DeclarationPatterns[$Extension])[0]
            # A test whose name cannot be found counts as added.
            if ($Declaration -match $DeclarationPatterns[$Extension]) {
                $Key = "${Extension}:$($Matches.name)"
                if ((Get-Count $After $Key) -le (Get-Count $Before $Key)) {
                    continue
                }
            }
            $HasMarker = $Lines[$Test.Start..$Test.End] -match $MarkerPattern
            if (-not $HasMarker) {
                Add-Violation $File ($Test.Attribute + 1) "new test has no '// oracle:' marker"
            }
        }
    }
}

# Names the test a marker sits in: the declaration below when the marker heads a test's attributes,
# otherwise the nearest one above.
function Get-TestName([string] $File, [int] $Line) {
    $Lines = @(Get-Content -LiteralPath (Join-Path $Root $File))
    $Pattern = $DeclarationPatterns[[System.IO.Path]::GetExtension($File)]
    $Marker = $Line - 1
    if ($Lines[$Marker] -match '^\s*(//|#\[|\[)') {
        $Index = $Marker + 1
        while ($Index -lt $Lines.Count -and $Lines[$Index] -match '^\s*(//|#\[|\[)') {
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
