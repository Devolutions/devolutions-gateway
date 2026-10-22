BeforeAll {
    $Script = Join-Path $PSScriptRoot 'check-oracle-markers.ps1'
    # Fixtures write a PowerShell marker as "`# oracle:", which builds `# oracle:` while this file's own scan reads no marker in it.

    # The script annotates in GitHub Actions, and fixture violations must not annotate the pull request.
    $SavedGitHubActions = $Env:GITHUB_ACTIONS
    $SavedStepSummary = $Env:GITHUB_STEP_SUMMARY
    $Env:GITHUB_ACTIONS = $null
    $Env:GITHUB_STEP_SUMMARY = $null

    $PinA = '43958682a1b2' + ('0' * 28)
    $PinB = 'b0b0b0b0b0b0' + ('1' * 28)
    $Contract = "# Specs`n`n<a id=`"agent-id`"></a>`n## 6 Agent identity`n`nAgents present a key.`n`n## 7 Other`n"

    function Set-RepoFile([string] $Repo, [string] $Path, [string] $Content) {
        $FullPath = Join-Path $Repo $Path
        New-Item -ItemType Directory -Force -Path (Split-Path $FullPath) | Out-Null
        [System.IO.File]::WriteAllText($FullPath, $Content)
    }

    function Invoke-Git([string] $Repo) {
        & git -C $Repo -c user.name=test -c user.email=test@example.com @args | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "git $args failed"
        }
    }

    # Copies one committed template, since building a repository per test dominates the run time.
    function New-Repo {
        $Repo = Join-Path $TestDrive ([guid]::NewGuid())
        Copy-Item -Recurse -LiteralPath $Template -Destination $Repo
        Clear-ReadOnly $Repo
        $Repo
    }

    # Git writes its objects read-only, which stops Pester from removing the test drive on Windows.
    function Clear-ReadOnly([string] $Path) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -Force | Where-Object IsReadOnly | ForEach-Object { $_.IsReadOnly = $false }
    }

    function New-Template {
        $Repo = (New-Item -ItemType Directory -Path (Join-Path $TestDrive 'template')).FullName
        Invoke-Git $Repo init -q
        Set-RepoFile $Repo 'docs/JMUX-spec.md' "# JMUX Specification`n`n## Channels`n"
        Set-RepoFile $Repo 'crates/x/INTENT.md' "# Invariants`n`n``````text`n# Fenced`n```````n"
        Set-RepoFile $Repo 'src/recording.intent.md' "# Artifacts`n"
        Set-RepoFile $Repo 'api/CONTRACT.md' "# API`n`n<a id=`"framing`"></a>`n## 3.2 Framing`n"
        Set-RepoFile $Repo 'api/README.md' "# Framing`n"
        Set-RepoFile $Repo 'docs/fences.md' "# Fences`n`n````````md`n``````text`n## Nested`n`````````n`n~~~`n``````text`n## Mixed`n~~~`n`n## Real`n"
        Set-RepoFile $Repo 'docs/anchors.md' "# Anchors`n`n<a id=`"spaced`"></a>`n`n## Spaced`n`n<a id=`"stray`"></a>`nA paragraph.`n`n## Later`n`n<a id=`"orphan`"></a>`n"
        Set-RepoFile $Repo 'fuzz/.gitignore' "artifacts`n"
        Set-RepoFile $Repo 'fuzz/artifacts/jmux/crash-1' 'crash'
        Set-RepoFile $Repo 'fuzz/artifacts/jmux/crash-ignored' 'crash'
        Invoke-Git $Repo add -A
        Invoke-Git $Repo add -f 'fuzz/artifacts/jmux/crash-1'
        Invoke-Git $Repo commit -q -m base
        $Repo
    }

    $Template = New-Template

    # Answers the GitHub REST endpoints the script calls from $Repositories, where each readable repository
    # maps to its default branch, branch heads, and files per commit; any other repository answers 404,
    # as GitHub does for a private repository the token cannot read.
    function New-FakeGitHub([hashtable] $Repositories, [hashtable] $Calls = @{}) {
        {
            param([string] $Endpoint, [string] $Accept)
            $Calls[$Endpoint] = 1 + [int] $Calls[$Endpoint]
            $NotFound = [pscustomobject]@{ Status = 404; Body = '{"message":"Not Found"}' }
            if ($Endpoint -notmatch '^repos/(?<repository>[^/]+/[^/]+)(?<rest>/.*)?$' -or -not $Repositories.ContainsKey($Matches.repository)) {
                return $NotFound
            }
            $Repository = $Repositories[$Matches.repository]
            $Rest = $Matches.rest
            if (-not $Rest) {
                return [pscustomobject]@{ Status = 200; Body = (@{ default_branch = $Repository.Default } | ConvertTo-Json) }
            }
            if ($Rest -match '^/commits/(?<ref>[^/]+)$') {
                $Ref = $Matches.ref
                $Sha = if ($Repository.Branches.ContainsKey($Ref)) { $Repository.Branches[$Ref] } else { @($Repository.Commits.Keys | Where-Object { $_.StartsWith($Ref) }) | Select-Object -First 1 }
                if (-not $Sha) {
                    return [pscustomobject]@{ Status = 422; Body = '{"message":"No commit found"}' }
                }
                return [pscustomobject]@{ Status = 200; Body = (@{ sha = $Sha } | ConvertTo-Json) }
            }
            if ($Rest -match '^/contents/(?<path>.+)\?ref=(?<sha>[0-9a-f]{40})$') {
                $Files = $Repository.Commits[$Matches.sha]
                $Path = [uri]::UnescapeDataString($Matches.path)
                if ($Files -and $Files.Keys -ccontains $Path) {
                    return [pscustomobject]@{ Status = 200; Body = $Files[$Path] }
                }
            }
            $NotFound
        }.GetNewClosure()
    }

    function Invoke-Check([string] $Repo, [string] $Base, [scriptblock] $GitHubApi = (New-FakeGitHub @{}), [switch] $DriftReport) {
        $Arguments = @{ Root = $Repo; GitHubApi = $GitHubApi; DriftReport = $DriftReport }
        if ($Base) {
            $Arguments.Base = $Base
        }
        $Output = & $Script @Arguments 6>$null
        [pscustomobject]@{ Output = @($Output); ExitCode = $LASTEXITCODE }
    }
}

AfterAll {
    Clear-ReadOnly $Template
    $Env:GITHUB_ACTIONS = $SavedGitHubActions
    $Env:GITHUB_STEP_SUMMARY = $SavedStepSummary
}

Describe 'Marker grammar and references' {
    It 'Accepts <Name>' -ForEach @(
        @{ Name = 'a named spec'; Marker = 'spec RFC 6455 §5.2' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a named spec with a slash'; Marker = 'spec ISO/IEC 8825-1 §8.1' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a named spec with a dot'; Marker = 'spec ITU-T X.690 §8.1' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a spec under docs/'; Marker = 'spec docs/JMUX-spec.md §Channels' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a contract section by number'; Marker = 'contract api/CONTRACT.md §3.2' } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'a contract section by title in another case'; Marker = 'contract api/CONTRACT.md §3.2 framing' } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'a contract section by anchor'; Marker = 'contract api/CONTRACT.md §framing' } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'an anchor a blank line above its heading'; Marker = 'spec docs/anchors.md §spaced' } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'a heading after code fences'; Marker = 'spec docs/fences.md §Real' } # oracle: spec CommonMark 0.31.2 §4.5
        @{ Name = 'an INTENT.md section'; Marker = 'intent crates/x/INTENT.md §Invariants' } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'a .intent.md section'; Marker = 'intent src/recording.intent.md §Artifacts' } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'a Jira regression'; Marker = 'regression DGW-123 empty header' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a pull request regression'; Marker = 'regression #2136' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'another repository''s issue'; Marker = 'regression Devolutions/IronRDP#12' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a committed fuzz crash file'; Marker = 'regression fuzz/artifacts/jmux/crash-1' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a reference'; Marker = 'reference FreeRDP capture' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'the round-trip law'; Marker = 'property round-trip' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'the monotonic law'; Marker = 'property monotonic' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a mutant'; Marker = 'mutant dropping the length check' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
    ) {
        $Repo = New-Repo
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {} // oracle: $Marker`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Rejects <Name>' -ForEach @(
        @{ Name = 'scaffold'; Marker = 'scaffold'; Message = "'scaffold' marker must not merge" } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a marker without a kind'; Marker = ''; Message = 'marker has no kind' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'an unknown kind'; Marker = 'specification RFC 6455 §5.2'; Message = "unknown oracle kind 'specification'" } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a kind in another case'; Marker = 'Spec RFC 6455 §5.2'; Message = "unknown oracle kind 'Spec'" } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a kind without a reference'; Marker = 'reference'; Message = "'reference' marker has no reference" } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a property in words'; Marker = 'property decode inverts encode'; Message = "'property decode inverts encode' is not a well-known law" } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a law in another case'; Marker = 'property Round-trip'; Message = "'property Round-trip' is not a well-known law" } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a law with more words'; Marker = 'property round-trip of encode'; Message = "'property round-trip of encode' is not a well-known law" } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a spec without a section'; Marker = 'spec RFC 6455'; Message = "'spec' marker needs '<document> §<section>'" } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a spec URL'; Marker = 'spec https://github.com/Devolutions/devolutions-gateway/blob/master/docs/JMUX-spec.md §Channels'; Message = 'looks like a URL or a path' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a spec at a branch'; Marker = 'spec Devolutions/devolutions-gateway@master docs/JMUX-spec.md §Channels'; Message = 'looks like a URL or a path' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a spec path in another case'; Marker = 'spec Docs/JMUX-spec.md §Channels'; Message = 'looks like a URL or a path' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a spec path outside docs/'; Marker = 'spec crates/jmux-proto/SPEC.md §Channels'; Message = 'looks like a URL or a path' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a bare Markdown file name as a spec'; Marker = 'spec JMUX-spec.md §Channels'; Message = 'looks like a URL or a path' } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a missing spec under docs/'; Marker = 'spec docs/JET.md §Header'; Message = "spec file 'docs/JET.md' is not tracked" } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'a missing spec section under docs/'; Marker = 'spec docs/JMUX-spec.md §Sessions'; Message = "spec file 'docs/JMUX-spec.md' has no section 'Sessions'" } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'a contract that is not a CONTRACT*.md'; Marker = 'contract api/README.md §Framing'; Message = "contract 'api/README.md' is not a CONTRACT*.md file" } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a missing contract'; Marker = 'contract web/CONTRACT.md §Framing'; Message = "contract file 'web/CONTRACT.md' is not tracked" } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'a contract path relative to the test'; Marker = 'contract CONTRACT.md §3.2'; Message = "contract file 'CONTRACT.md' is not tracked" } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'a missing contract section'; Marker = 'contract api/CONTRACT.md §3.3'; Message = "contract file 'api/CONTRACT.md' has no section '3.3'" } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'a heading number prefix'; Marker = 'contract api/CONTRACT.md §3'; Message = "has no section '3'" } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'an anchor in another case'; Marker = 'contract api/CONTRACT.md §FRAMING'; Message = "has no section 'FRAMING'" } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'a missing intent section'; Marker = 'intent crates/x/INTENT.md §Goals'; Message = "intent file 'crates/x/INTENT.md' has no section 'Goals'" } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'a heading inside a code fence'; Marker = 'intent crates/x/INTENT.md §Fenced'; Message = "has no section 'Fenced'" } # oracle: spec CommonMark 0.31.2 §4.5
        @{ Name = 'a heading after a shorter fence inside a longer one'; Marker = 'spec docs/fences.md §Nested'; Message = "has no section 'Nested'" } # oracle: spec CommonMark 0.31.2 §4.5
        @{ Name = 'a heading after a backtick fence inside a tilde one'; Marker = 'spec docs/fences.md §Mixed'; Message = "has no section 'Mixed'" } # oracle: spec CommonMark 0.31.2 §4.5
        @{ Name = 'an anchor followed by a paragraph'; Marker = 'spec docs/anchors.md §stray'; Message = "has no section 'stray'" } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'an anchor with no heading after it'; Marker = 'spec docs/anchors.md §orphan'; Message = "has no section 'orphan'" } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'an intent that is not an intent file'; Marker = 'intent docs/JMUX-spec.md §Channels'; Message = "is not an INTENT*.md or *.intent*.md file" } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a regression in words'; Marker = 'regression the crash from last week'; Message = "regression reference 'the' is not a Jira key" } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'a missing fuzz crash file'; Marker = 'regression fuzz/artifacts/jmux/crash-2'; Message = "regression reference 'fuzz/artifacts/jmux/crash-2'" } # oracle: intent ci/check-oracle-markers.intent.md §grammar
        @{ Name = 'an ignored fuzz crash file, which CI never sees'; Marker = 'regression fuzz/artifacts/jmux/crash-ignored'; Message = "regression reference 'fuzz/artifacts/jmux/crash-ignored'" } # oracle: intent ci/check-oracle-markers.intent.md §languages
    ) {
        $Repo = New-Repo
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {}`n// oracle: $Marker`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -HaveCount 1
        $Result.Output[0] | Should -BeLike "src/lib.rs:2: *$Message*"
        $Result.ExitCode | Should -Be 1
    }

    It 'Ignores oracle: after the // of a URL' { # oracle: intent ci/check-oracle-markers.intent.md §languages
        $Repo = New-Repo
        Set-RepoFile $Repo 'src/lib.rs' "const URL: &str = `"http://oracle:8080/x`";`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Ignores marker-shaped text inside <Name>' -ForEach @(
        @{ Name = 'a Rust raw string'; Path = 'src/lib.rs'; Content = "const S: &str = r`"`n// oracle: scaffold`n`";`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'a C# verbatim string'; Path = 'dotnet/T.cs'; Content = "class T { string s = @`"`n// oracle: scaffold`n`"; }`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'a PowerShell here-string'; Path = 'ci/a.ps1'; Content = "`$x = @'`n`# oracle: scaffold`n'@`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'a nested Rust block comment'; Path = 'src/lib.rs'; Content = "/* outer`n/* inner */`n// oracle: scaffold`n*/`nfn f() {}`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
    ) {
        $Repo = New-Repo
        Set-RepoFile $Repo $Path $Content
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Reads a C# line comment after a block comment, which does not nest' { # oracle: intent ci/check-oracle-markers.intent.md §languages
        $Repo = New-Repo
        Set-RepoFile $Repo 'dotnet/T.cs' "/* a /* b */`n// oracle: scaffold`nclass T {}`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -Be @("dotnet/T.cs:2: 'scaffold' marker must not merge; give what it marks a strong source, keep it as 'mutant', or delete it")
        $Result.ExitCode | Should -Be 1
    }

    It 'Ignores a marker label in another case' { # oracle: intent ci/check-oracle-markers.intent.md §languages
        $Repo = New-Repo
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {} // ORACLE: scaffold`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Checks markers in PowerShell files' { # oracle: intent ci/check-oracle-markers.intent.md §languages
        $Repo = New-Repo
        Set-RepoFile $Repo 'ci/a.Tests.ps1' "Describe 'd' {`n    It 'a' { `# oracle: scaffold`n    }`n}`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -Be @("ci/a.Tests.ps1:2: 'scaffold' marker must not merge; give what it marks a strong source, keep it as 'mutant', or delete it")
        $Result.ExitCode | Should -Be 1
    }

    It 'Checks markers in C# files and Rust doctests' { # oracle: intent ci/check-oracle-markers.intent.md §languages
        $Repo = New-Repo
        Set-RepoFile $Repo 'dotnet/Tests.cs' "class T {} // oracle: scaffold`n"
        Set-RepoFile $Repo 'src/doc.rs' "/// # // oracle: scaffold`nfn f() {}`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -HaveCount 2
        $Result.Output | Should -BeLike '*: ''scaffold'' marker must not merge*'
        $Result.ExitCode | Should -Be 1
    }
}

Describe 'Repeated anchors' {
    It 'Rejects an anchor id repeated within a file a marker may cite' { # oracle: intent ci/check-oracle-markers.intent.md §paths
        $Repo = New-Repo
        Set-RepoFile $Repo 'docs/repeated.md' "<a id=`"x`"></a>`n# A`n`n<a id=`"x`"></a>`n# B`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -Be @("docs/repeated.md:4: anchor 'x' repeats the one on line 1")
        $Result.ExitCode | Should -Be 1
    }

    It 'Accepts the same anchor id in two files' { # oracle: intent ci/check-oracle-markers.intent.md §paths
        $Repo = New-Repo
        Set-RepoFile $Repo 'docs/one.md' "<a id=`"x`"></a>`n# A`n"
        Set-RepoFile $Repo 'docs/two.md' "<a id=`"x`"></a>`n# B`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Rejects a citation of a pinned file with a repeated anchor, cited by <Name>' -ForEach @(
        @{ Name = 'the repeated id'; Section = 'x' } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'a heading'; Section = 'A' } # oracle: intent ci/check-oracle-markers.intent.md §paths
    ) {
        $Repo = New-Repo
        $GitHub = New-FakeGitHub @{
            'Org/specs' = @{ Default = 'main'; Branches = @{ main = $PinA }; Commits = @{ $PinA = @{ 'docs/CONTRACT.specs.md' = "<a id=`"x`"></a>`n# A`n`n<a id=`"x`"></a>`n# B`n" } } }
        }
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {} // oracle: contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §$Section`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo -GitHubApi $GitHub

        $Result.Output | Should -Be @("src/lib.rs:1: 'docs/CONTRACT.specs.md' in Org/specs at 43958682a1b2 has more than one anchor 'x'")
        $Result.ExitCode | Should -Be 1
    }
}

Describe 'Pinned references to other repositories' {
    BeforeEach {
        $Repo = New-Repo
        $Calls = @{}
        $GitHub = New-FakeGitHub @{
            'Org/specs' = @{
                Default = 'main'
                Branches = @{ main = $PinA; deadbeefcafe = $PinA }
                Commits = @{ $PinA = @{ 'docs/CONTRACT.specs.md' = $Contract; 'docs/CONTRACT.crlf.md' = ($Contract -replace "`n", "`r`n"); 'docs/README.md' = $Contract } }
            }
        } $Calls
    }

    It 'Accepts <Name>' -ForEach @(
        @{ Name = 'a section by number'; Marker = 'contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §6' } # oracle: intent ci/check-oracle-markers.intent.md §pins
        @{ Name = 'a section by anchor'; Marker = 'contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §agent-id' } # oracle: intent ci/check-oracle-markers.intent.md §pins
        @{ Name = 'a section of a file with CRLF line endings'; Marker = 'contract Org/specs@43958682a1b2:docs/CONTRACT.crlf.md §6' } # oracle: spec CommonMark 0.31.2 §2.1
        @{ Name = 'a spec at a full SHA'; Marker = 'spec Org/specs@43958682a1b20000000000000000000000000000:docs/README.md §7 Other' } # oracle: intent ci/check-oracle-markers.intent.md §pins
    ) {
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {} // oracle: $Marker`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo -GitHubApi $GitHub

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Rejects <Name>' -ForEach @(
        @{ Name = 'an unpinned reference'; Marker = 'contract Org/specs:docs/CONTRACT.specs.md §6'; Message = "'contract' marker must pin a commit SHA" } # oracle: intent ci/check-oracle-markers.intent.md §pins
        @{ Name = 'a branch pin'; Marker = 'contract Org/specs@main:docs/CONTRACT.specs.md §6'; Message = "'contract' marker must pin a commit SHA" } # oracle: intent ci/check-oracle-markers.intent.md §pins
        @{ Name = 'a pin shorter than 12 digits'; Marker = 'contract Org/specs@43958682a1b:docs/CONTRACT.specs.md §6'; Message = "'contract' marker must pin a commit SHA" } # oracle: intent ci/check-oracle-markers.intent.md §pins
        @{ Name = 'an unpinned reference to an unreadable repository'; Marker = 'intent Org/secret@v1.2:INTENT.md §Goals'; Message = "'intent' marker must pin a commit SHA" } # oracle: intent ci/check-oracle-markers.intent.md §pins
        @{ Name = 'an unknown commit'; Marker = 'contract Org/specs@0123456789ab:docs/CONTRACT.specs.md §6'; Message = "'0123456789ab' is not a commit of Org/specs" } # oracle: intent ci/check-oracle-markers.intent.md §pins
        @{ Name = 'a branch named like a SHA'; Marker = 'contract Org/specs@deadbeefcafe:docs/CONTRACT.specs.md §6'; Message = "'deadbeefcafe' is not a commit of Org/specs" } # oracle: intent ci/check-oracle-markers.intent.md §pins
        @{ Name = 'a missing file'; Marker = 'contract Org/specs@43958682a1b2:docs/CONTRACT.other.md §6'; Message = "'docs/CONTRACT.other.md' does not exist in Org/specs at 43958682a1b2" } # oracle: intent ci/check-oracle-markers.intent.md §pins
        @{ Name = 'a missing section'; Marker = 'contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §8'; Message = "'docs/CONTRACT.specs.md' in Org/specs at 43958682a1b2 has no section '8'" } # oracle: intent ci/check-oracle-markers.intent.md §pins
        @{ Name = 'a contract that is not a CONTRACT*.md'; Marker = 'contract Org/specs@43958682a1b2:docs/README.md §6'; Message = "contract 'docs/README.md' is not a CONTRACT*.md file" } # oracle: intent ci/check-oracle-markers.intent.md §grammar
    ) {
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {}`n// oracle: $Marker`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo -GitHubApi $GitHub

        $Result.Output | Should -HaveCount 1
        $Result.Output[0] | Should -BeLike "src/lib.rs:2: *$Message*"
        $Result.ExitCode | Should -Be 1
    }

    It 'Checks only the syntax of a pinned reference to a repository the token cannot read' { # oracle: intent ci/check-oracle-markers.intent.md §pins
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {} // oracle: contract Org/secret@43958682a1b2:docs/CONTRACT.md §6`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo -GitHubApi $GitHub

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Checks only the syntax of a pinned reference to an organization that has not authorized the token' { # oracle: intent ci/check-oracle-markers.intent.md §pins
        $Saml = { param($Endpoint, $Accept) [pscustomobject]@{ Status = 403; Body = '{"message":"Resource protected by organization SAML enforcement."}' } }
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {} // oracle: contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §6`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo -GitHubApi $Saml

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Stops on <Name> rather than skip every pin' -ForEach @(
        @{ Name = 'a bad token'; Status = 401; Body = '{"message":"Bad credentials"}' } # oracle: intent ci/check-oracle-markers.intent.md §pins
        @{ Name = 'a rate limit'; Status = 403; Body = '{"message":"API rate limit exceeded for user ID 1."}' } # oracle: intent ci/check-oracle-markers.intent.md §pins
        @{ Name = 'a secondary rate limit'; Status = 429; Body = '{"message":"You have exceeded a secondary rate limit."}' } # oracle: intent ci/check-oracle-markers.intent.md §pins
    ) {
        $Failing = { param($Endpoint, $Accept) [pscustomobject]@{ Status = $Status; Body = $Body } }.GetNewClosure()
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {} // oracle: contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §6`n"
        Invoke-Git $Repo add -A

        { Invoke-Check $Repo -GitHubApi $Failing } | Should -Throw "*returned ${Status}*"
    }

    It 'Rejects a pinned path in another case, <Name>' -ForEach @(
        @{ Name = 'cited after the real path'; Paths = @('docs/CONTRACT.specs.md', 'Docs/CONTRACT.specs.md') } # oracle: intent ci/check-oracle-markers.intent.md §paths
        @{ Name = 'cited before the real path'; Paths = @('Docs/CONTRACT.specs.md', 'docs/CONTRACT.specs.md') } # oracle: intent ci/check-oracle-markers.intent.md §paths
    ) {
        $Lines = $Paths | ForEach-Object { "fn f() {} // oracle: contract Org/specs@43958682a1b2:$_ §6" }
        Set-RepoFile $Repo 'src/lib.rs' (($Lines -join "`n") + "`n")
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo -GitHubApi $GitHub

        $Result.Output | Should -Be @("src/lib.rs:$([array]::IndexOf($Paths, 'Docs/CONTRACT.specs.md') + 1): 'Docs/CONTRACT.specs.md' does not exist in Org/specs at 43958682a1b2")
    }

    It 'Fetches a pinned file once for several markers' { # oracle: intent ci/check-oracle-markers.intent.md §pins
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {} // oracle: contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §6`nfn g() {} // oracle: contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §7`n"
        Invoke-Git $Repo add -A

        Invoke-Check $Repo -GitHubApi $GitHub | Out-Null

        $Calls["repos/Org/specs/contents/docs/CONTRACT.specs.md?ref=$PinA"] | Should -Be 1
    }
}

Describe 'Drift report' {
    BeforeEach {
        $Repo = New-Repo
        Set-RepoFile $Repo 'src/lib.rs' "#[test]`nfn agent_presents_key() {`n    // oracle: contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §6`n}`n"
        Invoke-Git $Repo add -A
    }

    It 'Reports a pinned section that is <Name> on the default branch' -ForEach @(
        @{ Name = 'unchanged'; Head = "# Specs, revised`n`n<a id=`"agent-id`"></a>`n## 6 Agent identity`n`nAgents present a key.`n"; Status = 'unchanged: bump the pin to b0b0b0b0b0b0' } # oracle: intent ci/check-oracle-markers.intent.md §drift
        @{ Name = 'unchanged while the next section gains an anchor'; Head = "# Specs`n`n<a id=`"agent-id`"></a>`n## 6 Agent identity`n`nAgents present a key.`n`n<a id=`"other`"></a>`n## 7 Other`n"; Status = 'unchanged: bump the pin to b0b0b0b0b0b0' } # oracle: intent ci/check-oracle-markers.intent.md §drift
        @{ Name = 'changed'; Head = "# Specs`n`n## 6 Agent identity`n`nAgents present a certificate.`n"; Status = 'changed on main; re-check the test against the new text' } # oracle: intent ci/check-oracle-markers.intent.md §drift
        @{ Name = 'renamed'; Head = "# Specs`n`n## 6 Agent keys`n`nAgents present a key.`n"; Status = "moved: the section is now '6 Agent keys' on main; re-check the test" } # oracle: intent ci/check-oracle-markers.intent.md §drift
        @{ Name = 'removed'; Head = "# Specs`n`n## 7 Other`n"; Status = 'removed: §6 no longer resolves on main; re-check the test' } # oracle: intent ci/check-oracle-markers.intent.md §drift
        @{ Name = 'gone with its file'; Head = $null; Status = "removed: 'docs/CONTRACT.specs.md' no longer exists on main; re-check the test" } # oracle: intent ci/check-oracle-markers.intent.md §drift
    ) {
        $HeadFiles = if ($Head) { @{ 'docs/CONTRACT.specs.md' = $Head } } else { @{} }
        $GitHub = New-FakeGitHub @{
            'Org/specs' = @{ Default = 'main'; Branches = @{ main = $PinB }; Commits = @{ $PinA = @{ 'docs/CONTRACT.specs.md' = $Contract }; $PinB = $HeadFiles } }
        }

        $Result = Invoke-Check $Repo -GitHubApi $GitHub -DriftReport

        $Result.Output | Should -Contain "| src/lib.rs:3 (agent_presents_key) | contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §6 | $Status |"
        $Result.ExitCode | Should -Be 0
    }

    It 'Resolves an anchor before a heading of the same text' { # oracle: intent ci/check-oracle-markers.intent.md §paths
        Set-RepoFile $Repo 'src/lib.rs' "#[test]`nfn ordered() {`n    // oracle: contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §x`n}`n"
        Invoke-Git $Repo add -A
        $Pinned = "<a id=`"x`"></a>`n## A`n`none`n`n## x`n`ntwo`n"
        $Head = "<a id=`"x`"></a>`n## A`n`none`n`n## x`n`nthree`n"
        $GitHub = New-FakeGitHub @{
            'Org/specs' = @{ Default = 'main'; Branches = @{ main = $PinB }; Commits = @{ $PinA = @{ 'docs/CONTRACT.specs.md' = $Pinned }; $PinB = @{ 'docs/CONTRACT.specs.md' = $Head } } }
        }

        $Result = Invoke-Check $Repo -GitHubApi $GitHub -DriftReport

        $Result.Output | Should -Contain '| src/lib.rs:3 (ordered) | contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §x | unchanged: bump the pin to b0b0b0b0b0b0 |'
    }

    It 'Groups the report by repository' { # oracle: intent ci/check-oracle-markers.intent.md §drift
        Set-RepoFile $Repo 'src/other.rs' "#[test] // oracle: intent Org/agent@b0b0b0b0b0b0:INTENT.md §Goals`nfn goals() {}`n"
        Invoke-Git $Repo add -A
        $GitHub = New-FakeGitHub @{
            'Org/specs' = @{ Default = 'main'; Branches = @{ main = $PinA }; Commits = @{ $PinA = @{ 'docs/CONTRACT.specs.md' = $Contract } } }
            'Org/agent' = @{ Default = 'master'; Branches = @{ master = $PinB }; Commits = @{ $PinB = @{ 'INTENT.md' = "# Goals`n" } } }
        }

        $Result = Invoke-Check $Repo -GitHubApi $GitHub -DriftReport

        $Result.Output | Where-Object { $_ -like '### *' } | Should -Be @('### Org/agent', '### Org/specs')
    }

    It 'Marks a pinned reference to a repository the token cannot read as skipped' { # oracle: mutant reporting an unreadable pin as changed or removed
        $Result = Invoke-Check $Repo -DriftReport

        $Result.Output | Should -Contain '| src/lib.rs:3 (agent_presents_key) | contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §6 | skipped: the token cannot read this repository |'
    }
}

Describe 'New tests' {
    BeforeEach {
        $Repo = New-Repo
        Set-RepoFile $Repo 'src/old.rs' "#[test]`nfn old() {}`n"
        Set-RepoFile $Repo 'dotnet/OldTests.cs' "class OldTests`n{`n    [Fact]`n    public void Old() { }`n}`n"
        Set-RepoFile $Repo 'ci/old.Tests.ps1' "Describe 'd' {`n    It 'old' {`n        1 | Should -Be 1`n    }`n}`n"
        Invoke-Git $Repo add -A
        Invoke-Git $Repo commit -q -m tests
        $Base = (& git -C $Repo rev-parse HEAD)
    }

    It 'Reports a new <Name> without a marker at its test attribute' -ForEach @(
        @{ Name = 'Rust test'; Path = 'src/a.rs'; Content = "fn helper() {}`n`n#[test]`nfn a() {`n    assert!(true);`n}`n"; Line = 3; Form = '// oracle:' } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'tokio test'; Path = 'src/a.rs'; Content = "#[tokio::test(flavor = `"multi_thread`")]`nasync fn a() {}`n"; Line = 1; Form = '// oracle:' } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'rstest with a tokio test'; Path = 'src/a.rs'; Content = "#[rstest]`n#[tokio::test]`nasync fn a() {}`n"; Line = 1; Form = '// oracle:' } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'xUnit fact'; Path = 'dotnet/ATests.cs'; Content = "class ATests`n{`n    [Fact]`n    public void A() { }`n}`n"; Line = 3; Form = '// oracle:' } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'xUnit theory'; Path = 'dotnet/ATests.cs'; Content = "class ATests`n{`n    [Theory]`n    [InlineData(1)]`n    public void A(int x) { }`n}`n"; Line = 3; Form = '// oracle:' } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'Rust test followed by a marked helper'; Path = 'src/a.rs'; Content = "#[test]`nfn a() {`n    let s = `"}`";`n}`n`nfn helper() {`n    // oracle: property round-trip`n}`n"; Line = 1; Form = '// oracle:' } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'Pester test'; Path = 'ci/a.Tests.ps1'; Content = "Describe 'd' {`n    It 'a' {`n        1 | Should -Be 1`n    }`n}`n"; Line = 2; Form = '# oracle:' } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'Pester test followed by a marked one'; Path = 'ci/a.Tests.ps1'; Content = "Describe 'd' {`n    It 'a' {`n    }`n`n    It 'b' {`n        1 | Should -Be 1 `# oracle: property round-trip`n    }`n}`n"; Line = 2; Form = '# oracle:' } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'Pester test declared with a lowercase it'; Path = 'ci/a.Tests.ps1'; Content = "Describe 'd' {`n    it 'a' {`n    }`n}`n"; Line = 2; Form = '# oracle:' } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'Rust test with a brace in a block comment, followed by a marked helper'; Path = 'src/a.rs'; Content = "#[test]`nfn a() {`n    /* { */`n}`n`nfn helper() {`n    // oracle: property round-trip`n}`n"; Line = 1; Form = '// oracle:' } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'Rust test whose only marker sits in a raw string'; Path = 'src/a.rs'; Content = "#[test]`nfn a() {`n    let s = r`"`n// oracle: property round-trip`n`";`n}`n"; Line = 1; Form = '// oracle:' } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'Rust test whose only marker label is uppercase'; Path = 'src/a.rs'; Content = "#[test]`nfn a() {} // ORACLE: property round-trip`n"; Line = 1; Form = '// oracle:' } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'xUnit fact followed by a marked helper'; Path = 'dotnet/ATests.cs'; Content = "class ATests`n{`n    [Fact]`n    public void A()`n    {`n    }`n`n    void Helper() { } // oracle: property round-trip`n}`n"; Line = 3; Form = '// oracle:' } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
    ) {
        Set-RepoFile $Repo $Path $Content
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $Base

        $Result.Output | Should -Be @("${Path}:${Line}: new test has no '$Form' marker")
        $Result.ExitCode | Should -Be 1
    }

    It 'Accepts a new test with its marker <Name>' -ForEach @(
        @{ Name = 'on its It line'; Path = 'ci/a.Tests.ps1'; Content = "Describe 'd' {`n    It 'a' { `# oracle: property round-trip`n    }`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'above its It'; Path = 'ci/a.Tests.ps1'; Content = "Describe 'd' {`n    `# oracle: property round-trip`n    It 'a' {`n    }`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'on a -ForEach row'; Path = 'ci/a.Tests.ps1'; Content = "Describe 'd' {`n    It 'a <N>' -ForEach @(`n        @{ N = 1 } `# oracle: property round-trip`n    ) {`n    }`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'in its body after -ForEach hashtables'; Path = 'ci/a.Tests.ps1'; Content = "Describe 'd' {`n    It 'a <N>' -ForEach @(@{ N = 1 }, @{ N = 2 }) {`n        `$N | Should -BeGreaterThan 0 `# oracle: property round-trip`n    }`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'above its attributes'; Path = 'src/a.rs'; Content = "// oracle: property round-trip`n#[test]`nfn a() {}`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'in its body'; Path = 'src/a.rs'; Content = "#[test]`nfn a() {`n    // oracle: property round-trip`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'on a case row'; Path = 'src/a.rs'; Content = "#[rstest]`n#[case::empty(0)] // oracle: property round-trip`nfn a(#[case] n: u8) {}`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'in its body after a case spanning lines'; Path = 'src/a.rs'; Content = "#[rstest]`n#[case::one(`n    `"]`",`n)]`n#[tokio::test]`nasync fn a(#[case] s: &str) {`n    // oracle: property round-trip`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'in its body after a raw string holding a quote and a brace'; Path = 'src/a.rs'; Content = "#[test]`nfn a() {`n    let s = r#`"`"}`"#;`n    // oracle: property round-trip`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'in its body after a raw string spanning lines'; Path = 'src/a.rs'; Content = "#[test]`nfn a() {`n    let s = r`"`n}`n`";`n    // oracle: property round-trip`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'in its body after a fixed-size array parameter'; Path = 'src/a.rs'; Content = "#[rstest]`n#[case::four([1, 2, 3, 4])]`nfn parses(#[case] bytes: [u8; 4]) {`n    // oracle: property round-trip`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
        @{ Name = 'in its body after a C# interpolated string holding a brace'; Path = 'dotnet/ATests.cs'; Content = "class ATests`n{`n    [Fact]`n    public void A()`n    {`n        var text = `$`"{string.Join(`"}`", values)}`";`n        // oracle: property round-trip`n    }`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §languages
    ) {
        Set-RepoFile $Repo $Path $Content
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $Base

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Does not credit a new test with the marker above the next test' { # oracle: intent ci/check-oracle-markers.intent.md §languages
        Set-RepoFile $Repo 'src/a.rs' "#[test]`nfn a() {}`n// oracle: property round-trip`n#[test]`nfn b() {}`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $Base

        $Result.Output | Should -Be @("src/a.rs:1: new test has no '// oracle:' marker")
    }

    It 'Reports a new test named like an existing one in another file' { # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        Set-RepoFile $Repo 'src/a.rs' "#[test]`nfn old() {}`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $Base

        $Result.Output | Should -Be @("src/a.rs:1: new test has no '// oracle:' marker")
    }

    It 'Ignores an unmarked existing test after <Name>' -ForEach @(
        @{ Name = 'skipping a Pester test'; Path = 'ci/old.Tests.ps1'; Content = "Describe 'd' {`n    It 'old' -Skip {`n        1 | Should -Be 1`n    }`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'moving a Pester test to another file'; Path = 'ci/moved.Tests.ps1'; Content = "Describe 'd' {`n    It 'old' {`n        1 | Should -Be 1`n    }`n}`n"; Remove = 'ci/old.Tests.ps1' } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'skipping it'; Path = 'dotnet/OldTests.cs'; Content = "class OldTests`n{`n    [Fact(Skip = `"flaky`")]`n    public void Old() { }`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'making it async'; Path = 'src/old.rs'; Content = "#[tokio::test]`nasync fn old() {}`n" } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'wrapping it in a module'; Path = 'src/old.rs'; Content = "mod tests {`n    #[test]`n    fn old() {}`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'moving it to another file'; Path = 'src/old/tests.rs'; Content = "#[test]`nfn old() {}`n"; Remove = 'src/old.rs' } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
    ) {
        if ($Remove) {
            Remove-Item -LiteralPath (Join-Path $Repo $Remove)
        }
        Set-RepoFile $Repo $Path $Content
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $Base

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Exempts an existing unmarked test when <Name>' -ForEach @(
        @{ Name = 'a marked namesake joins its file'; Path = 'src/old.rs'; Content = "#[test]`nfn old() {}`n`nmod b {`n    #[test]`n    fn old() {} // oracle: property round-trip`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        @{ Name = 'a marked Pester namesake joins its file'; Path = 'ci/old.Tests.ps1'; Content = "Describe 'd' {`n    It 'old' {`n        1 | Should -Be 1`n    }`n}`n`nDescribe 'e' {`n    It 'old' { `# oracle: property round-trip`n    }`n}`n" } # oracle: intent ci/check-oracle-markers.intent.md §new-tests
    ) {
        Set-RepoFile $Repo $Path $Content
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $Base

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Reports a new unmarked namesake of an existing marked test' { # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        Set-RepoFile $Repo 'src/kept.rs' "#[test]`nfn kept() {} // oracle: property round-trip`n"
        Invoke-Git $Repo add -A
        Invoke-Git $Repo commit -q -m kept
        $KeptBase = (& git -C $Repo rev-parse HEAD)
        Set-RepoFile $Repo 'src/kept.rs' "#[test]`nfn kept() {} // oracle: property round-trip`n`nmod b {`n    #[test]`n    fn kept() {}`n}`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $KeptBase

        $Result.Output | Should -Be @("src/kept.rs:5: new test has no '// oracle:' marker")
    }

    It 'Ignores an unmarked test moved while a marked namesake is added elsewhere' { # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        Remove-Item -LiteralPath (Join-Path $Repo 'src/old.rs')
        Set-RepoFile $Repo 'src/moved.rs' "#[test]`nfn old() {}`n"
        Set-RepoFile $Repo 'src/z.rs' "#[test]`nfn old() {} // oracle: property round-trip`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $Base

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Reports only the added one of two unmarked namesakes' { # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        Set-RepoFile $Repo 'src/old.rs' "#[test]`nfn old() {}`n`nmod b {`n    #[test]`n    fn old() {}`n}`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $Base

        $Result.Output | Should -Be @("src/old.rs:5: new test has no '// oracle:' marker")
    }

    It 'Ignores an unmarked test that already existed at the base' { # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        Set-RepoFile $Repo 'src/old.rs' "#[test]`nfn old() {}`n`n#[test]`nfn new() {} // oracle: property round-trip`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $Base

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Skips new tests without a base' { # oracle: intent ci/check-oracle-markers.intent.md §new-tests
        Set-RepoFile $Repo 'src/a.rs' "#[test]`nfn a() {}`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }
}
