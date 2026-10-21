# oracle: spec .agents/skills/test-oracle-reviewer/SKILL.md §Markers

BeforeAll {
    $Script = Join-Path $PSScriptRoot 'check-oracle-markers.ps1'

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
                if ($Files -and $Files.ContainsKey($Path)) {
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
        @{ Name = 'a named spec'; Marker = 'spec RFC 6455 §5.2' }
        @{ Name = 'a named spec with a slash'; Marker = 'spec ISO/IEC 8825-1 §8.1' }
        @{ Name = 'a named spec with a dot'; Marker = 'spec ITU-T X.690 §8.1' }
        @{ Name = 'a spec under docs/'; Marker = 'spec docs/JMUX-spec.md §Channels' }
        @{ Name = 'a contract section by number'; Marker = 'contract api/CONTRACT.md §3.2' }
        @{ Name = 'a contract section by title in another case'; Marker = 'contract api/CONTRACT.md §3.2 framing' }
        @{ Name = 'a contract section by anchor'; Marker = 'contract api/CONTRACT.md §framing' }
        @{ Name = 'an INTENT.md section'; Marker = 'intent crates/x/INTENT.md §Invariants' }
        @{ Name = 'a .intent.md section'; Marker = 'intent src/recording.intent.md §Artifacts' }
        @{ Name = 'a Jira regression'; Marker = 'regression DGW-123 empty header' }
        @{ Name = 'a pull request regression'; Marker = 'regression #2136' }
        @{ Name = 'another repository''s issue'; Marker = 'regression Devolutions/IronRDP#12' }
        @{ Name = 'a committed fuzz crash file'; Marker = 'regression fuzz/artifacts/jmux/crash-1' }
        @{ Name = 'a reference'; Marker = 'reference FreeRDP capture' }
        @{ Name = 'the round-trip law'; Marker = 'property round-trip' }
        @{ Name = 'the monotonic law'; Marker = 'property monotonic' }
        @{ Name = 'a mutant'; Marker = 'mutant dropping the length check' }
    ) {
        $Repo = New-Repo
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {} // oracle: $Marker`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Rejects <Name>' -ForEach @(
        @{ Name = 'scaffold'; Marker = 'scaffold'; Message = "'scaffold' marker must not merge" }
        @{ Name = 'a marker without a kind'; Marker = ''; Message = 'marker has no kind' }
        @{ Name = 'an unknown kind'; Marker = 'specification RFC 6455 §5.2'; Message = "unknown oracle kind 'specification'" }
        @{ Name = 'a kind in another case'; Marker = 'Spec RFC 6455 §5.2'; Message = "unknown oracle kind 'Spec'" }
        @{ Name = 'a kind without a reference'; Marker = 'reference'; Message = "'reference' marker has no reference" }
        @{ Name = 'a property in words'; Marker = 'property decode inverts encode'; Message = "'property decode inverts encode' is not a well-known law" }
        @{ Name = 'a law in another case'; Marker = 'property Round-trip'; Message = "'property Round-trip' is not a well-known law" }
        @{ Name = 'a law with more words'; Marker = 'property round-trip of encode'; Message = "'property round-trip of encode' is not a well-known law" }
        @{ Name = 'a spec without a section'; Marker = 'spec RFC 6455'; Message = "'spec' marker needs '<document> §<section>'" }
        @{ Name = 'a spec URL'; Marker = 'spec https://github.com/Devolutions/devolutions-gateway/blob/master/docs/JMUX-spec.md §Channels'; Message = 'looks like a URL or a path' }
        @{ Name = 'a spec at a branch'; Marker = 'spec Devolutions/devolutions-gateway@master docs/JMUX-spec.md §Channels'; Message = 'looks like a URL or a path' }
        @{ Name = 'a spec path in another case'; Marker = 'spec Docs/JMUX-spec.md §Channels'; Message = 'looks like a URL or a path' }
        @{ Name = 'a spec path outside docs/'; Marker = 'spec crates/jmux-proto/SPEC.md §Channels'; Message = 'looks like a URL or a path' }
        @{ Name = 'a missing spec under docs/'; Marker = 'spec docs/JET.md §Header'; Message = "spec file 'docs/JET.md' is not tracked" }
        @{ Name = 'a missing spec section under docs/'; Marker = 'spec docs/JMUX-spec.md §Sessions'; Message = "spec file 'docs/JMUX-spec.md' has no section 'Sessions'" }
        @{ Name = 'a contract that is not a CONTRACT*.md'; Marker = 'contract api/README.md §Framing'; Message = "contract 'api/README.md' is not a CONTRACT*.md file" }
        @{ Name = 'a missing contract'; Marker = 'contract web/CONTRACT.md §Framing'; Message = "contract file 'web/CONTRACT.md' is not tracked" }
        @{ Name = 'a contract path relative to the test'; Marker = 'contract CONTRACT.md §3.2'; Message = "contract file 'CONTRACT.md' is not tracked" }
        @{ Name = 'a missing contract section'; Marker = 'contract api/CONTRACT.md §3.3'; Message = "contract file 'api/CONTRACT.md' has no section '3.3'" }
        @{ Name = 'a heading number prefix'; Marker = 'contract api/CONTRACT.md §3'; Message = "has no section '3'" }
        @{ Name = 'an anchor in another case'; Marker = 'contract api/CONTRACT.md §FRAMING'; Message = "has no section 'FRAMING'" }
        @{ Name = 'a missing intent section'; Marker = 'intent crates/x/INTENT.md §Goals'; Message = "intent file 'crates/x/INTENT.md' has no section 'Goals'" }
        @{ Name = 'a heading inside a code fence'; Marker = 'intent crates/x/INTENT.md §Fenced'; Message = "has no section 'Fenced'" }
        @{ Name = 'an intent that is not an intent file'; Marker = 'intent docs/JMUX-spec.md §Channels'; Message = "is not an INTENT*.md or *.intent*.md file" }
        @{ Name = 'a regression in words'; Marker = 'regression the crash from last week'; Message = "regression reference 'the' is not a Jira key" }
        @{ Name = 'a missing fuzz crash file'; Marker = 'regression fuzz/artifacts/jmux/crash-2'; Message = "regression reference 'fuzz/artifacts/jmux/crash-2'" }
        @{ Name = 'an ignored fuzz crash file, which CI never sees'; Marker = 'regression fuzz/artifacts/jmux/crash-ignored'; Message = "regression reference 'fuzz/artifacts/jmux/crash-ignored'" }
    ) {
        $Repo = New-Repo
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {}`n// oracle: $Marker`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -HaveCount 1
        $Result.Output[0] | Should -BeLike "src/lib.rs:2: *$Message*"
        $Result.ExitCode | Should -Be 1
    }

    It 'Ignores oracle: after the // of a URL' {
        $Repo = New-Repo
        Set-RepoFile $Repo 'src/lib.rs' "const URL: &str = `"http://oracle:8080/x`";`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Checks markers in C# files and Rust doctests' {
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
        @{ Name = 'a section by number'; Marker = 'contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §6' }
        @{ Name = 'a section by anchor'; Marker = 'contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §agent-id' }
        @{ Name = 'a section of a file with CRLF line endings'; Marker = 'contract Org/specs@43958682a1b2:docs/CONTRACT.crlf.md §6' }
        @{ Name = 'a spec at a full SHA'; Marker = 'spec Org/specs@43958682a1b20000000000000000000000000000:docs/README.md §7 Other' }
    ) {
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {} // oracle: $Marker`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo -GitHubApi $GitHub

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Rejects <Name>' -ForEach @(
        @{ Name = 'an unpinned reference'; Marker = 'contract Org/specs:docs/CONTRACT.specs.md §6'; Message = "'contract' marker must pin a commit SHA" }
        @{ Name = 'a branch pin'; Marker = 'contract Org/specs@main:docs/CONTRACT.specs.md §6'; Message = "'contract' marker must pin a commit SHA" }
        @{ Name = 'a pin shorter than 12 digits'; Marker = 'contract Org/specs@43958682a1b:docs/CONTRACT.specs.md §6'; Message = "'contract' marker must pin a commit SHA" }
        @{ Name = 'an unpinned reference to an unreadable repository'; Marker = 'intent Org/secret@v1.2:INTENT.md §Goals'; Message = "'intent' marker must pin a commit SHA" }
        @{ Name = 'an unknown commit'; Marker = 'contract Org/specs@0123456789ab:docs/CONTRACT.specs.md §6'; Message = "'0123456789ab' is not a commit of Org/specs" }
        @{ Name = 'a branch named like a SHA'; Marker = 'contract Org/specs@deadbeefcafe:docs/CONTRACT.specs.md §6'; Message = "'deadbeefcafe' is not a commit of Org/specs" }
        @{ Name = 'a missing file'; Marker = 'contract Org/specs@43958682a1b2:docs/CONTRACT.other.md §6'; Message = "'docs/CONTRACT.other.md' does not exist in Org/specs at 43958682a1b2" }
        @{ Name = 'a missing section'; Marker = 'contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §8'; Message = "'docs/CONTRACT.specs.md' in Org/specs at 43958682a1b2 has no section '8'" }
        @{ Name = 'a contract that is not a CONTRACT*.md'; Marker = 'contract Org/specs@43958682a1b2:docs/README.md §6'; Message = "contract 'docs/README.md' is not a CONTRACT*.md file" }
    ) {
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {}`n// oracle: $Marker`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo -GitHubApi $GitHub

        $Result.Output | Should -HaveCount 1
        $Result.Output[0] | Should -BeLike "src/lib.rs:2: *$Message*"
        $Result.ExitCode | Should -Be 1
    }

    It 'Checks only the syntax of a pinned reference to a repository the token cannot read' {
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {} // oracle: contract Org/secret@43958682a1b2:docs/CONTRACT.md §6`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo -GitHubApi $GitHub

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Checks only the syntax of a pinned reference to an organization that has not authorized the token' {
        $Saml = { param($Endpoint, $Accept) [pscustomobject]@{ Status = 403; Body = '{"message":"Resource protected by organization SAML enforcement."}' } }
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {} // oracle: contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §6`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo -GitHubApi $Saml

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Stops on <Name> rather than skip every pin' -ForEach @(
        @{ Name = 'a bad token'; Status = 401; Body = '{"message":"Bad credentials"}' }
        @{ Name = 'a rate limit'; Status = 403; Body = '{"message":"API rate limit exceeded for user ID 1."}' }
        @{ Name = 'a secondary rate limit'; Status = 429; Body = '{"message":"You have exceeded a secondary rate limit."}' }
    ) {
        $Failing = { param($Endpoint, $Accept) [pscustomobject]@{ Status = $Status; Body = $Body } }.GetNewClosure()
        Set-RepoFile $Repo 'src/lib.rs' "fn f() {} // oracle: contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §6`n"
        Invoke-Git $Repo add -A

        { Invoke-Check $Repo -GitHubApi $Failing } | Should -Throw "*returned ${Status}*"
    }

    It 'Fetches a pinned file once for several markers' {
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
        @{ Name = 'unchanged'; Head = "# Specs, revised`n`n<a id=`"agent-id`"></a>`n## 6 Agent identity`n`nAgents present a key.`n"; Status = 'unchanged: bump the pin to b0b0b0b0b0b0' }
        @{ Name = 'changed'; Head = "# Specs`n`n## 6 Agent identity`n`nAgents present a certificate.`n"; Status = 'changed on main; re-check the test against the new text' }
        @{ Name = 'renamed'; Head = "# Specs`n`n## 6 Agent keys`n`nAgents present a key.`n"; Status = "moved: the section is now '6 Agent keys' on main; re-check the test" }
        @{ Name = 'removed'; Head = "# Specs`n`n## 7 Other`n"; Status = 'removed: §6 no longer resolves on main; re-check the test' }
        @{ Name = 'gone with its file'; Head = $null; Status = "removed: 'docs/CONTRACT.specs.md' no longer exists on main; re-check the test" }
    ) {
        $HeadFiles = if ($Head) { @{ 'docs/CONTRACT.specs.md' = $Head } } else { @{} }
        $GitHub = New-FakeGitHub @{
            'Org/specs' = @{ Default = 'main'; Branches = @{ main = $PinB }; Commits = @{ $PinA = @{ 'docs/CONTRACT.specs.md' = $Contract }; $PinB = $HeadFiles } }
        }

        $Result = Invoke-Check $Repo -GitHubApi $GitHub -DriftReport

        $Result.Output | Should -Contain "| src/lib.rs:3 (agent_presents_key) | contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §6 | $Status |"
        $Result.ExitCode | Should -Be 0
    }

    It 'Resolves an anchor before a heading of the same text' {
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

    It 'Groups the report by repository' {
        Set-RepoFile $Repo 'src/other.rs' "#[test] // oracle: intent Org/agent@b0b0b0b0b0b0:INTENT.md §Goals`nfn goals() {}`n"
        Invoke-Git $Repo add -A
        $GitHub = New-FakeGitHub @{
            'Org/specs' = @{ Default = 'main'; Branches = @{ main = $PinA }; Commits = @{ $PinA = @{ 'docs/CONTRACT.specs.md' = $Contract } } }
            'Org/agent' = @{ Default = 'master'; Branches = @{ master = $PinB }; Commits = @{ $PinB = @{ 'INTENT.md' = "# Goals`n" } } }
        }

        $Result = Invoke-Check $Repo -GitHubApi $GitHub -DriftReport

        $Result.Output | Where-Object { $_ -like '### *' } | Should -Be @('### Org/agent', '### Org/specs')
        $Result.Output | Should -Contain '| src/other.rs:1 (goals) | intent Org/agent@b0b0b0b0b0b0:INTENT.md §Goals | current: pinned to the head of master |'
    }

    It 'Marks a pinned reference to a repository the token cannot read as skipped' {
        $Result = Invoke-Check $Repo -DriftReport

        $Result.Output | Should -Contain '| src/lib.rs:3 (agent_presents_key) | contract Org/specs@43958682a1b2:docs/CONTRACT.specs.md §6 | skipped: the token cannot read this repository |'
    }
}

Describe 'New tests' {
    BeforeEach {
        $Repo = New-Repo
        Set-RepoFile $Repo 'src/old.rs' "#[test]`nfn old() {}`n"
        Set-RepoFile $Repo 'dotnet/OldTests.cs' "class OldTests`n{`n    [Fact]`n    public void Old() { }`n}`n"
        Invoke-Git $Repo add -A
        Invoke-Git $Repo commit -q -m tests
        $Base = (& git -C $Repo rev-parse HEAD)
    }

    It 'Reports a new <Name> without a marker at its test attribute' -ForEach @(
        @{ Name = 'Rust test'; Path = 'src/a.rs'; Content = "fn helper() {}`n`n#[test]`nfn a() {`n    assert!(true);`n}`n"; Line = 3 }
        @{ Name = 'tokio test'; Path = 'src/a.rs'; Content = "#[tokio::test(flavor = `"multi_thread`")]`nasync fn a() {}`n"; Line = 1 }
        @{ Name = 'rstest with a tokio test'; Path = 'src/a.rs'; Content = "#[rstest]`n#[tokio::test]`nasync fn a() {}`n"; Line = 1 }
        @{ Name = 'xUnit fact'; Path = 'dotnet/ATests.cs'; Content = "class ATests`n{`n    [Fact]`n    public void A() { }`n}`n"; Line = 3 }
        @{ Name = 'xUnit theory'; Path = 'dotnet/ATests.cs'; Content = "class ATests`n{`n    [Theory]`n    [InlineData(1)]`n    public void A(int x) { }`n}`n"; Line = 3 }
    ) {
        Set-RepoFile $Repo $Path $Content
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $Base

        $Result.Output | Should -Be @("${Path}:${Line}: new test has no '// oracle:' marker")
        $Result.ExitCode | Should -Be 1
    }

    It 'Accepts a new test with its marker <Name>' -ForEach @(
        @{ Name = 'above its attributes'; Content = "// oracle: property round-trip`n#[test]`nfn a() {}`n" }
        @{ Name = 'in its body'; Content = "#[test]`nfn a() {`n    // oracle: property round-trip`n}`n" }
        @{ Name = 'on a case row'; Content = "#[rstest]`n#[case::empty(0)] // oracle: property round-trip`nfn a(#[case] n: u8) {}`n" }
    ) {
        Set-RepoFile $Repo 'src/a.rs' $Content
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $Base

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Does not credit a new test with the marker above the next test' {
        Set-RepoFile $Repo 'src/a.rs' "#[test]`nfn a() {}`n// oracle: property round-trip`n#[test]`nfn b() {}`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $Base

        $Result.Output | Should -Be @("src/a.rs:1: new test has no '// oracle:' marker")
    }

    It 'Reports a new test named like an existing one in another file' {
        Set-RepoFile $Repo 'src/a.rs' "#[test]`nfn old() {}`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $Base

        $Result.Output | Should -Be @("src/a.rs:1: new test has no '// oracle:' marker")
    }

    It 'Ignores an unmarked existing test after <Name>' -ForEach @(
        @{ Name = 'skipping it'; Path = 'dotnet/OldTests.cs'; Content = "class OldTests`n{`n    [Fact(Skip = `"flaky`")]`n    public void Old() { }`n}`n" }
        @{ Name = 'making it async'; Path = 'src/old.rs'; Content = "#[tokio::test]`nasync fn old() {}`n" }
        @{ Name = 'wrapping it in a module'; Path = 'src/old.rs'; Content = "mod tests {`n    #[test]`n    fn old() {}`n}`n" }
        @{ Name = 'moving it to another file'; Path = 'src/old/tests.rs'; Content = "#[test]`nfn old() {}`n"; Remove = 'src/old.rs' }
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

    It 'Ignores an unmarked test that already existed at the base' {
        Set-RepoFile $Repo 'src/old.rs' "#[test]`nfn old() {}`n`n#[test]`nfn new() {} // oracle: property round-trip`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo $Base

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }

    It 'Skips new tests without a base' {
        Set-RepoFile $Repo 'src/a.rs' "#[test]`nfn a() {}`n"
        Invoke-Git $Repo add -A

        $Result = Invoke-Check $Repo

        $Result.Output | Should -BeNullOrEmpty
        $Result.ExitCode | Should -Be 0
    }
}
