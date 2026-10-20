# Stryker.NET mechanics

Stryker.NET lists the tests that killed each mutant in its JSON report, but only when bail is disabled, so the kill matrix is read from the report; it has no user-defined mutation operators, so domain mutants are patches as `domain-mutants.md` describes.
These notes target Stryker.NET 5.0.0 with xUnit v2 on the VsTest runner.

## Install

In the solution directory, `dotnet new tool-manifest` then `dotnet tool install dotnet-stryker`; the manifest it writes is a repository file, not output, so leave it untracked unless the pull request adopts it.

## Run

Run the clean suite first with a TRX log, because the report names tests by id and the TRX carries the id with the display name:

```powershell
dotnet test <TestProject>.csproj --logger "trx;LogFileName=clean.trx" --results-directory <scratch-dir>/trx
```

Then, from the test project directory:

```powershell
dotnet stryker --mutate "**/<Module>/*.cs" --disable-bail --break-on-initial-test-failure --reporter json --reporter cleartext --output <scratch-dir> --skip-version-check
```

`--mutate` takes several globs, `!<glob>` excludes, and `<file>.cs{<start>..<end>}` limits to a character span; Stryker mutates the whole project in memory before filtering, so compile-error warnings about files outside the scope are noise.
`--disable-bail` runs every covering test to completion; by default Stryker aborts a mutant's run at the first failure, and `killedBy` then holds only the tests that had failed by then, a partial list that makes kills look unique.
`--break-on-initial-test-failure` stops the run when the clean suite fails, which a test edit can cause, because a matrix built over failing tests proves nothing.
For a change's diff, add `--since:<branch, tag, or full SHA>`; a revision expression such as `HEAD~1` or an abbreviated SHA is rejected.
A test-only diff still yields mutants under `--since`: every mutant covered by a test in a changed test file counts as changed.
Pass `--project <Name>.csproj` only when the test project references more than one project.
Coverage analysis, `perTest` by default, runs only the tests covering each mutant, so the matrix spans the whole test project without scoping tests and a unique kill is unique across the project; restricting to a test class needs `test-case-filter` in `stryker-config.json`, since the 5.0.0 command line rejects it as a flag.
Stryker builds the test project itself and writes a `.gitignore` of `*` into `--output`, so the output stays untracked wherever it is.
Build and the initial run take a few minutes before the first mutant, so scope first; timeouts are computed per mutant from the initial run, and `additional-timeout` and `timeout-ratio` are config-file options.

## Kill matrix

`<scratch-dir>/reports/mutation-report.json` holds `files[<path>].mutants[]` with `id`, `mutatorName`, `replacement`, `location`, `status` (`Killed`, `Survived`, `NoCoverage`, `Timeout`, `CompileError`, `Ignored`), and `coveredBy` and `killedBy` lists of test ids, and `testFiles[<path>].tests[]` with `id` and `name`.
`name` is the method's qualified name without arguments, so every row of a `[Theory]` shares one name; `id` is the VsTest test case id, which the TRX carries as `UnitTest/@id` with the display name and arguments.
Key on the id throughout: display names collide when xUnit truncates long string arguments.

```powershell
$report = Get-Content -Raw <scratch-dir>/reports/mutation-report.json | ConvertFrom-Json
[xml]$trx = Get-Content -Raw <scratch-dir>/trx/clean.trx
$name = @{}
foreach ($t in $trx.TestRun.TestDefinitions.UnitTest) { $name[$t.id] = $t.name }
$report.files.PSObject.Properties | Where-Object Name -like '*<Module>*' | ForEach-Object {
    foreach ($m in $_.Value.mutants | Where-Object status -eq 'Killed') {
        foreach ($id in $m.killedBy) { "$($m.id)`tL$($m.location.start.line) $($m.mutatorName): $($m.replacement)`t$($name[$id])" }
    }
}
```

A unique kill is a mutant whose `killedBy` has one entry.
A test in `coveredBy` of mutants it never kills catches none of them.
Rows of a `[MemberData]` theory whose arguments xUnit cannot serialize share one id, so the matrix cannot tell them apart; give such rows a string key.
Stryker keeps no per-test output, so for assertion-level evidence apply the mutant by hand from `location` and `replacement`, run the killing test with `dotnet test --filter "FullyQualifiedName~<Class>.<Method>"`, and read the failing assertion from the stack trace.
Mutant ids are assigned in order over the whole project, so an edit anywhere can renumber them, and lines shift with edits above; across runs match mutants by file, `mutatorName`, `replacement`, and the text of the mutated line in `files[<path>].source`.

## Rerun

Refresh the clean run and its TRX, then rerun with the same `--mutate` globs and flags after each change.
Do not use `--with-baseline`; it reuses results for mutants it considers unchanged, the opposite of a rerun.
Keep `mutation-level`, `--mutate` and any `test-case-filter` identical between the runs you compare: a run at another level or over a filtered test set reports a different mutant population, not a different suite.

## Pitfalls

Verify a surprising status by applying the mutant by hand: Stryker can report as survived a mutant in a static initializer, whose value is computed before the mutant switches on, or a replacement that would not compile on its own, and a machine at full load turns slow kills into timeouts.
A whole library of about 6,000 lines gave 1,724 mutants and ran in 48 minutes at `--concurrency 12`, so a pull request's pass scopes with `--since` or `--mutate` first.
A domain mutant that makes a member public must add an XML doc comment where documentation warnings are errors, or it fails to compile and proves nothing.
Patches written on Windows may carry CRLF; convert them to LF before `git apply` in a repository whose `.gitattributes` sets `eol=lf`.

## Consolidation forms

Cases are `[Theory]` with `[InlineData]` rows for literal data, whose display name carries the arguments, or `[MemberData(nameof(<Member>))]` keyed by a string per row for other data, so a failure names the row.
Properties are CsCheck: compose `Gen<T>` with LINQ, keep each type's generator in one static class of the test project so it is written once, and `Sample` reports a seed on failure to replay through `seed:` or `CsCheck_Seed`.
CsCheck over FsCheck because its generators shrink without per-type shrinkers, so a composed generator costs one declaration like a proptest strategy, and because it adds no FSharp.Core to a C# test project.
