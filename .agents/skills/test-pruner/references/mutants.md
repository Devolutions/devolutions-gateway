# cargo-mutants mechanics

cargo-mutants reports whether the suite caught each mutant.
It has no user-defined mutation operators and keeps per-test results only in its logs, so both are built on its outputs.
These notes target cargo-mutants 27.1.

## Run

Scope with `--file '<package-dir>/src/<module>/**'` for a crate or module, or `--in-diff <diff>` for a pull request.
Package directories differ: `devolutions-gateway/src` sits at the repository root, while most libraries live under `crates/`.

```sh
cargo mutants --file '<path>' --test-package <test-package> --in-place --baseline skip --timeout <s> --build-timeout <s> -- --no-fail-fast <cargo-test-args>
```

The baseline phase ignores `--test-package` and tests the mutated package, so it fails when the tests live in `testsuite`.
Run the scoped tests once by hand instead, then skip the baseline and set both timeouts to a few times the measured test run and incremental build.
Arguments after `--` go to `cargo test`, and a second `--` reaches the test binary: `-- --no-fail-fast --test integration_tests -- websocket::` runs only the `websocket` tests of the `testsuite` binary.
`--no-fail-fast` keeps one failing test binary from hiding the results of the others.

The default mode copies the tree and cold-builds the workspace; `--in-place` reuses the warm `target/` and is much cheaper.
It mutates the worktree during the run, so read code with `git show HEAD:<path>` meanwhile, run no other cargo command against the same `target/`, and check `git status` afterwards.

Outputs under `mutants.out/`: `caught.txt`, `missed.txt`, `unviable.txt`, `outcomes.json`, `log/` with one log per mutant, and `diff/` with one patch per mutant.
Keep the same test scope and flags for every run; changing test scope makes mutants caught by other tests appear missed.
Mutant names include a line number, so compare caught sets with the line number stripped.
Do not use `--iterate`; it skips mutants caught in previous runs, the opposite of a rerun.

## Kill matrix

Each log holds the test harness output for its mutant, with one `ok` or `FAILED` line per test.
A test caught a mutant when its line reads `FAILED`, so parse the logs instead of rerunning tests:

```powershell
Get-ChildItem mutants.out/log/*.log | ForEach-Object {
    $mutant = $_.BaseName
    Select-String -Path $_.FullName -Pattern '^test (\S+) \.\.\. FAILED$' |
        ForEach-Object { "$mutant`t$($_.Matches[0].Groups[1].Value)" }
}
```

A unique kill is a mutant caught by exactly one test in scope.
For assertion-level evidence, read the `panicked at <file>:<line>` location of each failure; an assertion whose line never appears across its test's kills catches nothing the others miss.

## Rerun

Rerun with the same scope and flags after each change.
Any mutant that moved from caught to missed without an approved deletion explaining it means revert.

## Domain mutants

Write each as a small patch; apply, run the scoped tests, revert; caught means any test failed.
Patches are pull request evidence, not repository files.

Codec catalog:

- Swap endianness on one field read or write.
- Length prefix off by one in either direction.
- Remove one bounds check or remaining-length test.
- Wrong padding count, or padding read but not skipped.
- Swap two adjacent fields of the same type.
- Flip one bit in a flags field.
- Write one byte fewer than `size()` reports.
- Return `Ok` on a malformed-input branch that returns `Err`.
- Accept a reserved or out-of-range enum value.

Async and resource catalog:

- Remove or shorten a deadline.
- Detach a task instead of aborting it, or hold a `JoinHandle` where an abort-on-drop handle is required.
- Return early before a drain or flush.
- Swallow an error as `Ok`.
- Skip recording a state flag.
- Swap two status or close codes.

Add every mutant the challenger produces that the rest of the suite misses.
