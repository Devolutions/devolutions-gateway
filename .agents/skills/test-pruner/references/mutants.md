# cargo-mutants mechanics

cargo-mutants reports whether the suite caught each mutant.
It has no user-defined mutation operators and keeps per-test results only in its logs, so both are built on its outputs.
These notes target cargo-mutants 27.1.

## Run

Scope with `--file '<package-dir>/src/<module>/**'` for a crate or module, `--re '<fn>|<fn>'` for a pull request's changed functions, or `--in-diff <diff>` for its whole diff; build time dominates, so scope first.
Package directories differ: `devolutions-gateway/src` sits at the repository root, while most libraries live under `crates/`.

```sh
cargo mutants --file '<path>' --test-package <test-package> --in-place --baseline skip --timeout <s> --build-timeout <s> -- --no-fail-fast <cargo-test-args>
```

The baseline phase ignores `--test-package` and tests the mutated package, so it fails when the tests live in `testsuite`.
Run the scoped tests once by hand instead, then skip the baseline and set both timeouts to a few times the measured test run and incremental build.
Arguments after `--` go to `cargo test`, and a second `--` reaches the test binary: `-- --no-fail-fast --test integration_tests -- websocket::` runs only the `websocket` tests of the `testsuite` binary.
`--no-fail-fast` keeps one failing test binary from hiding the results of the others.
Pass `--features <f>` for feature-gated code; without it that code gets no mutants and nothing warns.
Pass `--output <scratch-dir>` so `mutants.out` stays out of the checkout.

The default mode copies the tree and cold-builds the workspace; `--in-place` reuses the warm `target/` and is much cheaper.
It mutates the worktree during the run, so read code with `git show HEAD:<path>` meanwhile, run no other cargo command against the same `target/`, and check `git status` afterwards.

Outputs under `mutants.out/`: `caught.txt`, `missed.txt`, `unviable.txt`, `outcomes.json`, `log/` with one log per mutant, and `diff/` with one patch per mutant.
Keep the same test scope and flags for every run; changing test scope makes mutants caught by other tests appear missed.
Key mutants by their full name from `outcomes.json`; stripping line numbers merges distinct mutants, and test-only edits do not move source lines.
Do not use `--iterate`; it skips mutants caught in previous runs, the opposite of a rerun.
Read `unviable.txt`: when a function returns through a `Result` type alias, cargo-mutants cannot build its `Ok` replacement and drops it there without warning, so add that mutant by hand; for a check, "always `Ok`" is the mutant that matters most.
Patches in `mutants.out/diff/` carry the mutant description in their `+++` line; to apply one, rewrite that line to the path and use `git apply -p0`.

## Kill matrix

Each log holds the test harness output for its mutant, with one `ok` or `FAILED` line per test.
A test caught a mutant when its line reads `FAILED`, so parse the logs instead of rerunning tests.
Key the matrix on `outcomes.json`, which maps each mutant name to its log; log file names do not distinguish mutants at the same position.
A mutant caught by timeout has no per-test result, so rerun its tests one at a time.
Run from the directory that contains `mutants.out`:

```powershell
(Get-Content -Raw mutants.out/outcomes.json | ConvertFrom-Json).outcomes |
    Where-Object { $_.scenario.Mutant -and $_.summary -in 'CaughtMutant', 'Timeout' } |
    ForEach-Object {
        $mutant = $_.scenario.Mutant.name
        $failed = Select-String -Path "mutants.out/$($_.log_path)" -Pattern '^test (\S+) \.\.\. FAILED$' |
            ForEach-Object { $_.Matches[0].Groups[1].Value }
        if (-not $failed) { "$mutant`t<$($_.summary): no per-test result, rerun tests individually>" }
        $failed | ForEach-Object { "$mutant`t$_" }
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

Decision and validation catalog, for each security or policy decision: remove it, weaken it, key it on the wrong identity, or apply it to the wrong object.

- Always return `Ok` from the check.
- Accept any candidate by dropping a filter.
- Look up by the wrong key, such as a name hash instead of a thumbprint.
- Stop after the first candidate.
- Ignore one input source, such as caller-provided roots.
- Skip verification of a candidate's chain.
- Swap error precedence or report the wrong error.

Add every mutant the challenger produces that the rest of the suite misses.
