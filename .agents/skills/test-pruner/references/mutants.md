# cargo-mutants mechanics

cargo-mutants reports whether the suite caught each mutant.
It has no per-test attribution and no user-defined mutation operators, so both are built on its outputs.

## Baseline

```sh
cargo mutants --file 'crates/<crate>/src/<module>/**' --test-package <crate> --jobs 4
```

Outputs under `mutants.out/`: `caught.txt`, `missed.txt`, `unviable.txt`, `outcomes.json`, and `diff/` with one patch per mutant.
Use the same `--test-package` or `--test-workspace` for the baseline and every rerun; changing test scope makes mutants caught by another crate's tests appear missed.
Mutant names include a line number, so compare caught sets with the line number stripped.
Do not use `--iterate`; it skips mutants caught in previous runs, the opposite of a rerun.

## Kill matrix

For each caught mutant, record which flagged tests catch it.
One build per mutant is the cheap form:

```sh
for d in mutants.out/diff/*.diff; do
  git apply "$d"
  cargo test -p <crate> --no-run 2>/dev/null
  for t in $FLAGGED_TESTS; do
    cargo test -p <crate> -q -- --exact "$t" >/dev/null 2>&1 && echo "$d $t PASS" || echo "$d $t FAIL"
  done
  git checkout -- .
done
```

`FAIL` means the test caught the mutant.
A unique kill is a mutant caught by exactly one flagged test and by no unflagged test.
The floor is what the suite catches with all flagged tests skipped (`cargo mutants ... -- -- --skip <t1> --skip <t2>`); everything above the floor must stay covered by a retained test.

## Rerun

```sh
cargo mutants --file 'crates/<crate>/src/<module>/**' --test-package <crate> --baseline skip
```

Any mutant that moved from caught to missed without an approved deletion explaining it means revert.

## Domain mutants

Write each as a small patch; apply, run `cargo test -p <crate>`, revert; caught means any test failed.
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

Add every mutant the challenger produces that the rest of the suite misses.
