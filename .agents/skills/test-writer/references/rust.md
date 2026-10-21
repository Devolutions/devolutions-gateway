# Rust forms

Each rule in `SKILL.md` takes these forms in Rust.

Properties use `proptest`; the crate's existing strategies are the generators to reuse.
Fuzz targets live in `fuzz/`.

Snapshots use `expect-test`, whose `UPDATE_EXPECT=1` rewrites every stale value after a representation change.
Past a screen, a snapshot moves to a sibling file through `expect_file!`, and a blob through `include_bytes!`.

Cases are `rstest`, each named with `#[case::name]`.
A cross product is enum-valued `#[values]`, so each combination's name says what it checks.
A regression test is its own test function, not an `rstest` case, named for its issue.
