# Testsuite

This crate exercises the shipped binaries the way users and CI do.
It is not the place to re-test library internals.

## Run the binary

Start Gateway, Agent, or jetsocat through `testsuite::cli` with a `DgwConfig::builder()` from `testsuite::dgw_config`, then drive it through its CLI, HTTP API, and WebSocket endpoints.
Use `disable_token_validation(true)` with an unsigned JWT instead of signing real tokens.
When a behaviour cannot be reached from outside, add a small `__debug__` config knob or environment variable to the binary rather than linking the implementation.

## Dependencies are a design signal

The testsuite depends on the binaries' public surface and on generic tooling, not on the crates that implement them.
Wanting `axum`, `devolutions-gateway`, `agent-tunnel`, or another internal crate usually means one of:

- The test is a unit test and belongs in a `#[cfg(test)]` module next to the code, where those crates already are.
- The binary needs a knob so the behaviour becomes reachable.
- The logic is generic and belongs in a shared crate such as `transport`, with its own unit tests.

Building a fake server in `src/` to mint an internal type is the pattern to avoid.
State in the pull request why a new dependency was unavoidable.

## Fewer, stronger tests

Before adding a test, name the bug it catches that existing tests miss and the independent source for its expected value.
A test whose expected value was derived from the implementation detects change, not bugs; run the `test-oracle-reviewer` skill on new tests.
Use `rstest` with named cases when tests check the same property and differ only in data.
Use `proptest` only for a real property such as a round-trip; a property that re-implements the unit adds nothing.
A test that must wait on the wall clock belongs in `tests/timing/` behind `#[ignore]`.
