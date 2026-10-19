# Testsuite

New integration tests go in this crate's single test binary, so the suite links once and runs as one process.
A test either drives a shipped binary or exercises the public API of a library crate under `crates/`.
Drive the binary whenever the behaviour is reachable that way.

## Run the binary

Start Gateway, Agent, or jetsocat through `testsuite::cli` with a `DgwConfig::builder()` from `testsuite::dgw_config`, then drive it through its CLI, HTTP API, and WebSocket endpoints.
Use `disable_token_validation(true)` with an unsigned JWT instead of signing real tokens, except in tests of token validation itself, which the flag bypasses entirely.
When a behaviour cannot be reached from outside, add a small `__debug__` config knob or environment variable to the binary rather than linking the implementation.
`DgwConfig` picks unused ports itself; bind any other listener to `127.0.0.1:0` and read the port back, and take a port a binary needs up front from `test_utils::find_unused_ports`, because parallel tests collide on a fixed port.

## Dependencies are a design signal

A library crate under `crates/` is a contract and may be a dev-dependency when its public API is what the test checks.
The binary crates are not: wanting `devolutions-gateway`, `devolutions-agent`, `jetsocat`, or a web framework such as `axum` usually means one of:

- The test is a unit test and belongs in a `#[cfg(test)]` module next to the code.
- The binary needs a knob so the behaviour becomes reachable.
- The logic is generic and belongs in a shared crate such as `transport`, with its own unit tests.

Building a fake server in `src/` to mint an internal type is the pattern to avoid.
State in the pull request why a new dependency was unavoidable.

## Timing tests

Tests that assert a duration bound run serially, because concurrent tests inflate the measurement.
Put them in `tests/timing/` with `#[ignore = "run serially by the timing-sensitive CI step"]`.
A test that waits for a fixed delay is not a timing test.
If the delay runs in the test process, `#[tokio::test(start_paused = true)]` advances the clock past it instantly; if it runs in the binary, make it injectable.
