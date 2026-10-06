# dvc-session-harness

`dvc-session-harness` is a Windows-only standalone tool for reproducing DVC establishment edge cases seen by RDM clients.
It intentionally does not reuse Devolutions Session runtime logic so production code stays untouched.

## What this simulates

It opens and closes the `Devolutions::Now::Agent` dynamic virtual channel with controlled timing.
This allows repeatable recreation of timeout windows and rapid channel churn without NetIQ.
Each action is logged with a millisecond Unix timestamp to align with RDM, agent, and session logs.

## Scenarios

- `open-hold`: open once, hold for `--open-ms`, then close.
- `timeout-window`: repeat open/hold/close cycles to emulate server-side negotiation windows.
- `delayed-open`: wait `--delay-ms` before starting `timeout-window` behavior.
- `no-open`: do not open DVC at all and only sleep for `--open-ms`.

## Usage

```powershell
cd tools/dvc-session-harness
cargo run --release -- timeout-window --cycles 6 --open-ms 5000 --gap-ms 200
```

```powershell
cargo run --release -- delayed-open --delay-ms 12000 --open-ms 5000
```

```powershell
cargo run --release -- no-open --open-ms 15000
```

## Log format

Events are emitted as plain text key/value lines.
The format is stable so scripts can parse it and correlate with customer traces.

Example:

```text
ts_ms=1791292800123 scenario=timeout-window cycle=2 event=open-success detail="channel opened"
```
