# dvc-session-harness

`dvc-session-harness` is a Windows-only standalone tool for reproducing DVC establishment edge cases seen by RDM clients.
It intentionally does not reuse Devolutions Session runtime logic so production code stays untouched.

## What this simulates

It opens and closes the `Devolutions::Now::Agent` dynamic virtual channel with controlled timing.
This allows repeatable recreation of timeout windows and rapid channel churn without NetIQ.
Each action is logged with a millisecond Unix timestamp to align with RDM, agent, and session logs.
The harness supports Ctrl+C and exits cleanly.

## Scenarios

- `open-hold`: open once, hold for `--open-ms`, then close.
- `timeout-window`: repeat open/hold/close cycles to emulate server-side negotiation windows.
- `delayed-open`: wait `--delay-ms` before starting `timeout-window` behavior.
- `no-open`: do not open DVC at all and only sleep for `--open-ms`.

## Protocol shim modes

- `none` (default): open/close behavior only.
- `minimal`: send a server capset and periodic heartbeats while the channel is open.

Minimal shim mode is useful when you want RDM to stay attached longer instead of failing immediately with “agent not available”.

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

```powershell
cargo run --release -- timeout-window --cycles 200 --open-ms 5000 --gap-ms 200 --wait-for-open-ms 300000 --retry-interval-ms 250
```

Use `--wait-for-open-ms` when launch/reconnect timing is unpredictable.
With this mode, the harness keeps retrying DVC open within each cycle instead of exiting on the first `0x8007001F`.

```powershell
cargo run --release -- timeout-window --protocol-shim minimal --cycles 200 --open-ms 5000 --gap-ms 200 --wait-for-open-ms 300000 --retry-interval-ms 250 --heartbeat-ms 3000
```

## Log format

Events are emitted as plain text key/value lines.
The format is stable so scripts can parse it and correlate with customer traces.

Example:

```text
ts_ms=1791292800123 scenario=timeout-window cycle=2 event=open-success detail="channel opened"
```
