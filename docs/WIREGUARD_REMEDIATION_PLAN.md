# WireGuard Agent Remediation Plan

This document tracks the remaining end-to-end hardening and cleanup work for the WireGuard agent routing feature.

## Scope

The following items are in scope for this pass:

- Protect `/jet/agents` with an authenticated diagnostics scope.
- Constrain agent-side `CONNECT` targets so the agent only dials addresses it has advertised.
- Keep agent routing opt-in: sessions without `jet_agent_id` must stay on the regular direct Gateway path.
- Remove the `VirtualTcpStream` receiver mutex misuse.
- Add backpressure to gateway-to-agent relay writes instead of using an unbounded queue.
- Avoid blocking the WireGuard listener event loop on slow virtual stream consumers.
- Clean up agent stream state when TCP write or read paths fail.
- Reduce per-packet logging noise on the WireGuard UDP path.
- Remove duplicated `ServerStream` routing glue shared by `fwd.rs` and `generic_client.rs`.
- Zeroize temporary private key material after loading it from configuration.

## Sequencing

1. Secure the control plane.
   Add authenticated access to `/jet/agents`.
   Add agent-side target validation before opening TCP connections.

2. Fix gateway stream correctness.
   Replace the receiver mutex with direct ownership.
   Replace the unbounded outbound queue with bounded backpressure-aware sending.
   Ensure relay dispatch from the listener does not await on slow consumers.

3. Fix agent stream cleanup.
   Remove orphaned `active_streams` entries when write paths fail.
   Notify the gateway when the agent tears down a stream because of a local TCP failure.

4. Remove duplicated routing glue.
   Extract the shared `ServerStream` abstraction and shared route selection logic.

5. Verify and document.
   Run targeted Rust and TypeScript checks.
   Run the multi-agent Docker end-to-end harness, including reconnect takeover.
   Update documentation and the local knowledge base to reflect the final behavior.

## Acceptance Criteria

- `/jet/agents` rejects unauthenticated access.
- Agent `CONNECT` requests fail if the destination is outside the agent's advertised IPv4 subnets.
- Sessions without `jet_agent_id` never auto-route through an agent.
- `VirtualTcpStream` no longer wraps its receiver in a blocking mutex.
- Gateway-to-agent relay writes use bounded buffering with explicit backpressure.
- The listener event loop no longer awaits on per-stream delivery to virtual streams.
- Agent write/read failures release stream state and notify the gateway.
- UDP packet receipt logging is not emitted at `info!` level per packet.
- `fwd.rs` and `generic_client.rs` share one `ServerStream` abstraction instead of duplicating it.
- Temporary private key buffers are zeroized after configuration loading.
- `cargo +nightly fmt --all`, targeted `cargo check`, targeted TypeScript checks, and the multi-agent WireGuard end-to-end test all pass.
