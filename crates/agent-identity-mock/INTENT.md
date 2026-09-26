# Mock authority

This binary is a reference authority for the conformance tester.
It implements, exactly as [CONTRACT.md](../../docs/agent-identity/CONTRACT.md) specifies:

- the agent-facing operations;
- the agent channel defined in `agent-channel-proto`;
- the DVLS admin API: tokens, devices, revocation, deletion, request-renewal, root rotation.

## Independent derivation

- The mock depends on no agent crate other than `agent-channel-proto`.
- It does not reuse the agent's request and response types, or its signing code.
- It verifies signatures and channel proofs with its own oracle, written from the contract, not with the `httpsig` crate the agent signs with.
  A signature-base bug shared by both sides would otherwise pass the suite.
- The oracle is self-contained and LLM-owned: pure functions, no I/O, time passed in, and no dependency on the rest of the mock.
  Humans treat it as a black box; trust in it comes from its narrow API and from the shared test vectors it must pass.

If the mock and the agent shared an interpretation of the contract, the conformance suite could not detect a misreading of it.

## Mock-only control

A separate control surface allows:

- fault injection: dropped or failed responses, clock skew, short certificate lifetimes, an unavailable or broken channel;
- moving the mock clock;
- an ordered log of channel and certificate events.

This control surface is never part of the contract.

Several instances can run side by side, to exercise multiple authorities.
The mock serves under a configurable path prefix, to exercise authorities hosted in a virtual directory.
