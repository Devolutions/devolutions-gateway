This library holds everything every authority must do the same way under `docs/agent-identity/CONTRACT.agent-identity.md`, and nothing about storage, hosting or management, so that DVLS and PSU cannot drift apart on the agent-facing protocol.
The feature's shared intent is `INTENT.agent-identity.md` beside this file.

## Authenticated identity

- An authority must use the identity produced by the signature check.
  Code that acts for an identity takes it as a type only that check can create; an identity is never taken from a value the agent or a caller sent.
