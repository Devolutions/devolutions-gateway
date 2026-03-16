# WireGuard Dynamic Enrollment MVP

This document defines the end state and the implementation phases for fully dynamic WireGuard agent enrollment.

## Product Goal

Gateway must stop relying on statically configured WireGuard peers.

Agent onboarding must become dynamic and copy-paste driven.

Gateway UI will eventually generate an enrollment string that the operator can paste on the agent host.

The agent will use that enrollment string to register itself, obtain tunnel identity, and then start WireGuard.

## Final Model

The system is split into three layers.

### Enrollment Layer

Gateway issues a short-lived enrollment token.

The enrollment token is requested through Gateway UI.

The enrollment token is carried in a copyable enrollment string.

The agent uses the enrollment string to call a Gateway enrollment API over HTTPS.

Gateway validates the enrollment token, accepts the agent public key, allocates an `AgentId`, allocates an `AssignedIp`, and persists the peer identity.

### WireGuard Peer Layer

After enrollment, Gateway treats the agent as a normal WireGuard peer.

Peer identity is no longer read from static Gateway configuration.

Gateway reconstructs enrolled peers from persistent storage on startup.

Gateway must also support adding and removing peers at runtime without restart.

### Runtime Route Layer

After the WireGuard peer is established, the agent advertises reachable subnets at runtime.

Gateway does not store static routes.

Gateway only uses an agent when the session token explicitly carries `jet_agent_id`.

If no agent is explicitly requested, Gateway must stay on the normal direct path.

## Explicit Non-Goals

This MVP does not add approval workflow.

This MVP does not add automatic network scanning.

This MVP does not auto-route through an agent when `jet_agent_id` is missing.

This MVP does not keep static `AllowedSubnets`.

## Security Model

Bare WireGuard is not sufficient for first-time enrollment.

WireGuard requires both sides to already know each other's public keys.

Dynamic first enrollment therefore needs a bootstrap control-plane authentication step.

The MVP uses an enrollment token over HTTPS for that bootstrap step.

## Enrollment String

The enrollment string is a compact, copyable bootstrap payload.

The exact wire format can evolve, but the MVP should encode at least:

- Gateway HTTPS API base URL.
- Gateway WireGuard endpoint.
- Enrollment token.

The agent CLI will accept the enrollment string directly.

## Persistence

Gateway needs a persistent peer registry.

The MVP stores enrolled peers in a sidecar file under the Gateway data directory.

The sidecar file becomes the source of truth for dynamic peers.

## Implementation Phases

### Phase 1

Add a persistent Gateway `AgentStore`.

Load enrolled peers from the store on startup.

Refactor the WireGuard listener to support runtime `add_peer` and `remove_peer`.

This phase builds the runtime foundation without changing onboarding yet.

### Phase 2

Add Gateway enrollment token persistence.

Add Gateway APIs to create an enrollment token and to complete enrollment.

The enrollment API persists the new peer and injects it into the running WireGuard listener without restart.

### Phase 3

Add an agent `enroll` flow.

The agent generates its own keypair.

The agent posts its public key and metadata to the Gateway enrollment API.

The agent persists the returned runtime configuration and then starts the existing WireGuard tunnel manager.

### Phase 4

Add a Gateway UI page or tab to generate an enrollment string.

The UI only needs to call the Gateway API and provide a copy button for the resulting enrollment string.

## Current MVP Status

The repository now contains the first end-to-end implementation slice for dynamic enrollment.

Gateway persists enrolled peers in a sidecar agent store.

Gateway persists one-time enrollment tokens in a sidecar enrollment token store.

Gateway can issue a copyable enrollment string through a standalone web app API.

The agent can consume that enrollment string through the `enroll` subcommand and write a runnable config file.

Gateway UI now exposes a minimal `/session/agents` page that can request and display the enrollment string and bootstrap command.

Gateway now persists enrollment tokens atomically before any peer side effects.

Gateway rolls back agent registration if runtime peer injection fails.

Gateway and the standalone web app both use the same `GET /jet/agents/{agent_id}` status path, which allows the browser and the real E2E harness to wait for an enrolled agent to come online.

The remaining work is mainly black-box validation and any product-level polishing around the generated command flow.

## Acceptance Criteria

- Gateway can restart and reconstruct enrolled peers from persistent storage.
- Gateway can add a new WireGuard peer at runtime without restart.
- Gateway can remove a WireGuard peer at runtime without restart.
- Gateway still only uses agents when `jet_agent_id` is explicitly present.
- Static peer configuration no longer exists for WireGuard agent identity.
- Gateway UI can obtain a copyable enrollment string from Gateway.
- Agent can enroll itself using that string and then connect over WireGuard.
