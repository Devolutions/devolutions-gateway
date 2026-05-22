# Agent Tunnel: Gateway Identity & Endpoint Resolution

Design proposal for decoupling Gateway's cryptographic identity (server cert SAN)
from its network reachability (the endpoint agents dial).

Audience: gateway/agent/installer maintainers + DVLS-side maintainers.

## Background

The PR (#1789) introduces an agent tunnel where:

- DVLS mints an enrollment JWT with `jet_gw_url` claim
- Agent POSTs CSR to `<jet_gw_url>/jet/tunnel/enroll`
- Gateway signs the CSR with its internal `agent-tunnel-ca`, returns:
  - `client_cert_pem`, `gateway_ca_cert_pem`, `server_spki_sha256`
  - `quic_endpoint`: `format!("{}:{}", conf.hostname, conf.agent_tunnel.listen_port)`
- Agent stores everything in `agent.json` and connects QUIC to that endpoint

## Problem

A single `conf.hostname` field on the gateway side is overloaded as both:

1. **Cryptographic identity** — the SAN written into `agent-tunnel-server-cert.pem`
2. **Network advertisement** — the hostname returned to agents as their dial target

These two responsibilities are coupled in code but uncoupled in reality.

In any realistic deployment a single gateway is reachable through multiple
distinct names depending on the agent's network position:

- HQ-internal FQDN (`gateway.corp.example.com`)
- LAN/lab IP literal (`10.10.0.7`)
- External public DNS (`agw.public.example.com`)

Today the gateway picks one (`conf.hostname`) and forces every agent to use it,
regardless of how the agent was told to reach the gateway by the admin.

### Symptom we hit during integration testing

- Gateway config: `Hostname = "it-help-gw.ad.it-help.ninja"`
- Enrollment JWT: `jet_gw_url = "http://10.10.0.7:7777"` (chosen because the
  test VM cannot resolve internal AD DNS)
- Agent enrolls successfully via IP
- Gateway response: `quic_endpoint = "it-help-gw.ad.it-help.ninja:4433"`
- Agent service tries to QUIC-dial that hostname, DNS resolution fails forever,
  silent reconnect loop

The installer reports success because `agent.exe up` exits 0 (it writes
config; it does not validate the resulting tunnel).

### Why this is a design issue, not just a config oversight

The admin had no leverage: they correctly used an IP because the agent's
network couldn't see the gateway by name. The gateway then overrode that
choice and asserted a name the agent's network had never heard of. The
admin's intent ("reach me at 10.10.0.7") was lost the moment enrollment
moved past the HTTP request.

If we "fix" by switching `Hostname` to the IP, we break the AD-internal use
case where agents do use the FQDN. The fields fight each other because they
should not be the same field.

## Constraints (confirmed)

| Question | Answer |
|---|---|
| Single gateway reachable via multiple names? | Very common |
| Multiple DVLS instances? | 99% single, but design must not assume |
| Agent roams between gateways? | No, one gateway per agent for life |
| Enrollment token reuse? | Reusable until token expiry for this iteration; TODO: decide single-use enforcement later |
| Reinstall reuses identity? | No, always new agent_id |

## Proposed design

### 1. Gateway: multi-SAN server cert + advertised-names list

Add a new config block:

```json
"AgentTunnel": {
    "Enabled": true,
    "ListenPort": 4433,
    "AdvertisedNames": [
        "gateway.corp.example.com",
        "10.10.0.7",
        "agw.public.example.com"
    ]
}
```

`AdvertisedNames` accepts either a bare string or an object with a display
label, deserialized via serde `#[serde(untagged)]`:

```json
"AdvertisedNames": [
    "10.10.0.7",
    { "name": "gateway.corp.example.com", "label": "HQ FQDN" },
    { "name": "agw.public.example.com",   "label": "Public DNS" }
]
```

The label is purely informational, surfaced by DVLS UI when offering the
admin a choice. The Gateway itself only uses `name` for SAN generation and
host validation.

`AdvertisedNames` is the authoritative list of names/IPs this gateway is
reachable as for the agent-tunnel use case. The gateway:

- Signs `agent-tunnel-server-cert.pem` with **all** of them in SAN
  (DnsName entries for FQDNs, IpAddr entries for literals — rcgen handles
  both)
- Regenerates the cert at startup whenever the SAN set on disk differs from
  the current config list (allow admin to add/remove names without a manual
  cert reset). SAN-only regeneration must reuse the existing
  `agent-tunnel-server-key.pem` so the server SPKI pin remains stable for
  already enrolled agents. Generate a new server key only when the key is
  missing/corrupt; that is an SPKI rotation event and existing agents must be
  re-enrolled.
- Exposes `AdvertisedNames` by **extending the existing diagnostics endpoint**
  (`/jet/diagnostics/configuration`) rather than adding a new route. The
  response gains an `agent_tunnel` field carrying `enabled`, `listen_port`,
  and `advertised_names`. Same auth scope, no new public surface. DVLS reads
  this single endpoint for all gateway introspection.

The legacy `conf.hostname` is no longer used for the agent tunnel cert. It
remains usable elsewhere (or we deprecate it in a follow-up).

### 2. Enrollment response: compatibility bridge

Today:

```rust
let quic_endpoint = format!("{}:{}", conf.hostname, conf.agent_tunnel.listen_port);
```

For one compatibility window, return both the legacy full endpoint and the new
port-only field:

```rust
pub struct EnrollResponse {
    pub agent_id: Uuid,
    pub client_cert_pem: String,
    pub gateway_ca_cert_pem: String,
    pub quic_endpoint: String, // legacy: "<jet_gw_url.host>:<quic_port>"
    pub quic_port: u16,
    pub server_spki_sha256: String,
}
```

`quic_endpoint` must be computed from the normalized `jet_gw_url` host and the
agent tunnel listen port, not from `conf.hostname`.
Old agents keep using `quic_endpoint` and still benefit from the fix.
New agents prefer `quic_port` plus the enrollment URL host.
After one release, remove `quic_endpoint` in a schema cleanup PR.

The long-term model is: the gateway tells the agent which port to dial, not
which host. The host the agent uses is whichever host the agent already chose
to enroll through — that's the host the admin intentionally configured for
that agent's network.

### 3. Agent: derive the endpoint from the enrollment URL

In `devolutions-agent`:

```rust
// JWT carries jet_gw_url, e.g. "https://10.10.0.7:7777"
let enrollment_url = Url::parse(&claims.jet_gw_url)?;
let host = enrollment_url.host_str().context("missing host in jet_gw_url")?;

// Response carries quic_port; helper handles DNS, IPv4, and bracketed IPv6.
let gateway_endpoint = format_endpoint(host, quic_port)?;
```

This goes into `agent.json` as `Tunnel.GatewayEndpoint`. On runtime the agent:

- Resolves `host` (which the admin already verified is resolvable from this
  agent's network, by virtue of the enrollment URL working)
- QUIC-dials it
- TLS handshake uses `host` as SNI; the server cert SAN list includes `host`
  (because admin put it in `AdvertisedNames`); validation passes
- SPKI pinning still applies on top

Endpoint formatting must not be raw `format!("{host}:{port}")`.
It must handle:

| host kind | endpoint |
|---|---|
| DNS | `gateway.example.com:4433` |
| IPv4 | `10.10.0.7:4433` |
| IPv6 | `[fd00::7]:4433` |

Host comparison and SAN generation must normalize DNS names case-insensitively
and parse IP literals as IP addresses rather than DNS names.

### 4. Gateway: validate the enrollment URL host against AdvertisedNames

Before signing the CSR, gateway parses the JWT's `jet_gw_url` and rejects
the request if the host portion is not in `AdvertisedNames`. This fails fast
with a clear error message instead of producing a cert/endpoint pair the
agent cannot use.

Response on rejection (HTTP 400):

```json
{
  "error": "enrollment_host_not_advertised",
  "message": "The Gateway is not advertised as 'evil.example.com'. Allowed advertised names: [\"gateway.corp.example.com\", \"10.10.0.7\"].",
  "help": "Either (a) regenerate the enrollment string in DVLS using one of the names listed above, or (b) ask the Gateway operator to add 'evil.example.com' to AgentTunnel.AdvertisedNames in gateway.json and restart the Gateway."
}
```

The HTTP body is consumed by the agent CLI and re-emitted to stderr verbatim
so the message reaches the installer dialog and Windows event log.

### 5. Enrollment token replay prevention (TODO, deferred)

Do **not** add a gateway-side enrollment/JTI store in this pass.
Enrollment JWTs remain reusable until their normal expiry.

Strict single-use enrollment is still desirable, but it should be handled as
a follow-up decision rather than bundled into the endpoint identity fix.
The preferred owner is DVLS because DVLS issues the enrollment JWT and presents
the enrollment string to the admin.
If Gateway later needs to enforce replay prevention independently, the design
can revisit a bounded consumed-JTI store as an explicit statefulness tradeoff.

### 6. Installer: verify-then-report

Add `agent.exe verify-tunnel --timeout <secs>`. It:

- Reads `agent.json`
- Performs one QUIC handshake
- Sends one `RouteAdvertise` message and waits for ack
- Exit code 0 = tunnel works
- Non-zero = exits with stderr describing the failure point AND a one-line
  next-step the operator can act on without reading source

In `CA.EnrollAgentTunnel`, after `up` returns success, call `verify-tunnel`
with a hardcoded 10s timeout. If it fails, `ActionResult.Failure` +
InstallMessage.Error + MSI rollback. The installer's "success" now means
the tunnel is up, not just that a cert exists.

The 10s timeout is not configurable in this iteration. No MSI property to
tune it, no escape hatch to skip verification. If real deployments later
need a longer budget for slow customer networks, expose a property then —
not pre-emptively.

`verify-tunnel`'s stderr is a **single line of JSON** carrying the error
triple, written as the last line before exit:

```
{"kind":"dns_resolution_failed","detail":"Could not resolve 'gateway.corp' from this machine","next_step":"This agent's network cannot resolve 'gateway.corp'. ..."}
```

The installer CA reads stderr, parses the JSON, and feeds `kind`, `detail`,
`next_step` into the MSI error dialog. Agent log file and Windows Event Log
record the same object plus underlying stack.

Drop the Gateway URL override field from the installer dialog — with this
design the JWT is the single source of truth for the agent-facing URL, and
overriding it server-side would defeat the whole point.

#### Error catalog (verify-tunnel + agent service runtime)

Every failure path must emit a structured triple: **kind**, **detail**,
**next_step**. The installer dialog and Windows Event Log show all three;
the agent log file shows them plus the underlying stack.

| kind | when it fires | detail (variable) | next_step (the help text) |
|---|---|---|---|
| `enrollment_host_not_advertised` | Gateway rejects enrollment at HTTP layer (Section 4) | "Gateway advertises: [...]. JWT used host: X" | "Regenerate the enrollment string in DVLS using one of the advertised names, or add 'X' to AgentTunnel.AdvertisedNames on the Gateway." |
| `dns_resolution_failed` | QUIC dial step, OS returns NXDOMAIN / no such host | "Could not resolve 'X' from this machine" | "This agent's network cannot resolve 'X'. Either generate an enrollment string with a name this machine can resolve (e.g. an IP literal that the Gateway also advertises), or add a DNS entry / hosts file mapping for 'X'." |
| `udp_unreachable` | DNS resolves but UDP socket cannot send / no QUIC initial response in N seconds | "Resolved X -> A.B.C.D; UDP/<port> blocked or no listener" | "Verify Gateway is running and UDP <port> is open between this agent and the Gateway. Check Windows Firewall, corporate firewall, NAT, and SophosNTP / EDR network filters on both ends." |
| `tls_san_mismatch` | QUIC TLS handshake fails because server cert SAN does not include the dial host | "Connecting as 'X' but server cert SAN is [...]" | "Gateway operator must add 'X' to AgentTunnel.AdvertisedNames in gateway.json and restart the Gateway. The server certificate will be regenerated with X in SAN." |
| `tls_spki_pin_mismatch` | TLS chain validates but SPKI does not match the value captured at enrollment | "Pinned SPKI <hex>; server presented SPKI <hex>" | "The Gateway's agent-tunnel keypair changed since this agent enrolled (server key regenerated, gateway reinstalled, or man-in-the-middle). Re-enroll this agent by uninstalling and reinstalling with a fresh enrollment string." |
| `quic_handshake_timeout` | TLS got far enough to start but no Finished message within timeout | "Handshake stalled at <phase>" | "Network path likely drops UDP mid-flow (path MTU, broken NAT, deep packet inspection). Try a different network egress, lower QUIC MTU, or disable EDR network inspection for the Gateway endpoint." |
| `route_advertise_timeout` | Tunnel up but Gateway did not ack RouteAdvertise within timeout | "QUIC connected, no advertise ack in <N>s" | "Gateway is running an older or incompatible build; ensure Gateway version supports the agent tunnel feature. Check Gateway logs for RouteAdvertise handling errors." |
| `enrollment_token_expired` | JWT exp claim is in the past | "exp: <iso>, now: <iso>" | "Generate a new enrollment string in DVLS. Default token lifetime is short; coordinate enrollment with the installer run." |
| `enrollment_token_signature_invalid` | JWT signature does not verify against provisioner.pem | "verification error: <axum/jwt error>" | "The Gateway's provisioner.pem does not match the DVLS instance that signed this enrollment string. Verify DVLS is configured with the same Gateway entry, and that provisioner.pem on the Gateway corresponds to the provisioner.key DVLS is using." |
| `unexpected_error` | A failure path has not yet been classified | "Unexpected failure during <phase>; correlation_id=<id>; log=<path>" | "Collect the agent log and Gateway log using the correlation ID, then file a support issue. This is a product bug if it reaches the operator." |

#### Surface points

- **Installer dialog**: shows `kind` as the error title, `detail` as the
  subtitle, `next_step` as the body. One Copy-to-Clipboard button copies all
  three plus the timestamp and agent ID (if assigned).
- **Windows Event Log**: source = "DevolutionsAgent"; one event per failure
  with the structured fields as named properties so it's parseable by
  monitoring tools.
- **Agent service log file** (`agent.<date>.log`): full triple plus
  underlying stack and the request/response payloads (redacted).
- **DVLS Agent list view**: when an agent shows offline, the per-row tooltip
  shows the most recent `kind` + `next_step` so the admin sees the actionable
  hint without leaving the UI.

#### Anti-goals for the error catalog

- No bare "unknown error", "internal error", or other context-free catch-all
  messages reach the operator. The fallback is `unexpected_error`, and it must
  include `detail`, `next_step`, correlation ID, and log location.
- No stack traces in the operator-facing surface. Stacks live in agent log
  files only.
- No URLs to docs as the sole answer. The `next_step` must be self-contained
  for the common case. Docs links are additive.

### 7. DVLS

- When admin adds a Gateway entry, DVLS fetches `AdvertisedNames` from
  `/jet/diagnostics/agent-tunnel` and stores them as a cache
- When generating an enrollment string, DVLS refreshes `AdvertisedNames` from
  the Gateway before presenting choices. A stale cached list must not be the
  only source for new enrollment strings.
- "Generate enrollment string" UI presents `AdvertisedNames` as a dropdown
  instead of a free-text URL field
- Agent list view queries the gateway's `/jet/tunnel/agents` for live status
  rather than maintaining a separate DVLS-side mirror

## Migration

- Existing deployments with `conf.hostname = "x"` and no `AdvertisedNames`:
  default `AdvertisedNames = [conf.hostname]` so single-name setups keep
  working without changes
- Existing agent.json files with the old `GatewayEndpoint` string remain
  valid; nothing to migrate
- Existing enrollment tokens remain reusable until expiry. Strict single-use
  replay prevention is a TODO and is not part of this change.

## Resolved decisions

| # | Question | Decision |
|---|---|---|
| 1 | Cert regen trigger | Silent at startup. Log previous SAN, new SAN, new cert fingerprint. |
| 2 | Verify-tunnel timeout | Hardcoded 10s. No MSI property. No skip-verify escape hatch. |
| 3 | AdvertisedNames discovery | Extend `/jet/diagnostics/configuration` with an `agent_tunnel` field. Same scope. No new endpoint. |
| 4 | Error triple transport | Single-line JSON on stderr. Installer CA parses and surfaces fields into InstallMessage.Error. |
| 5 | Compat bridge | `EnrollResponse` returns both `quic_endpoint` (legacy, computed from `jet_gw_url.host`) and `quic_port` (new). Remove `quic_endpoint` in a follow-up release. |
| 6 | AdvertisedNames schema | Accept string or `{name, label}` object via serde untagged. Label is informational, surfaced by DVLS UI. |

## Explicit non-goals (deferred to follow-up PRs)

- **Single-use enrollment enforcement**. Tokens reusable until expiry for
  this iteration. Future decision: DVLS, Gateway, or both as owner.
- **Gateway farm / load-balanced gateway HA**. Agent tunnel assumes one
  agent enrolls to one gateway for life. A shared FQDN across multiple
  gateway backends behind a load balancer is not supported in this
  iteration. An agent enrolled through such an LB may bind to a single
  backend via session affinity, but cross-gateway agent discovery is not
  part of this design. Document this in admin docs.
- **Configurable verify-tunnel timeout / skip-verify escape hatch**. Add
  later if real deployments demand it; not pre-emptively.

## Implementation plan (PR breakdown)

Each PR ships independently. PR 1 alone fixes the SAN mismatch; subsequent
PRs add the polish.

### PR 1 — Gateway: AdvertisedNames + multi-SAN + diagnostics + host validation

Scope (all in `devolutions-gateway`):

- Add `AgentTunnelConf.advertised_names: Vec<AdvertisedName>` with serde
  untagged string-or-object support.
- Migration shim: when absent, default to `vec![conf.hostname.clone()]` so
  existing deployments keep working.
- At gateway boot: compare on-disk `agent-tunnel-server-cert.pem` SAN list
  against config. If different, regenerate cert (reusing existing keypair)
  with all advertised names as multi-SAN. Log old SAN, new SAN, new cert
  fingerprint.
- `EnrollResponse`: add `quic_port: u16`. Compute `quic_endpoint` from
  the validated `jet_gw_url.host` + agent tunnel listen port (not from
  `conf.hostname`).
- Enrollment handler: parse `jet_gw_url`, normalize host (DNS lowercased,
  IPs parsed), reject with HTTP 400 + structured `{error, message, help}`
  body when host is not in `AdvertisedNames`.
- Extend `/jet/diagnostics/configuration` response with `agent_tunnel:
  { enabled, listen_port, advertised_names: [{ name, label }] }`.

Verification:

- Unit tests for SAN regen idempotence, host normalization, host
  validation.
- Integration test: configure gateway with `AdvertisedNames = [name1,
  name2]`; enroll via name1; verify cert SAN contains both; reject
  enrollment via name3.

### PR 2 — Agent: derive endpoint from JWT host, consume `quic_port`

Scope (all in `devolutions-agent`):

- Parse `jet_gw_url` host from JWT.
- `format_endpoint(host, port)` helper handling DNS / IPv4 / bracketed
  IPv6.
- Prefer `quic_port` from response when available; fall back to parsing
  `quic_endpoint` for backward compatibility against older gateways.
- Write `agent.json::Tunnel.GatewayEndpoint` from the new logic.

Verification:

- Unit tests for endpoint formatting (IPv4, IPv6, DNS).
- End-to-end: agent enrolls via IP literal, QUIC dials same IP, TLS SAN
  validates against multi-SAN cert from PR 1.

### PR 3 — Installer: `verify-tunnel` + structured error surfacing

Scope (split across `devolutions-agent` and `dgw-pr-installer/package/AgentWindowsManaged`):

- New `agent.exe verify-tunnel --timeout <secs>` subcommand. One QUIC
  handshake + one RouteAdvertise round-trip. Emits single-line JSON triple
  on stderr; exit code 0 on success, non-zero on failure.
- Error catalog implementation (kinds from Section 6 of this doc).
- `CA.EnrollAgentTunnel` calls `verify-tunnel` after `up`. Parses stderr
  JSON; on failure, `ActionResult.Failure` + `session.Message(Error, ...)`.
- Drop Gateway URL override field from `AgentTunnelDialog` (and the
  associated `AGENT_TUNNEL_GATEWAY_URL` Property declaration).
- Windows Event Log writer in agent service for the same triples (source:
  `DevolutionsAgent`, structured named properties).

Verification:

- Manual install with bad enrollment (DNS unresolvable) → installer
  dialog shows `next_step`, MSI rollbacks.
- Manual install with good enrollment → tunnel up, installer reports
  success, agent appears in gateway agents list.

### PR 4 — DVLS: AdvertisedNames dropdown + live agent list

Scope (DVLS Web + DVLS server):

- Gateway entry editor: on save, call gateway's
  `/jet/diagnostics/configuration`, store `agent_tunnel.advertised_names`
  in the gateway record.
- "Generate enrollment string" UI: dropdown of advertised names with
  labels, no free-text URL box. Refresh from gateway before generation.
- Agent list view: query gateway's `/jet/tunnel/agents` for live status
  instead of mirroring locally. Tooltip shows latest `kind` + `next_step`
  for offline agents.

Verification:

- Add a new advertised name in gateway.json → DVLS sees it after manual
  refresh + on next "Generate" click.
- Generate string → install agent → DVLS list shows agent online within
  30 seconds.

### PR 5 (future) — Single-use enforcement, gateway farm story

Out of scope for the identity refactor. Tracked as follow-ups.

## What this design does NOT change

- Trust chain: provisioner key still lives only in DVLS; gateway has only
  the public half. Agent-tunnel CA still lives only in gateway.
- Cert pinning: SPKI pin still applies on top of SAN check.
- One-gateway-per-agent invariant.
- Reinstall semantics (always a new agent_id).

## Codex opinion - 2026-05-22

I reviewed this against the local knowledge base before commenting, especially `D:\AGENT_KNOWLEDGE_BASE\integrations\dvls-to-gateway-agent-tunnel.md`, `D:\AGENT_KNOWLEDGE_BASE\integrations\gateway-quic-tunnel-pr-split.md`, `D:\AGENT_KNOWLEDGE_BASE\integrations\how-they-fit-together.md`, `D:\AGENT_KNOWLEDGE_BASE\projects\devolutions-gateway.md`, `D:\AGENT_KNOWLEDGE_BASE\projects\DVLS.md`, and `D:\AGENT_KNOWLEDGE_BASE\notes\tokens-and-claims.md`.
My short take is: the core design is right, but I would ship it with a compatibility bridge and be careful not to undo the current stateless DVLS-signed enrollment direction.

The important product problem is not certificate generation.
The product problem is that the installer can say "success" while the tunnel is dead because the agent was handed an endpoint it cannot resolve.
For IT teams and MSPs, that failure mode is expensive because it appears after deployment, often on a remote customer network, and it turns a clean RMM or MSI rollout into a support ticket.
Fixing this makes Agent Tunnel feel like a real deployment feature instead of a lab feature.

The business value is strong.
MSPs live in split-DNS, NAT, VPN, customer-site, and segmented-network reality.
They need to enroll agents from whatever name or IP works at that site, then let RDM and DVLS route RDP, SSH, KDC, and other Gateway traffic through that agent without opening inbound firewall holes to every target.
This feature reduces customer network friction, makes private-network onboarding more repeatable, and gives Devolutions a cleaner story for managed remote access into customer environments.

The expected user workflow should be simple.
An admin configures the Gateway with the names or IPs that agents may legitimately use.
DVLS shows those choices when generating the enrollment string.
The admin chooses the endpoint that matches the target network, then deploys the Agent MSI through RMM, GPO, Intune, or manual install.
The installer enrolls, verifies one real tunnel handshake, and only reports success if the tunnel can actually advertise routes.
After that, help desk users and administrators should not have to think about the tunnel when launching sessions from RDM or DVLS Web.

I strongly agree with splitting cryptographic identity from network reachability.
`conf.hostname` should not be both the SAN source and the agent dial target.
The multi-SAN `AdvertisedNames` model is the right primitive because the Gateway can be known as an internal FQDN, a public DNS name, and a site-local IP at the same time.
The config name might be worth refining to something like `AgentTunnel.AdvertisedHosts` or `AgentTunnel.ReachableNames`, but the concept is correct.

I also agree that the agent should derive the QUIC host from the enrollment URL host.
If the agent successfully reached `jet_gw_url` during enrollment, that host is the best available evidence of what works from the agent's network.
The gateway should return the QUIC port, not override the host with `conf.hostname`.
Implementation must handle IP literals and IPv6 bracket formatting carefully, because `10.10.0.7:4433` and `[fd00::7]:4433` need different endpoint formatting.

The main compatibility risk is the enrollment response schema.
The 2026-05-21 KB snapshot says the current merged direction has the agent reading `jet_gw_url` from the enrollment JWT and still receiving `quic_endpoint` from the enrollment response.
I would not hard-break that response unless every dependent artifact is moved in one coordinated PR set.
For one release, I would accept both shapes or return both `quic_endpoint` and `quic_port`, with the new agent preferring `quic_port` plus the enrollment URL host.
That keeps older agents and installer builds from failing during staged rollout.

I agree with validating the enrollment URL host against `AdvertisedNames`.
That validation should happen as early as possible and produce an operator-grade error, not a generic enrollment failure.
DNS names should compare case-insensitively, IPs should be parsed and normalized, and the implementation should avoid accepting an arbitrary redirected host just because the HTTP request reached the gateway.
The security property should be: the agent may only enroll through a host or IP the Gateway operator intentionally advertised for agent tunnel use.

The `verify-tunnel` installer step is a must-have, not a nice-to-have.
Without it, we still have a gap between "configuration was written" and "the customer can route a session".
A 10 second default is reasonable, but the MSI property should be overrideable for slow customer networks.
The error should identify the failing phase: DNS, UDP reachability, TLS SAN validation, SPKI pinning, QUIC handshake, route advertise, or timeout.

I am more cautious about the consumed-JTI SQLite table, and the current decision is to defer it.
Single-use enrollment is good security, but the KB says the architecture intentionally moved to stateless DVLS-signed JWT enrollment and removed gateway-side enrollment token storage.
For this iteration, enrollment tokens can remain reusable until expiry.
If strict single-use is required later, the cleanest owner is the issuer, which is DVLS, because DVLS is generating the enrollment string and presenting it to the admin.
If the Gateway must enforce replay prevention anyway, the table is acceptable as a bounded fallback, but it should be called out as a deliberate tradeoff against stateless enrollment rather than a small implementation detail.

The DVLS UI should not be a free-text URL box for normal users.
The dropdown from `AdvertisedNames` is the right default because it prevents typos and keeps the cert SAN list, gateway validation, and admin intent aligned.
For MSP usability, each advertised name should probably have an optional display label such as "Customer LAN", "Public DNS", or "Lab subnet".
Most IT operators think in site and network names first, not in certificate SAN mechanics.

Certificate regeneration at startup is acceptable if it is explicit in logs and diagnostics.
I would log the previous SAN set, new SAN set, and new server certificate fingerprint.
DVLS should also be able to detect drift by querying diagnostics, because otherwise an admin can generate an enrollment string using a stale cached name after the Gateway config changed.
This is especially important for MSPs managing multiple customer gateways.

The load balancer and gateway-farm question remains the biggest unresolved edge.
The design correctly acknowledges that a shared FQDN can route an enrolled agent to the wrong gateway if registration state is per-gateway.
We should not accidentally imply HA support for agent tunnel until there is sticky routing, shared agent registry state, or a documented farm ownership model.
For now, the UI and docs should describe this as one agent enrolled to one gateway, with load-balanced gateway farms out of scope.

My recommended implementation order would be:

1. Add `AgentTunnel.AdvertisedNames`, multi-SAN server cert generation, diagnostics exposure, and enrollment-host validation.
2. Change new agents to derive the QUIC host from `jet_gw_url` and consume `quic_port`, while keeping response compatibility for old agents during rollout.
3. Add `agent.exe verify-tunnel` and wire the MSI to fail install when verification fails.
4. Update DVLS to present advertised names as labeled choices when generating enrollment strings.
5. Revisit strict single-use enforcement and gateway-farm behavior as explicit TODO follow-up decisions.

Bottom line: I would move forward with this design.
It solves a real deployment blocker, lines up with how IT professionals and MSPs actually operate, and turns enrollment from "certs were written" into "the tunnel is reachable and usable".
The only part I would not take blindly is the gateway-side JTI store, because it partially reverses the stateless enrollment architecture that the current PR stack just landed.
