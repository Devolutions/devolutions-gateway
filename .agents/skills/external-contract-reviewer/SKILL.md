---
name: external-contract-reviewer
description: Review Devolutions Gateway changes against authoritative external contracts. Use when a diff may affect HTTP or OpenAPI behavior, WebSocket behavior, relay or tunneling semantics, configuration schemas, or agent and platform protocols.
---

# External contract reviewer

First decide whether the change materially affects an externally visible contract.
Do not force this review onto internal refactors, tests, tooling, or implementation details that preserve observable behavior.

Review applicable surfaces:

- HTTP routes, methods, authentication, headers, status codes, request and response bodies, and OpenAPI definitions.
- WebSocket handshakes, subprotocols, messages, framing, session behavior, closure, and errors.
- Relay and tunneling establishment, routing, framing, multiplexing, shutdown, and failure behavior.
- Configuration names, types, formats, defaults, validation, compatibility, and `config_schema.json`.
- Gateway-to-agent communication and operating-system or vendor platform protocols.

Identify the governing source before judging the implementation.
Prefer normative standards and vendor specifications for standardized behavior, and checked-in schemas or explicitly canonical repository documentation for Gateway-defined contracts.
Treat generated files and existing implementation behavior as evidence, not authority, unless the repository declares them canonical.
Use the `windows-protocols` skill when Microsoft Open Specifications govern the changed behavior.
When no authoritative source is available, state the evidence gap instead of inventing a requirement.

Map each contract-relevant change to its governing requirement and attempt to falsify compliance.
Check versioning, capability negotiation, sequencing, endpoint roles, security requirements, compatibility guards, and error semantics when applicable.
For encoded or structured data, check field order, widths, signedness, constants, reserved values, optional fields, lengths, bounds, encode/decode symmetry, and malformed-input handling.
For schemas, compare implementation defaults and validation with the declared schema and verify that generated companions remain consistent.

Separate normative requirements from informative guidance, product-specific behavior, and inference.
Cite the governing source precisely, including a section, URL, or repository path.
Report only contract-relevant findings with a concrete location, observable impact, and actionable correction.
Do not propose general architectural refactors unless conformance requires them.
