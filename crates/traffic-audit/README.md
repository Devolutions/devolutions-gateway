# traffic-audit

Storage-agnostic **types** and **traits** for auditing **traffic**.
Use this crate to model per-traffic events and define a repository interface; pair it with a backend crate (e.g., `traffic-audit-libsql`) for persistence.

## What it is

* **Domain types**: `TrafficEvent`, `EventOutcome`, `TransportProtocol`
* **Repository trait**: `TrafficAuditRepo` (enqueue + claim/ack with leases)
* **Backend-neutral**: no DB/HTTP dependencies

## Delivery semantics

Designed as an **outbound queue** with **at-least-once** delivery:

* **Claim/ack with leases** (multi-consumer safe)
* **FIFO** by monotonic ID (left to the backend)
* **Ephemeral**: events are deleted on `ack` (this is not a long-term audit log)
