# traffic-audit-libsql

LibSQL/SQLite implementation of the **traffic audit** repository (claim/ack queue for traffic events).

## What it is

A durable, at-least-once **outbound queue** for `TrafficEvent`s. Writers enqueue events; one or more consumers **claim** batches with a lease, forward them, then **ack** to delete.

* Works with local SQLite files or remote libSQL.
* Safe for multiple consumers (leases + transactional claims).
* Ships with schema migrations and sensible PRAGMAs for this workload.
* Tuned for audit *traffic*: `journal_mode=WAL`, `synchronous=NORMAL` (local SQLite).
* Events are ephemeral here: after successful forwarding and `ack`, the table should stay near-empty.

## Guarantees

* **Concurrency:** claims use a single transaction (`BEGIN IMMEDIATE`) → no double-delivery during a lease.
* **Ordering:** claims return rows in increasing `id` (FIFO).
* **Recovery:** unacked items become claimable when the lease expires.
