---
status: accepted
---

# Authorize Agent identities with an allowlist

Gateway will persist accepted Agent identities, unique names, and public-key SPKI hashes in a dedicated `agent_tunnel.db` beside its other databases.
Enrollment adds a new identity and key, mTLS admission requires both to match, and deletion durably removes them before terminating the connection and sessions.
This allowlist fails closed when state is missing and makes enrollment the explicit authorization action.
Time-bounded enrollment-attempt records make identical retries idempotent without allowing a deleted Agent to replay its original token.

## Considered options

A revoked-identity denylist was rejected because missing state would restore deleted Agents.
Exact certificate fingerprints were rejected because renewal reuses the Agent key and should not require an authorization write.
Trust-on-first-connect migration was rejected because Agent Tunnel was unstable and automatic import would weaken the allowlist.

## Consequences

Existing pre-stable Agents must be re-enrolled.
An accepted identity cannot be enrolled again until it is deleted.
Re-enrollment binds a deleted identity to a new key without restoring certificates issued for older keys.
Re-enrollment after deletion requires a new provisioner token.
Certificate renewal must preserve the accepted public key; key rotation requires deletion and a new enrollment.
Agent names are unique without ASCII case and may not have leading or trailing spaces.
The CA and authorization database belong to one Gateway data directory and must be backed up and restored together.
Database or migration failures prevent Gateway startup, and a successful deletion must survive process failure and power loss.
The authorization registry does not persist connection telemetry or routes.
