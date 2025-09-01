-- Migration 0: Initial traffic_events table and indexes
-- This creates the complete audit event schema with efficient indexing for claim/ack operations

CREATE TABLE traffic_events (
    id INTEGER PRIMARY KEY,
    session_id BLOB NOT NULL,
    outcome INTEGER NOT NULL CHECK (outcome IN (0, 1, 2)),
    protocol INTEGER NOT NULL CHECK (protocol IN (0, 1)),
    target_host TEXT NOT NULL,
    target_ip_family INTEGER NOT NULL CHECK (target_ip_family IN (4, 6)),
    target_ip BLOB NOT NULL,
    target_port INTEGER NOT NULL CHECK (target_port >= 0 AND target_port <= 65535),
    connect_at_ms INTEGER NOT NULL,
    disconnect_at_ms INTEGER NOT NULL,
    active_duration_ms INTEGER NOT NULL CHECK (active_duration_ms >= 0),
    bytes_tx INTEGER NOT NULL CHECK (bytes_tx >= 0),
    bytes_rx INTEGER NOT NULL CHECK (bytes_rx >= 0),
    enqueued_at_ms INTEGER NOT NULL DEFAULT (unixepoch('subsec') * 1000),
    locked_by TEXT NULL,
    lock_until_ms INTEGER NULL
) STRICT;

-- Index for session-based queries and temporal ordering
-- Useful for debugging and session-based analysis
CREATE INDEX te_session_time ON traffic_events(session_id, connect_at_ms);

-- Critical index for lease scanning and claim operations
-- This is the primary index used by consumers to find available events
CREATE INDEX te_lease_scan ON traffic_events(lock_until_ms, id);

-- Index for network-based analysis and filtering
-- Enables efficient queries by IP address, target_port, and time
CREATE INDEX te_network_endpoint ON traffic_events(target_ip_family, target_ip, target_port, connect_at_ms);

-- Index for outcome-based analysis and reporting
-- Useful for monitoring connection success rates over time
CREATE INDEX te_outcome_time ON traffic_events(outcome, connect_at_ms);
