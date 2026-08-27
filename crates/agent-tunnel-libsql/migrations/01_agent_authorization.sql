CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE accepted_agents (
    agent_id TEXT PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    client_spki_sha256 BLOB NOT NULL,
    enrollment_jti TEXT NOT NULL UNIQUE,
    CHECK (length(name) BETWEEN 1 AND 255),
    CHECK (name = trim(name)),
    CHECK (length(client_spki_sha256) = 32)
);

CREATE TABLE enrollment_attempts (
    jti TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    request_sha256 BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    CHECK (length(request_sha256) = 32),
    CHECK (deleted IN (0, 1))
);

CREATE TABLE deleted_agent_keys (
    client_spki_sha256 BLOB PRIMARY KEY,
    agent_id TEXT NOT NULL,
    CHECK (length(client_spki_sha256) = 32)
);
