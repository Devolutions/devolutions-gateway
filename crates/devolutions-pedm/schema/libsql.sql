/* In SQLite, we store time as an 8-byte integer (i64) with microsecond precision. This matches TIMESTAMPTZ in Postgres.
   Use `chrono::DateTime::timestamp_micros` when inserting or fetching timestamps in Rust.
*/

CREATE TABLE IF NOT EXISTS version
(
    version    integer PRIMARY KEY,
    updated_at integer NOT NULL DEFAULT (
        CAST(strftime('%s', 'now') AS integer) * 1000000 + CAST(strftime('%f', 'now') * 1000000 AS integer) % 1000000
        )
);

CREATE TABLE IF NOT EXISTS run
(
    id         integer PRIMARY KEY,
    start_time integer NOT NULL DEFAULT (
        CAST(strftime('%s', 'now') AS integer) * 1000000 + CAST(strftime('%f', 'now') * 1000000 AS integer) % 1000000
        ),
    pipe_name  text    NOT NULL
);

CREATE TABLE IF NOT EXISTS http_request
(
    id          integer PRIMARY KEY,
    at          integer NOT NULL DEFAULT (
        CAST(strftime('%s', 'now') AS integer) * 1000000 + CAST(strftime('%f', 'now') * 1000000 AS integer) % 1000000
        ),
    method      text    NOT NULL,
    path        text    NOT NULL,
    status_code integer NOT NULL
);

CREATE TABLE IF NOT EXISTS user
(
    id integer primary key,
    account_name text,
    domain_name text,
    account_sid text,
    domain_sid text
);

CREATE TABLE IF NOT EXISTS signature
(
    id integer primary key,
    authenticode_sig_status integer NOT NULL,
    issuer text
);

CREATE TABLE IF NOT EXISTS jit_elevation_result
(
    id integer PRIMARY KEY,
    success integer NOT NULL,
    timestamp integer NOT NULL,
    asker_path text NOT NULL,
    target_path text NOT NULL,
    target_command_line text,
    target_working_directory text,
    target_sha1 text NOT NULL,
    target_sha256 text NOT NULL,
    target_user_id integer,
    target_signature_id integer,
    FOREIGN KEY (target_signature_id) REFERENCES signature(id),
    FOREIGN KEY (target_user_id) REFERENCES user(id)
);

CREATE TABLE IF NOT EXISTS profile
(
    id integer PRIMARY KEY,
    name text NOT NULL,
    description TEXT,
    jit_elevation_method integer,
    jit_elevation_default_kind integer,
    jit_elevation_target_must_be_signed integer
);

CREATE TABLE IF NOT EXISTS policy
(
    id integer PRIMARY KEY,
    profile_id integer,
    user_id integer,
    FOREIGN KEY (profile_id) REFERENCES profile(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_profile
(
    user_id integer PRIMARY KEY,
    profile_id integer,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
    FOREIGN KEY (profile_id) REFERENCES profile(id) ON DELETE CASCADE
);

INSERT INTO version (version) VALUES (0) ON CONFLICT DO NOTHING;