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
    id         integer PRIMARY KEY AUTOINCREMENT,
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

CREATE TABLE IF NOT EXISTS elevate_tmp_request
(
    req_id  integer PRIMARY KEY,
    seconds integer NOT NULL
);

INSERT INTO version (version) VALUES (1) ON CONFLICT DO NOTHING;