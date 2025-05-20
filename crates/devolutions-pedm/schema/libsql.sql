/* In SQLite, we store time as an 8-byte integer (i64) with microsecond precision. This matches TIMESTAMPTZ in Postgres.
   Use `chrono::DateTime::timestamp_micros` when inserting or fetching timestamps in Rust.

   `valid_from` and `valid_to` are used in place of a temporal interval type.
   Since the special infinity value does not exist in SQLite, we use NULL. This allows for easy checking of a row validity. A row is presently valid if `valid_to` is NULL.
*/

CREATE TABLE IF NOT EXISTS version
(
    version    integer PRIMARY KEY,
    updated_at integer NOT NULL DEFAULT (
        cast(strftime('%s', 'now') AS integer) * 1000000 + cast(strftime('%f', 'now') * 1000000 AS integer) % 1000000
        )
);

CREATE TABLE IF NOT EXISTS run
(
    id         integer PRIMARY KEY,
    start_time integer NOT NULL DEFAULT (
        cast(strftime('%s', 'now') AS integer) * 1000000 + cast(strftime('%f', 'now') * 1000000 AS integer) % 1000000
        ),
    pipe_name  text    NOT NULL
);

CREATE TABLE IF NOT EXISTS http_request
(
    id          integer PRIMARY KEY,
    at          integer NOT NULL DEFAULT (
        cast(strftime('%s', 'now') AS integer) * 1000000 + cast(strftime('%f', 'now') * 1000000 AS integer) % 1000000
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

CREATE TABLE IF NOT EXISTS account_diff_request
(
    id integer PRIMARY KEY,
    at integer NOT NULL DEFAULT (
        cast(strftime('%s', 'now') AS integer) * 1000000 +
        cast(strftime('%f', 'now') * 1000000 AS integer) % 1000000
        )
);

CREATE TABLE IF NOT EXISTS domain
(
    id       integer PRIMARY KEY AUTOINCREMENT,
    subauth1 integer NOT NULL,
    subauth2 integer NOT NULL,
    subauth3 integer NOT NULL,
    subauth4 integer NOT NULL,
    CONSTRAINT unique_domain UNIQUE (subauth1, subauth2, subauth3, subauth4)
);

CREATE TABLE IF NOT EXISTS sid
(
    id          integer PRIMARY KEY AUTOINCREMENT,
    domain_id   integer NOT NULL REFERENCES domain (id),
    relative_id integer NOT NULL,
    CONSTRAINT unique_sid UNIQUE (domain_id, relative_id)
);

CREATE TABLE IF NOT EXISTS account
(
    id integer PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS account_name
(
    id         integer NOT NULL REFERENCES account (id),
    name       text    NOT NULL,
    valid_from integer NOT NULL DEFAULT (
        cast(strftime('%s', 'now') AS integer) * 1000000 +
        cast(strftime('%f', 'now') * 1000000 AS integer) % 1000000
        ),
    valid_to   integer DEFAULT NULL,
    PRIMARY KEY (id, valid_from)
);

CREATE TABLE IF NOT EXISTS account_removed
(
    id         integer NOT NULL REFERENCES account (id),
    valid_from integer NOT NULL DEFAULT (
        cast(strftime('%s', 'now') AS integer) * 1000000 +
        cast(strftime('%f', 'now') * 1000000 AS integer) % 1000000
        ),
    valid_to   integer DEFAULT NULL,
    PRIMARY KEY (id, valid_from)
);

CREATE TABLE IF NOT EXISTS account_sid
(
    account_id integer NOT NULL REFERENCES account (id),
    sid_id     integer NOT NULL REFERENCES sid (id),
    valid_from integer NOT NULL DEFAULT (
        cast(strftime('%s', 'now') AS integer) * 1000000 +
        cast(strftime('%f', 'now') * 1000000 AS integer) % 1000000
        ),
    valid_to   integer DEFAULT NULL,
    PRIMARY KEY (account_id, sid_id, valid_from)
);

INSERT INTO version (version) VALUES (0) ON CONFLICT DO NOTHING;