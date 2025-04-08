/* In SQLite, we store time as integer with microsecond precision. This is the same precision used by TIMESTAMPTZ in Postgres. */

CREATE TABLE pedm_run (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time INTEGER NOT NULL DEFAULT (CAST(strftime('%f', 'now') * 1000000 AS INTEGER)),
    pipe_name  TEXT NOT NULL
);

CREATE TABLE http_request (
    id          INTEGER PRIMARY KEY,
    at          INTEGER NOT NULL DEFAULT (CAST(strftime('%f', 'now') * 1000000 AS INTEGER)),
    method      TEXT NOT NULL,
    path        TEXT NOT NULL,
    status_code INTEGER NOT NULL
);

CREATE TABLE elevate_tmp_request (
    req_id  INTEGER PRIMARY KEY,
    seconds INTEGER NOT NULL
);
