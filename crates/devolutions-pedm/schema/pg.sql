CREATE TABLE IF NOT EXISTS version
(
    version  smallint PRIMARY KEY,
    add_time timestamptz NOT NULL DEFAULT NOW()
);

/* The startup of the server */
CREATE TABLE IF NOT EXISTS run
(
    id         int PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    start_time timestamptz NOT NULL DEFAULT NOW(),
    pipe_name  text        NOT NULL
);

CREATE TABLE IF NOT EXISTS http_request
(
    id          integer PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT NOW(),
    method      text        NOT NULL,
    path        text        NOT NULL,
    status_code smallint    NOT NULL
);

/* The request ID is `http_request(id)` but the http_request INSERT only executes in middleware after the response, so we don't use a FK. */
CREATE TABLE IF NOT EXISTS elevate_tmp_request
(
    req_id  integer PRIMARY KEY,
    seconds int NOT NULL
);

INSERT INTO version (version) VALUES (1) ON CONFLICT DO NOTHING;