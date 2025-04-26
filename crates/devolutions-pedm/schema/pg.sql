CREATE EXTENSION IF NOT EXISTS btree_gist;

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

CREATE TABLE IF NOT EXISTS account_diff_request
(
    id int PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS domain
(
    id       smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    subauth1 smallint NOT NULL,
    subauth2 bigint   NOT NULL,
    subauth3 bigint   NOT NULL,
    subauth4 bigint   NOT NULL,
    CONSTRAINT unique_domain UNIQUE (subauth1, subauth2, subauth3, subauth4)
);

CREATE TABLE IF NOT EXISTS sid
(
    id             smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    domain_id      smallint NOT NULL REFERENCES domain (id),
    relative_id    smallint NOT NULL,
    CONSTRAINT unique_sid UNIQUE (domain_id, relative_id)
);

CREATE TABLE IF NOT EXISTS account
(
    id smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY
);

CREATE TABLE IF NOT EXISTS account_name
(
    id     smallint  NOT NULL REFERENCES account (id),
    name   text      NOT NULL,
    during tstzrange NOT NULL DEFAULT tstzrange(now(), 'infinity'),
    PRIMARY KEY (id, during),
    EXCLUDE USING gist (id WITH =, during WITH &&)
);

CREATE TABLE IF NOT EXISTS account_removed
(
    id     smallint  NOT NULL REFERENCES account (id),
    during tstzrange NOT NULL DEFAULT tstzrange(now(), 'infinity'),
    PRIMARY KEY (id, during),
    EXCLUDE USING gist (id WITH =, during WITH &&)
);

CREATE TABLE IF NOT EXISTS account_sid
(
    account_id smallint  NOT NULL REFERENCES account (id),
    sid_id     smallint  NOT NULL REFERENCES sid (id),
    during     tstzrange NOT NULL DEFAULT tstzrange(now(), 'infinity'),
    PRIMARY KEY (account_id, sid_id, during),
    EXCLUDE USING gist (account_id WITH =, sid_id WITH =, during WITH &&)
);

INSERT INTO version (version) VALUES (0) ON CONFLICT DO NOTHING;