/* The startup of the server */
CREATE TABLE pedm_run
(
    id         int PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    start_time timestamptz NOT NULL DEFAULT NOW(),
    pipe_name  text        NOT NULL
);

CREATE TABLE http_request
(
    id          integer PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT NOW(),
    method      text        NOT NULL,
    path       text        NOT NULL,
    status_code smallint    NOT NULL
);

CREATE TABLE elevate_tmp_request
(
    req_id  integer PRIMARY KEY,  /* this is http_request but the http_request INSERT only executes in middleware after the response, so we don't use a FK */
    seconds int NOT NULL
);