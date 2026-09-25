# Agent Identity conformance runner

The runner checks the [Agent Identity V1 contract] against the mock server or a DVLS target.
Build both binaries with `cargo build -p agent-identity-mock -p agent-identity-conformance`.
Start two mocks as described in the [mock README] for the complete multi-authority run, then pass each `ready.json` URL, authority ID and TLS CA path:

```powershell
.\target\debug\agent-identity-conformance.exe `
  --target mock --base-url <first-url> --admin-token <first-admin-token> `
  --authority-id <first-authority-id> --extra-trusted-root <first-ca.pem> `
  --second-base-url <second-url> --second-admin-token <second-admin-token> `
  --second-authority-id <second-authority-id> --second-extra-trusted-root <second-ca.pem> `
  --agent-bin <devolutions-agent.exe> --work-dir <workspace-dir>
```

Use `--filter p_` for protocol-only checks or `--list` to inspect test names.
On DVLS, supply `--disposable-dvls-target` only when rotation is safe, and provide `--unprivileged-admin-token` to check permission denials.
`--dvls-rotation-window-secs` defaults to 60; `--leaf-lifetime-secs` defaults to 90 days and must match the server setting.
Pass `--agent-version <version>` to require the agent's reported version to match; the testsuite reads the root `VERSION` file and passes it automatically.
Agent cases check the five required §10.5 metadata fields and their values at each send.
Each generated agent config points `metadata_override_path` at a test-owned JSON file; mock-only renewal tests change its hostname between sends to verify that renew and the next Hello refresh metadata.
The DVLS expiry-boundary test needs a configured leaf lifetime of roughly 10–30 seconds.
`--expect-channel` defaults to `true`; use `--expect-channel false` when the server intentionally omits `channel_url`.
When the URL is absent, only gRPC-dependent checks become N/A; HTTP checks still run.

`PASS` and `FAIL` report assertions, while `N/A` marks platform-inapplicable or explicitly unavailable-channel tests.
`SKIP` means a required fixture is missing; any `SKIP` makes the run incomplete and exits nonzero unless `--allow-incomplete` is set.
The final summary reports counts, per-category durations and the reason for every non-PASS test.

The runner reports a unique `KEY NAME PREFIX` for each run and writes it to `__debug__.identity.key_name_prefix` in every generated `agent.json`.
Key names must be that prefix followed by a lowercase hyphenated UUID; file-backed keys live at `<data-dir>/identity/keys/<key_name>.p8`.
After each agent test, the runner fails if any key with that prefix is absent from `identity.json` or `enrollment-in-progress.json`, then deletes only run-prefixed machine and file-backed keys on either target.
It also rejects leftover temporary or unrecognized files anywhere under `<data-dir>/identity`.
`--authority-id` and `--second-authority-id` check server and stored authority IDs when supplied; they do not control cleanup.
The runner stops after 13 minutes; the testsuite allows 15 minutes and terminates the runner's process tree on timeout.

[Agent Identity V1 contract]: ../../docs/agent-identity/CONTRACT.md
[mock README]: ../agent-identity-mock/README.md
