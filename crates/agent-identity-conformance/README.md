# Agent Identity conformance runner

The runner checks the [Agent Identity V1 contract] against the mock server or a DVLS target.
Build both binaries with `cargo build -p agent-identity-mock -p agent-identity-conformance`.
Start two mocks as described in the [mock README] for the complete multi-authority run, then pass each `ready.json` URL, authority ID and TLS CA path:

```powershell
.\target\debug\agent-identity-conformance.exe `
  --target mock --base-url <first-url> --app-key <first-app-key> --app-secret <first-app-secret> `
  --authority-id <first-authority-id> --extra-trusted-root <first-ca.pem> `
  --second-base-url <second-url> --second-app-key <second-app-key> --second-app-secret <second-app-secret> `
  --second-authority-id <second-authority-id> --second-extra-trusted-root <second-ca.pem> `
  --agent-bin <devolutions-agent.exe> --work-dir <workspace-dir>
```

Use `--filter p_` for protocol-only checks or `--list` to inspect test names.
Use `--key-backend windows-software-provider|file` to select `Identity.KeyBackend` (`WindowsSoftwareProvider` or `File`); the default is Windows software provider on Windows and file elsewhere.
The runner calls each authority's management API as an application identity, with its key and secret: `--app-key` and `--app-secret` name one holding every Agent Identity permission, and `--second-app-key` and `--second-app-secret` one on the second authority; on the mock, they are the mock's own `--app-key` and `--app-secret`.
A key requires its secret, which the `AGENT_IDENTITY_CONFORMANCE_APP_SECRET`, `AGENT_IDENTITY_CONFORMANCE_SECOND_APP_SECRET` and `AGENT_IDENTITY_CONFORMANCE_UNPRIVILEGED_APP_SECRET` environment variables can supply instead, to keep secrets off the command line.
The runner logs in with `POST /api/v1/login` on first use and sends the `tokenId` it returns.
It logs in again before the `tokenId` lifetime elapses, assuming DVLS's 7 minutes until the API refuses a younger `tokenId`, and when the API refuses a `tokenId` it logs in once more and retries that request once.
Each re-login is logged at info level, without the `tokenId`, key or secret, and the run ends with `POST /api/v1/logout`.
On DVLS, the harness provisions the application identities, which DVLS's public API cannot create.
Supply `--disposable-dvls-target` only when rotation and settings changes are safe, and provide `--unprivileged-app-key` and `--unprivileged-app-secret`, an application identity without any Agent Identity permission, to check permission denials.
On the mock, the runner derives the keys of application identities with fewer permissions from `--app-key`, as the [mock README] describes.
Settings tests restore the original settings when they finish.
The runner reaches each authority's management API only through the module for that authority: `src/dvls.rs` speaks DVLS's management API, as DVLS's OpenAPI document defines it and the mock replicates it.
The disposable rotation checks require no other active identities on the published root; otherwise they report `SKIP` before rotating.
`--dvls-rotation-window-secs` defaults to 60; `--leaf-lifetime-secs` defaults to 90 days and must match the server setting.
Pass `--agent-version <version>` to require the agent's reported version to match; the testsuite reads the root `VERSION` file and passes it automatically.
Agent cases check the five required metadata fields and their values at each send ([Agent Identity V1 contract] §3.1).
Each generated agent config points `metadata_override_path` at a test-owned JSON file; mock-only renewal tests change its hostname between sends to verify that renew and the next Hello refresh metadata.
The DVLS expiry-boundary test needs a configured leaf lifetime of roughly 10–30 seconds.
`--expect-channel` defaults to `true`; use `--expect-channel false` when the server intentionally omits `config.agent_channel_url`.
When the URL is absent, gRPC-dependent checks report `SKIP`; HTTP confirm checks and channelless renewal still run.

`PASS` and `FAIL` report assertions, and `N/A` marks a test that does not apply to the platform or that the authority's module declares unsupported, so mock-only tests report `N/A` on DVLS.
`SKIP` means the target lacks a required fixture, privilege or channel.
Any `SKIP` makes the run incomplete and exits nonzero unless `--allow-incomplete` is set.
The final summary reports counts, per-category durations and the reason for every non-PASS test.

The runner reports a unique `KEY NAME PREFIX` of `conformance-<32 lowercase hex digits>` for each run and writes it to `__debug__.identity.key_name_prefix` in every generated `agent.json`.
Key names must be `<prefix>_<lowercase hyphenated UUID>`; file-backed keys live at `<data-dir>/identity/keys/<key_name>.p8`.
Only keys whose part before the first `_` equals the run prefix belong to that run.
After each agent test, the runner fails if any key with that prefix is absent from `identity.json` or `<data-dir>/identity/pending/<hex>.in-progress.json`, then deletes only run-prefixed machine and file-backed keys on either target.
It rejects unrecorded `*.p8` files and PKCS#8 private keys anywhere under `<data-dir>/identity`, plus leftover temporary siblings of identity files; other unknown files produce warnings.
On Unix, file-backed keys must have mode `0600` and be owned by the agent's uid.
Windows software provider keys must allow only the agent's account and SYSTEM, regardless of `acl_grant_current_user`; when the agent runs as SYSTEM, only SYSTEM is expected.
The SYSTEM fixture requires an elevated administrator unless the suite already runs as SYSTEM; without this fixture, the Windows non-exportability case reports `SKIP`.
`--authority-id` and `--second-authority-id` check server and stored authority IDs when supplied; they do not control cleanup.
The runner stops after 14 minutes 30 seconds; the testsuite allows 15 minutes and terminates the runner's process tree on timeout.

[Agent Identity V1 contract]: ../../docs/agent-identity/CONTRACT.agent-identity.md
[mock README]: ../agent-identity-mock/README.md
