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
Agent cases check the five required §10.5 metadata fields and stable values across enrollment, renewal and Hello.
The DVLS expiry-boundary test needs a configured leaf lifetime of roughly 10–30 seconds.
`--expect-channel` defaults to `true`; use `--expect-channel false` when the server intentionally omits `channel_url`.
When the URL is absent, only gRPC-dependent checks become N/A; HTTP checks still run.

`PASS` and `FAIL` report assertions, while `N/A` marks platform-inapplicable or explicitly unavailable-channel tests.
`SKIP` means a required fixture is missing; any `SKIP` makes the run incomplete and exits nonzero unless `--allow-incomplete` is set.
The final summary reports counts, per-category durations and the reason for every non-PASS test.

On Windows, mock runs clean up only newly created machine keys belonging to the provided authority IDs.
DVLS runs report leftover keys without deleting them unless `--cleanup-machine-keys` is supplied.
The authority-ID and pre-test key-snapshot guards apply even when cleanup is requested.

[Agent Identity V1 contract]: ../../docs/agent-identity/CONTRACT.md
[mock README]: ../agent-identity-mock/README.md
