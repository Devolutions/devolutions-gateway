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
The runner calls each authority's management API as an application identity, with its key and secret: `--app-key` and `--app-secret` name one holding every Agent Identity permission, and `--second-app-key` and `--second-app-secret` one on the second authority; on the mock, they are the mock's own `--app-key` and `--app-secret`.
A key requires its secret, which the `AGENT_IDENTITY_CONFORMANCE_APP_SECRET`, `AGENT_IDENTITY_CONFORMANCE_SECOND_APP_SECRET` and `AGENT_IDENTITY_CONFORMANCE_UNPRIVILEGED_APP_SECRET` environment variables can supply instead, to keep secrets off the command line.
Usage errors name only known flags, known `--authority` keys and argument positions, never values, because a misplaced value may be a secret.
The runner logs in with `POST /api/v1/login` on first use and sends the `tokenId` it returns.
It logs in again before the `tokenId` lifetime elapses, assuming DVLS's 7 minutes until the API refuses a younger `tokenId`, and when the API refuses a `tokenId` it logs in once more and retries that request once.
Each re-login is logged at info level, without the `tokenId`, key or secret, and the run ends with `POST /api/v1/logout`.
On DVLS, the harness provisions the application identities, which DVLS's public API cannot create.
Supply `--disposable-dvls-target` only when rotation and settings changes, including switching the agent channel off and on, are safe, and provide `--unprivileged-app-key` and `--unprivileged-app-secret`, an application identity without any Agent Identity permission, to check permission denials.
On the mock, the runner derives the keys of application identities with fewer permissions from `--app-key`, as the [mock README] describes.
Settings tests restore the original settings when they finish.
The runner reaches each authority's management API only through the module for that authority: `src/dvls.rs` speaks DVLS's management API, as DVLS's OpenAPI document defines it and the mock replicates it.
The disposable rotation checks require no other active identities on the published root; otherwise they report `SKIP` before rotating.
`--leaf-lifetime-secs` defaults to 90 days and must match the lifetime of the leaves the authority issues: its certificate lifetime setting, or the test-only lifetime DVLS uses instead in its unsafe test mode.
DVLS refuses a rotation deadline after the rotation maximum, which is at most one leaf lifetime ahead, so the rotation checks set their deadline `--dvls-rotation-window-secs` ahead, by default 60 seconds or 75% of `--leaf-lifetime-secs` rounded down to whole seconds, whichever is shorter.
A one-second leaf lifetime leaves no whole second for that default, so the runner then refuses to start without `--dvls-rotation-window-secs`.
Pass `--agent-version <version>` to require the agent's reported version to match; the testsuite reads the root `VERSION` file and passes it automatically.
Agent cases check the six required metadata fields and their values at each send ([Agent Identity V1 contract] §3.1).
Each generated agent config points `metadata_override_path` at a test-owned JSON file; mock-only renewal tests change its hostname between sends to verify that renew and the next Hello refresh metadata.
The DVLS expiry-boundary test needs leaves of roughly 10–30 seconds, which DVLS issues only from its test-only lifetime in its unsafe test mode.
The certificate lifetime setting is at least 15 minutes ([Agent Identity V1 contract] §4), so set that test-only lifetime for this test rather than lowering the setting.
`a_renewal_happy_path`, `a_request_renewal_connected`, `a_request_renewal_while_offline`, `a_multi_authority` and `a_rotation_migrates_connected_agent` need leaves that outlast a test: at least 135 seconds, 3/2 of a test's 90-second timeout, so that the agent's schedule, which renews a leaf two thirds into its lifetime, renews none of their certificates and none expires before the test ends.
An authority that backdates `notBefore`, or whose clock runs behind the runner's, needs longer leaves.
On an authority with shorter leaves these tests report `SKIP`; the mock's default 90-day leaves meet the need.
`--expect-channel` defaults to `true`; use `--expect-channel false` when the server intentionally omits `config.agent_channel_url`.
When no authority offers the channel, gRPC-dependent checks report `SKIP`; HTTP confirm checks and channelless renewal still run.

`PASS` and `FAIL` report assertions, and `N/A` marks a test that does not apply to the platform or that the authority's module declares unsupported, so mock-only tests report `N/A` on DVLS.
`SKIP` means the target lacks a required fixture, privilege or channel.
Any `SKIP` makes the run incomplete and exits nonzero unless `--allow-incomplete` is set.
The final summary reports counts, per-category durations and the reason for every non-PASS test.

The runner reports a unique `KEY NAME PREFIX` of `conformance-<32 lowercase hex digits>` for each run and writes it to `__debug__.identity.key_name_prefix` in every generated `agent.json`.
Key names must be `<prefix>_<lowercase hyphenated UUID>`; file-backed keys live at `<data-dir>/identity/keys/<key_name>.p8`.
The runner reads each key's storage from the `key_storage` of its `identity.json` slot or in-progress record, expects every key created without a key storage policy in the agent's built-in default (the Windows software provider on Windows, key files elsewhere), and gives the agent other storages through the mock's key storage policy control.
Cases that need two available key storages run on Windows only and report `N/A` elsewhere.
Each agent test's `<data-dir>` is a new `identity-agent-XXXXXX` directory under `--work-dir`.
Windows paths are limited to 259 characters without long-path support, and a key storage policy can put keys in files on Windows too, so there the runner fails before any test when `--work-dir` is longer than 79 characters, which would leave too little room for a key file path.
Only keys whose part before the first `_` equals the run prefix belong to that run.
After each agent test, the runner fails if any key with that prefix is absent from `identity.json` and `<data-dir>/identity/pending/<hex>.in-progress.json`, or recorded there with another key storage, then deletes only run-prefixed machine and file-backed keys on either target.
When an agent test fails or times out, the runner keeps the `<data-dir>` of the agent run that failed, with the agent's `agent-stdout.log` and `agent-stderr.log`, and prints `KEPT <test> <data-dir>`; it deletes the `<data-dir>` of a run that passed.
A kept `<data-dir>` holds no run-prefixed key, but may hold the test's pending enrollment tokens.
When the runner fails, the testsuite keeps its work directory, which holds the runner's `--work-dir`.
It rejects unrecorded `*.p8` files and PKCS#8 private keys anywhere under `<data-dir>/identity`, plus leftover temporary siblings of pending and key files; other unknown files produce warnings.
A temporary sibling of `identity.json` or of an in-progress record also produces a warning, because stopping the agent can cut that record's atomic write short.
On Unix, file-backed keys must have mode `0600` and be owned by the agent's uid.
Windows software provider keys must allow only the agent's account and SYSTEM, regardless of `acl_grant_current_user`; when the agent runs as SYSTEM, only SYSTEM is expected.
The Windows software provider stores keys as machine keys, which only an elevated administrator can create, so in an unelevated Windows run every test that starts the agent reports `SKIP`.
The SYSTEM fixture requires an elevated administrator unless the suite already runs as SYSTEM; without this fixture, the Windows non-exportability case reports `SKIP`.
`--authority-id` and `--second-authority-id` check server and stored authority IDs when supplied; they do not control cleanup.
The runner stops after 14 minutes 30 seconds; the testsuite allows 15 minutes and terminates the runner's process tree on timeout.

## Several authorities

`--leaf-lifetime-secs`, `--expect-channel`, `--disposable-dvls-target` and `--dvls-rotation-window-secs` declare the profile of the authorities that `--base-url` and `--second-base-url` name.
Each `--authority <spec>` adds an authority with its own profile, so that one DVLS run can cover checks that need differently configured authorities:

```powershell
$env:C_APP_SECRET = '<app-secret>'
.\target\debug\agent-identity-conformance.exe --target dvls <first and second authority flags> `
  --authority "base-url=https://localhost:15512,app-key=<app-key>,app-secret-env=C_APP_SECRET,extra-trusted-root=c.pem,leaf-lifetime-secs=7776000,expect-channel=false,disposable-dvls-target=true"
```

A spec is comma-separated `<key>=<value>` items, and values cannot contain commas.
Its keys are the names, without `--`, of the flags above and of `--base-url`, `--app-key`, `--authority-id` and `--extra-trusted-root`, with the same values, plus the required `app-secret-env`, which names the environment variable that holds the application secret, to keep it off the command line.
Each test runs on the first authority, in the order of their flags, that offers what the test needs: the agent channel or none, a disposable target, leaves of at most 30 seconds (DVLS issues them only from its test-only lifetime), leaves that outlast a test, leaves of the certificate lifetime setting rather than a test lifetime, or a config change.
The runner reads the settings of each disposable DVLS target at the start, and counts its leaves as following the setting when its leaf lifetime equals the setting in seconds.
DVLS's management API changes a config only by switching the agent channel off and on, so a config change needs a disposable target that offers the channel.
A test that needs two authorities also takes the next one that offers what it needs.
When no authority does, the test reports `SKIP` with the first need that the first authority lacks.
The mock offers everything but an absent channel through its controls, so on the mock every test runs on the first authority, and on the second when it needs two.
A test that runs on other authorities prints `AUTHORITY <test>` and the flags that declare them, such as `--authority 1` for the first `--authority`, before its result.
`--unprivileged-app-key` names an application identity of the first authority, so a test that runs on another one runs without it.

[Agent Identity V1 contract]: ../../docs/agent-identity/CONTRACT.agent-identity.md
[mock README]: ../agent-identity-mock/README.md
