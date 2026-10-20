# Agent Run As coverage

These checks cover an app-token HTTP connection, not complete Run As conformance.
A binary that refuses every credential-bearing launch can satisfy these checks.
Successful enrolled Windows execution remains an explicit fixture gap, not a passing or skipped acceptance test.
PSU obligations require separate checks.

## Run

Install PowerShell 7 with `pwsh` on `PATH` and the repository's Rust build prerequisites.
Run from the repository root:

```powershell
cargo test -p testsuite --test integration_tests --no-run --quiet
cargo test -p testsuite --test integration_tests psu_run_as:: -- --test-threads=1 --nocapture
```

The three executable cases have no default skips.
Missing PowerShell, failed registration, unsuccessful credential-free controls, transport loss, and timeouts are errors, never evidence that credentials were refused.
The runner builds the shipped Agent through `testsuite::cli`, writes a temporary `agent.json`, and uses foreground `run` with `DAGENT_CONFIG_PATH` pointing to that directory.
Unrelated modules are disabled, `Proxy.Mode` is `Off`, and the gRPC listener binds `127.0.0.1:0`.
Only disposable test tokens and synthetic credential strings are used.
The tests do not install a service, provision accounts, alter trust or rights, or contact a real PSU.

## Independent inputs and controls

The authority is [CONTRACT.md][contract] at `406a74ce561b72ba8c03331558965c87ba8b6ed1`.
Its Git blob SHA-256 is `9693736505da2b8d9be91e5eaf5d91d451773e35e992c27e2e6222f3dec661c8`.
Line references below identify that exact text.
`agent_control.proto` copies the public AgentControl interface at that revision and adds only the contract's credential message and field.
No enrollment messages or signing protocol are inferred.
The additional public enrollment schema at `2a2a0e8a545a4274be9d7c39760164a82aefd3e9` does not specify `server_assertion` signing or establish a usable enrollment fixture.

The fixture configuration uses only public DTO declarations in `devolutions-agent/src/config.rs`: lines 557-572, 587-611, 625-630, 639-644, 656-667, 680-758, 773-788, 846-888, and 1025-1074.
No production behavior is an expected-value source.
The valid control asks the native `pwsh` binary to write the literal `executed` into a temporary marker and exit zero.
Its successful process response and exact marker establish that the connection, executable, arguments, and working directory work before a negative assertion runs.
The control's expected output comes from that test-selected script, not a captured Agent result.

Each rejection case repeats that launch on the same connection, changing only credential presence and the correlation/stream identifiers that must be unused.
The first supplies syntactically nonempty synthetic strings; the second supplies a present empty message.
Neither synthetic credential is represented as a valid Windows account.
The oracle is refusal of any present credential on this ineligible connection, not field validation, logon failure, or an isolated authentication-versus-transport failure.
An omitted message and a present empty message differ under [proto3 message presence][presence], so accepting both would violate contract lines 15-16 and 101-105.
No diagnostic wording is prescribed; the reason must merely be nonempty and identical across the two ordered failure responses.

## Clause map

`registration` means `app_token_http_registration_does_not_advertise_run_as`.
`rejection` means both named cases of `app_token_http_rejects_present_credential`.
`control` means the successful credential-free launch required by every case.
`partial` identifies an executable check that does not establish the whole clause.
`gap` means no executable check is present; it is not an ignored test.
`peer` means a PSU obligation, not Agent coverage.

| Contract lines | Requirement or boundary | Coverage |
| --- | --- | --- |
| 3-5 | AgentControl boundary; enrollment, administration and credential-free protocol excluded | Scope and public schema reviewed; credential-free execution is only a setup/control surface. |
| 9-10 | Eligibility belongs to one live stream; replacement is a new connection | Partial: all checks use one actual stream; replacement history is a gap requiring enrolled acceptance. |
| 12-13 | Device authentication is certificate-backed and identity-bound; app tokens are not device auth even with an enrollment record | Partial: fixture has only an app token and HTTP; existing-record/enrollment-enabled variants and PSU binding are gaps/peer obligations. |
| 15-16 | Selected credential is present on the PSRP launch; empty message is present | Rejection checks nonempty and empty presence; PSRP job selection is peer. |
| 20-28 | Package, unchanged fields, field 9, string fields 1/2/3, message presence | Test-local schema derives directly from the public interface and table; rejection exercises field 9. Positive decoding and use of each credential field remain gaps. |
| 30, 37 | Proto3 encoding, default empty strings | Generated from the independently specified schema; present-empty rejection exercises default strings, not isolated default-field validation. No independent parser conformance claim. |
| 31 | Omission requests the service identity | Partial: control executes without a credential; actual service-identity SID comparison is a gap. |
| 32-33 | Omission preserves Windows/Linux/macOS, app-token and HTTP execution without Run As eligibility | Control on the platform running the suite; other platforms/configurations require their own runs. |
| 35 | Presence requests the supplied Windows identity | Ineligible presence is rejected; successful target-identity execution is a gap. |
| 36 | Nonblank username, nonempty password, no NUL in any string | Gap: each invalid-field case needs an eligible connection and a valid account control differing only in that field. Empty-message rejection does not cover this validation. |
| 39 | Exact GetNetworkCredential field mapping | Peer. |
| 40 | Empty domain selects UPN for `@`, otherwise local account | Gap: distinct pre-provisioned local/UPN accounts and eligible controls. |
| 44-46 | Exact case-sensitive capability name/version; no other pair authorizes | Partial: registration checks absence of the exact pair. PSU comparison variants are peer; eligible exact-pair advertisement is a gap. |
| 47 | Advertise iff Windows plus device auth plus verified HTTPS | Partial: registration checks the false branch on app-token HTTP. Windows enrolled verified-HTTPS true branch, app-token HTTPS, non-Windows device auth and other isolated false branches are gaps. |
| 48-49 | Use current registration; capability alone proves neither authentication nor TLS | Peer; fixture does not validate PSU authentication. |
| 51 | Windows Agent reports exactly `windows` | Registration when compiled and run on Windows. |
| 52 | Ordinal case-insensitive Windows substring check | Peer. |
| 53 | Registration is not attestation; enforce actual platform | Gap: non-Windows device-authenticated fixture is needed to isolate platform enforcement. |
| 55-60 | Before vault access require live device auth, Windows registration, exact capability and TLS 1.2/1.3 | Peer, including TLS-version controls. |
| 62-65 | Refuse without retrieval; recheck send; settings/records/IDs/schemes/headers cannot substitute; plaintext proxy final hop forbidden | Peer. |
| 67 | Normal TLS chain and hostname validation | Gap: approved application-scoped trust fixture and matched valid chain/hostname controls; no host trust changes permitted. |
| 68 | No insecure bypass, HTTP retry or enrollment proof in place of TLS validation | Gap: verified enrolled positive control plus each independently invalid transport fixture. |
| 69-70 | Accept credentials only on device-authenticated verified HTTPS on Windows; otherwise refuse | Partial: rejection checks the combined app-token HTTP false case. It does not isolate app-token HTTPS, device-authenticated HTTP, or non-Windows enforcement. |
| 71 | Eligibility cannot transfer to app-token or replacement stream | Gap: enrolled eligible stream, replacement stream and app-token reconnection fixture. |
| 75-77 | Explicit-versus-environment selection, no secret for no selection, no fallback for invalid explicit selection | Peer. |
| 79-81 | Case-insensitive variable lookup; existence/RunAs/secret/type/vault/PasswordNotRequired checks; case-insensitive PSCredential type | Peer. |
| 82-85 | Complete nonblank role matching, comma splitting/trim/empty handling, no substring grants, checks before secret retrieval | Peer. |
| 86 | Missing secret, blank username or empty password fails | Peer. |
| 87-89 | Only PSRP job launch gets credentials; imports/repository initialization/remote commands stay credential-free; no substitution | Peer. |
| 93-94 | Batch logon and native creation; runspace/startup/scripts execute as target | Gap: pre-provisioned account with known SID and batch rights, real eligible stream, and PSU PSRP integration. Native logon mode also needs independent audit evidence. |
| 95 | No user-profile loading, interactive desktop, UAC or extra rights | Review-only plus fixture gap: an external marker alone cannot establish native flags or lack of privilege grants. No production review performed here. |
| 96 | Missing batch rights or executable/directory access fails | Gap: externally provisioned accounts/ACL fixtures with one-dimension successful controls; do not alter host rights or ACLs. |
| 97 | Native Windows executable, including configured default for blank executable | PSU launcher selection is peer; empty/whitespace default with successful credentialed launch is an Agent fixture gap. |
| 98 | Target base environment plus overrides | Gap: enrolled accepted account with independently known base environment and chosen override/control values. |
| 100 | PSU refusal/resolution failure yields explanatory unsuccessful job, no credential launch | Peer. |
| 101-102 | No credential-free fallback, service-identity retry or ignored presence | Partial: rejection checks no ProcessStarted and no execution marker through failure completion for both present-message cases. Other failures and later retries remain gaps. |
| 104 | Unused IDs; ineligible connection/platform, invalid fields, logon/create failures all fail launch | Partial: fresh IDs and combined ineligible app-token HTTP case. Invalid fields, isolated platform, logon and process-creation failures require eligible controls. |
| 105 | No substitute identity and no ProcessStarted on failure | Rejection through the required failure pair plus marker check; indefinite future or out-of-band execution is not proven absent. |
| 106-109 | Writable connection: ordered StreamClosed/error/nonempty reason, then correlated ProcessCompleted/-1/not canceled/same explanation | Rejection requires the exact order and values on the live stream; heartbeat, diagnostics, stream data and late closure of the completed control stream are excluded from that response sequence. |
| 111 | Diagnostic wording is not a fixed code | Rejection asserts only nonempty and matching explanations, never literal wording. |
| 112 | PSU completes unsuccessfully without awaiting further correlation messages | Peer. |
| 113 | Disconnect proves nothing about launch and does not authorize credential-free retry | Disconnect/timeout is an error, not rejection evidence; PSU retry policy is peer and Agent post-disconnect behavior is unchecked. |
| 114 | No new retry/deduplication semantics | Review-only boundary; tests use unused IDs and demand no new duplicate-request behavior. |
| 118 | Credentials only in credential field on eligible connection | PSU sending policy is peer; the fixture deliberately sends an ineligible message to test Agent defense. Agent onward forwarding is unchecked. |
| 119 | No copying into arguments, environment, metadata, persisted config or diagnostics | Partial: received Diagnostic/StreamClosed/ProcessCompleted strings and top-level temporary captures/config files are checked for literal sentinels after a conforming rejection. Arguments/environment/outbound metadata, other persistence and encodings are gaps. |
| 120 | No credential-message/password logging; debug redacts message | Partial: literal username/password/domain absence in captured stdout/stderr/log/config files and received diagnostics. Eligible/debug paths, structural redaction, encoded values and logs outside the temporary directory remain review/fixture gaps. |
| 121 | PSU vault storage unchanged | Peer. |
| 122 | Job application output is not automatically redacted | Boundary: StreamData is not subjected to confidentiality assertions; no application-output redaction requirement is invented. |

## Required fixtures

Eligible acceptance needs a pre-enrolled Windows Agent connected to a loopback PSU fixture using device authentication over normally verified HTTPS.
Provide a documented enrollment signing/setup protocol or existing enrolled device material and application-scoped server trust configuration; proto messages alone are insufficient.
Device material and account credentials must be supplied out of band without entering source, arguments, diagnostic output or chat.
No such fixture is included or conditionally runnable here.

Successful Run As also needs an externally provisioned account with a known independent SID, batch-logon rights, access to the native executable and test working directory, and a documented base environment.
Local and UPN controls, denied-rights/access controls, and profile/desktop/privilege audit evidence need separately provisioned fixtures.
No real account logon, successful credentialed launch, rejected invalid credential field, or enrolled capability true branch has been executed by this suite.

The test-owned server accepts its configured stream but does not implement PSU certificate identity binding or a vault.
That is sufficient to exercise the Agent's defensive response on an HTTP app-token configuration, not to establish PSU authentication conformance.
No full conformance-success claim is valid until the gaps above are independently covered.

[contract]: ../../../docs/psu-agent/CONTRACT.md
[presence]: https://protobuf.dev/programming-guides/proto3/#message-type-fields-always-have-field-presence
