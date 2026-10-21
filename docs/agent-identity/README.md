# Agent Identity

Agent Identity gives a device running Devolutions Agent a durable identity with an authority, such as DVLS: an X.509 certificate for a private key that never leaves the device.
After the device enrolls once with an enrollment token, the agent renews the certificate on its own and keeps a channel open for the authority to push messages.
The [design intent][intent] explains why it works this way, and the [contract] defines the protocol between the agent and an authority.

A device holds at most one identity per authority, and enrolling with one authority never affects an identity held with another.

## Enroll a device

Get an enrollment token from your authority.
A token starts with `dvaet1.`, can enroll many devices up to its use limit, and expires.
Treat it as a secret, because anyone holding it can enroll new devices with your authority.

To enroll while installing on Windows, set the installer's `IDENTITY_ENROLLMENT_TOKEN` property, as described in the [installer README][installer].

To enroll an installed agent, pass the token on standard input:

```powershell
Get-Content -Raw 'C:\Secure\enrollment-token.txt' |
    & "$Env:ProgramFiles\Devolutions\Agent\DevolutionsAgent.exe" identity enroll -
```

`identity enroll -` reads the token from the first line of standard input, so the token never appears in a process listing or an installer log.
`identity enroll <token>` also works, but exposes the token on the command line.

On Windows, run the command as SYSTEM or from an elevated administrator prompt; any other account is refused.

- As SYSTEM, as the installer does, it works even if the service has never started.
- As an elevated administrator, it hands the token to the service through a drop box the service creates when it starts.
  Until the service has started once, the command fails and asks you to start the Devolutions Agent service.
  An administrator can submit a token this way but can't read it back.

On Linux and macOS, run the command as the account that runs the agent service.

The command only validates the token's format and stores the token in a pending-enrollment file; it never contacts the authority.
It prints the file's path and exits with status 0, or exits with a nonzero status if the token is malformed or can't be stored.
The agent service then enrolls in the background: it reads pending files when it starts and every 5 seconds.
On success, it logs `Agent Identity enrolled` with the authority and identity IDs.

Running the command again with the same token is a no-op, whether the device enrolled or the authority refused the token.
An install command that runs again, for example on an upgrade, therefore changes nothing.
A different token always enrolls a new identity, which replaces the device's identity with that authority.
The replaced identity stays on the authority until you revoke or delete it there.

## Configure Agent Identity

Agent Identity reads the `Identity` section of `agent.json`, in the agent's data directory:

```json
{
  "Identity": {
    "Enabled": true,
    "KeyBackend": "WindowsSoftwareProvider"
  }
}
```

| Setting | Values | Default |
| --- | --- | --- |
| `Enabled` | `true` or `false` | `true` |
| `KeyBackend` | `WindowsSoftwareProvider` or `File` | `WindowsSoftwareProvider` on Windows, `File` elsewhere |

With `Enabled` set to `false`, the service neither enrolls nor renews, and `identity enroll` still stores tokens for later.
The service reads these settings when it starts, so restart it after a change.

`WindowsSoftwareProvider` keeps device keys as machine keys in the Microsoft Software Key Storage Provider, and `File` keeps them as PKCS#8 files in the data directory.
Choose the backend before enrolling.
The agent looks for keys only in the configured backend and never falls back to another, so switching backends loses every enrolled identity as `key_lost`, and each needs a different token to enroll again.

Settings under `__debug__.identity` exist only for tests: they are unsupported, the agent logs a warning at start-up when any is set, and none belongs in production.
The [agent's identity module intent][agent-intent] lists them.

## Where the state lives

Agent Identity keeps its state in the `identity` folder of the agent's data directory:

- Windows: `%ProgramData%\Devolutions\Agent\identity`
- Linux: `/etc/devolutions-agent/identity`
- macOS: `/Library/Application Support/Devolutions Agent/identity`

| Path under `identity` | Content |
| --- | --- |
| `pending/` | Tokens waiting for enrollment: DPAPI-encrypted `.dat` files on Windows, `.json` files elsewhere |
| `rejected/` | One marker per token the authority refused permanently, holding no secret |
| `authorities/<authority_id>/identity.json` | The identity held with that authority: its IDs, config, certificate chains and key names |
| `keys/` | Device keys of the `File` backend |

With the `WindowsSoftwareProvider` backend, device keys are machine keys named `devolutions-agent-identity_<uuid>` instead.
On Windows, the folder grants access to SYSTEM only, except that Administrators can add files to `pending`, which `identity enroll` relies on.

Leave everything in the `identity` folder to the agent; `identity enroll` and, on Windows, a full uninstall are the supported ways to change it.

- Don't edit, move or delete its files.
  Deleting an identity's current key ends the identity as `key_lost`, and deleting a rejection marker or an identity lets the same token enroll the device again.
- Don't create device keys whose names start with `devolutions-agent-identity_`.
  The agent owns that prefix and, at start-up, deletes every such key it hasn't recorded.
- Don't change owners or permissions.
  The agent resets them on its directories at start-up, and while it can't trust a stored identity's directory, it stops all identity processing.

## After enrollment

### Renewal

The agent renews each certificate on its own, about two-thirds into its lifetime, or as soon as the authority asks.
With the authority's default lifetime of 90 days, that is between day 60 and day 67.5.
Each renewal replaces the device key, and the service logs `Agent Identity certificate renewed`.
A failed attempt is retried after a growing delay of at most one hour, and restarting the service retries at once.
A device that was offline can still renew until its certificate has been expired for as long as it was valid; after that, the identity ends.

### Channel and check-in

When the identity's config from the authority includes an `agent_channel_url`, the agent keeps a gRPC channel open to it over HTTP/2.
The authority pushes config changes and renewal requests through the channel, and features that need push, such as PEDM policies, require it.
After a stream closes, the agent reconnects after a growing delay: at most 5 minutes after network errors or server downtime, and at most one hour when the path can't carry gRPC, for example through a reverse proxy without HTTP/2.

While no channel works, the agent checks in instead: an HTTPS request that fetches the config and any renewal request.

- Without an `agent_channel_url`, it checks in when the service starts or the device enrolls, then every 24 hours ±10%.
- With one, it checks in once no stream has authenticated for an hour, then every 24 hours ±10% until a stream authenticates.

### When an identity ends

An identity ends when the authority revokes or deletes it, or refuses a renewal because the certificate expired beyond its grace.
The agent learns of it from the authority's answer to its next request.
It then records the identity as rejected, logs `The Agent Identity is rejected; it stops renewing and checking in` with the reason in `code`, and never contacts the authority for that identity again.
The same happens, with the code `key_lost`, when the identity's current device key no longer exists.

Revocation is final.
Running the same token again is a no-op, and only an enrollment with a different token brings the device back, as a new identity.
The ended identity keeps its files and keys until a new identity replaces it or the agent is uninstalled.

### Upgrade and uninstall

On Windows, a major upgrade, a repair or a maintenance run keeps every identity and its keys.
A full uninstall deletes the `identity` folder, rejection markers included, and every device key of Agent Identity, without contacting any authority.
A reinstall therefore behaves like a freshly imaged device: even after a revocation, the same token, if still valid, enrolls a new identity and uses up a token use.
Revoke or delete the old identity on the authority.

## Troubleshooting

### Service log

The service logs Agent Identity events in the agent's log files, in its data directory by default.

| Log message | Meaning and action |
| --- | --- |
| `Agent Identity enrollment will retry` | Enrollment failed for the transient `reason` shown; the agent retries. Check the network path, proxy and TLS trust to the authority. |
| `Discarded permanently rejected Agent Identity enrollment` | The authority refused the token as `token_invalid`, `token_expired` or `token_exhausted`, shown in `reason`. Enroll with a different token. |
| `Discarded revoked Agent Identity enrollment` | The identity this token created was revoked. Enroll with a different token. |
| `Could not decrypt Agent Identity pending file; discarded it` | A Windows pending file couldn't be decrypted. Run the enrollment command again. |
| `Agent Identity renewal will retry`, `Agent Identity confirmation will retry`, `Agent Identity check-in will retry` | The request failed for the transient `error` shown; the agent retries. |
| `The Agent Identity is rejected; it stops renewing and checking in` | The identity ended for the reason in `code`; see [When an identity ends](#when-an-identity-ends). |
| `Agent Identity state is unavailable; fix the identity directory ownership and ACL for the service account` | The agent can't trust its state in `directory`, typically after an owner or permission change there. Restore the service account as its owner with exclusive access; the agent retries on its own. |
| `Agent Identity key backend is unavailable; Agent Identity is stopped` | See [Key backend unavailable](#key-backend-unavailable). |
| `Agent Identity debug settings are enabled; remove __debug__.identity for production` | Remove the `__debug__.identity` section from `agent.json`. |

### Key backend unavailable

When the configured `KeyBackend` can't exist on the platform, such as `WindowsSoftwareProvider` on Linux, or isn't available on the machine, the agent stops Agent Identity before it touches any pending file or identity.
It logs `Agent Identity key backend is unavailable; Agent Identity is stopped` and raises system event 1100, `Agent Identity key backend unavailable`, with the backend name and the error.
On Windows, the event is in the Application log under the source `Devolutions Agent`; on Linux and macOS, it is in syslog under `devolutions-agent`.
The rest of the agent keeps running, and Agent Identity never falls back to another backend.
Make the backend available, or set `KeyBackend` to one that is, then restart the service; switching backends loses enrolled identities.

### Proxies and TLS

Identity requests and the channel go through the proxy set in the `Proxy` section of `agent.json`, like the agent's other outbound HTTP requests.
Known limitation: SOCKS4 and SOCKS4a proxies don't work, because the agent's HTTP library sends a malformed SOCKS4 request; use an HTTP, HTTPS, SOCKS5 or SOCKS5h proxy instead.

The authority's HTTPS certificate must validate against the device's OS trust store; the agent supports no other trust path.
Otherwise, every request fails as a transient error, and the agent keeps retrying.

### Clock skew

The authority refuses a signed request whose timestamp is too far from its own clock: more than 60 seconds ahead or 120 seconds behind.
The agent then retries once at the authority's time; if requests still fail, the retry warnings show `identity request clock skew`.
Keep the device clock synchronized.

## Related documents

- [Contract][contract]: the protocol between the agent and an authority.
- [Design intent][intent], shared by every Agent Identity component.
- [Agent identity behaviour][agent-identity-intent]: pending enrollments, stored identities, schedules and local state.
- [Agent identity module][agent-intent]: the `identity` command and configuration.
- [Device keys][device-key-intent] and [agent channel client][channel-intent].
- [Windows installer intent][installer-intent] and [installer README][installer].
- [Test vectors][vectors], checked independently by [`verify_vectors.py`][verify-vectors].
- [Mock authority][mock] and [conformance suite][conformance].

[intent]: INTENT.agent-identity.md
[contract]: CONTRACT.agent-identity.md
[vectors]: test-vectors.json
[verify-vectors]: verify_vectors.py
[agent-identity-intent]: ../../crates/agent-identity/INTENT.md
[agent-intent]: ../../devolutions-agent/src/identity/INTENT.md
[device-key-intent]: ../../crates/device-key/INTENT.md
[channel-intent]: ../../crates/agent-channel-client/INTENT.md
[installer-intent]: ../../package/AgentWindowsManaged/INTENT.md
[installer]: ../../package/AgentWindowsManaged/README.md#agent-identity
[mock]: ../../crates/agent-identity-mock/README.md
[conformance]: ../../crates/agent-identity-conformance/README.md
