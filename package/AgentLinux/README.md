# Devolutions Agent container

The container includes `multi-pwsh` and installs PowerShell 7.6.4 for the `devolutions-agent` user at image build time.
Its `pwsh` alias resolves to that managed version for `multi-pwsh host` commands.
PowerShell Universal is disabled by default.
Supply `PSU_SERVER_URL` and `PSU_APP_TOKEN` for legacy authentication, or opt in to device enrollment below.
When enabled, PSU uses the managed `/usr/local/bin/pwsh` alias.

Start the Agent without PowerShell Universal:

```powershell
docker run --rm `
  --add-host host.docker.internal:host-gateway `
  devolutions/devolutions-agent:latest
```

Enable PowerShell Universal by supplying both settings:

```powershell
docker run --rm `
  --add-host host.docker.internal:host-gateway `
  --env PSU_SERVER_URL='http://host.docker.internal:5006' `
  --env PSU_APP_TOKEN='<application-token>' `
  devolutions/devolutions-agent:latest
```

For HTTPS, set `PSU_SERVER_URL` to an `https://` URL and trust the PSU server certificate in the container's system certificate store.

| Environment variable | Default |
| --- | --- |
| `PSU_SERVER_URL` | Empty |
| `PSU_APP_TOKEN` | Empty |
| `PSU_AGENT_ID` | `devolutions-agent-linux` |
| `PSU_DISPLAY_NAME` | `Devolutions Agent Linux` |
| `PSU_POWERSHELL_EXECUTABLE` | `/var/lib/devolutions-agent/.pwsh/bin/pwsh` |

## PSU device enrollment

Build this branch rather than using a published legacy image:

```powershell
.\package\AgentLinux\BuildAndPublishContainer.ps1 `
  -Platform linux/amd64 -ImageName psu-agent-enrollment `
  -Version local -TagLatest:$false
```

PSU must implement the PSU-1337 protocol with the full issuing chain in its signed bootstrap proof.
Obtain the root certificate's SHA-256 DER fingerprint through a separate trusted channel.
Use a short-lived, use-limited token with the `AgentEnrollment` role and purpose, not an ordinary Agent token.
Do not set `PSU_APP_TOKEN` in device mode.
PSU-created job containers keep their existing ordinary Bearer configuration and do not opt in to enrollment.

Prepare a fresh named volume owned by the image's unprivileged agent user:

```powershell
docker volume create psu-agent-identity
docker run --rm --user root --entrypoint sh `
  --mount source=psu-agent-identity,target=/identity `
  psu-agent-enrollment:local `
  -c 'chown devolutions-agent:devolutions-agent /identity && chmod 700 /identity'
```

Set `PSU_ENROLLMENT_TOKEN` and `PSU_DEVICE_ROOT_THUMBPRINT` in the caller's environment without logging their values, then launch against a disposable local PSU HTTP/2 endpoint:

```powershell
docker run --rm --name psu-device-smoke `
  --add-host host.docker.internal:host-gateway `
  --mount source=psu-agent-identity,target=/identity `
  --env PSU_SERVER_URL=http://host.docker.internal:5006 `
  --env PSU_DEVICE_ROOT_THUMBPRINT --env PSU_ENROLLMENT_TOKEN `
  --env PSU_DEVICE_STATE_DIRECTORY=/identity `
  psu-agent-enrollment:local
```

Use normally validated HTTPS for remote servers; the pinned bootstrap proof neither encrypts HTTP nor prevents an active relay.
After enrollment, remove `PSU_ENROLLMENT_TOKEN` and reuse the same volume and endpoint on restart.
Device mode sends fresh `Device` assertions, retains pending credentials, and renews certificates without the enrollment token.
Revocation or reset never triggers re-enrollment or a Bearer downgrade.
Keep the volume private and do not share it between agents.

| Device environment variable | Requirement |
| --- | --- |
| `PSU_DEVICE_ROOT_THUMBPRINT` | Required SHA-256 root fingerprint; enables device mode. |
| `PSU_DEVICE_STATE_DIRECTORY` | Required path on a persistent volume writable by the agent user. |
| `PSU_ENROLLMENT_TOKEN` | Required only before the first successful enrollment. |
| `PSU_DEVICE_HARDWARE_ID` | Optional stable provisioning identifier; otherwise a separate installation UUID is persisted. |

See [the standalone smoke procedure](../AgentWindowsManaged/README.md#testing-psu-device-enrollment-without-installing-a-service) for approval, restart, renewal, and recovery checks.

Stopping a PSU job kills the job process and its process group.
Processes that a job script moves to their own session or process group, for example with `setsid`, keep running.

Build one image locally:

```powershell
./package/AgentLinux/BuildAndPublishContainer.ps1 -Platform linux/amd64
```

Publish the AMD64 and ARM64 images as one manifest after authenticating to Docker Hub:

```powershell
docker login
./package/AgentLinux/BuildAndPublishContainer.ps1 -Push
```

The script tags the image with the repository `VERSION` and `latest`.
Use `-Version`, `-ImageName`, `-MultiPwshVersion`, or `-TagLatest:$false` to override the defaults.
