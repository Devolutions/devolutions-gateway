# Devolutions Agent container

The container includes `multi-pwsh` and installs PowerShell 7.6.4 for the `devolutions-agent` user at image build time.
Its `pwsh` alias resolves to that managed version for `multi-pwsh host` commands.
PowerShell Universal is disabled by default and becomes available when both `PSU_SERVER_URL` and `PSU_APP_TOKEN` are specified.
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

| Environment variable | Default |
| --- | --- |
| `PSU_SERVER_URL` | Empty |
| `PSU_APP_TOKEN` | Empty |
| `PSU_AGENT_ID` | `devolutions-agent-linux` |
| `PSU_DISPLAY_NAME` | `Devolutions Agent Linux` |
| `PSU_HUBS` | Empty |
| `PSU_POWERSHELL_EXECUTABLE` | `/var/lib/devolutions-agent/.pwsh/bin/pwsh` |

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
