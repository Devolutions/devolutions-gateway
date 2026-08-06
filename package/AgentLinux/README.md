# Devolutions Agent container

The container enables the PowerShell Universal agent by default.
It includes `multi-pwsh`, installs its stable PowerShell channel at image build time, and configures the PSU agent to use the managed `/usr/local/bin/pwsh` alias.

`PSU_APP_TOKEN` is required when starting the container.
The other PSU settings can be overridden with environment variables.

```powershell
docker run --rm `
  --add-host host.docker.internal:host-gateway `
  --env PSU_APP_TOKEN='<application-token>' `
  devolutions/devolutions-agent:latest
```

| Environment variable | Default |
| --- | --- |
| `PSU_SERVER_URL` | `http://host.docker.internal:5006` |
| `PSU_AGENT_ID` | `devolutions-agent-linux` |
| `PSU_DISPLAY_NAME` | `Devolutions Agent Linux` |
| `PSU_HUBS` | Empty |
| `PSU_POWERSHELL_EXECUTABLE` | `/usr/local/bin/pwsh` |

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
