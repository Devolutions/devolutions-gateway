# 🚪 Devolutions Gateway – Container Entry Point

This container entry script configures and runs the **Devolutions Gateway** using environment variables. It is compatible with both Docker and Azure Web App (Linux) deployments.

## 🚀 Simple Example

Run this:

```powershell
docker run -it --rm `
  -e PORT=7171 `
  -p 7171:7171 `
  -e WEB_APP_ENABLED=true `
  devolutions-gateway:latest
```

Then open http://localhost:7171

---

## 🌐 Web Listener Configuration

| Variable                  | Description                                                        | Default    |
|---------------------------|--------------------------------------------------------------------|------------|
| `WEB_SCHEME`              | Internal web scheme: `http` or `https`                             | `http`     |
| `WEB_PORT` or `PORT`      | Internal port for the web listener                                 | `7171`     |
| `EXTERNAL_WEB_SCHEME`     | Scheme used externally (e.g. `https` behind a proxy)               | `WEB_SCHEME` |
| `EXTERNAL_WEB_PORT`       | Port exposed externally to clients                                 | `WEB_PORT` |
| `HOSTNAME`                | Hostname for certificate and configuration                         | `localhost` |
| `WEBSITE_HOSTNAME`        | Azure App hostname (auto-detected)                                 | *(Azure)*  |
| `WEBSITE_INSTANCE_ID`     | Azure instance ID (forces external scheme to `https`, port 443)    | *(Azure)*  |

---

## 🔌 TCP Listener Configuration

| Variable             | Description                                                    | Default  |
|----------------------|----------------------------------------------------------------|----------|
| `TCP_ENABLED`        | Enables the TCP listener                                        | `true`   |
| `TCP_PORT`           | Internal TCP listener port                                     | `8181`   |
| `EXTERNAL_TCP_PORT`  | External TCP port                                              | `TCP_PORT` |
| `TCP_HOSTNAME`       | External hostname for TCP listener                             | `*`      |

> When `WEB_APP_ENABLED=true`, `TCP_ENABLED` is disabled by default because it is not used in standalone web access.

---

## 🔐 Web App Configuration

| Variable                 | Description                                            | Default |
|--------------------------|--------------------------------------------------------|---------|
| `WEB_APP_ENABLED`        | Enables the embedded admin Web UI                     | `false` |
| `WEB_APP_AUTHENTICATION` | Auth mode: `None` or `Custom`                         | `None`  |
| `WEB_APP_USERNAME`       | Username for custom auth                              | unset   |
| `WEB_APP_PASSWORD`       | Password for custom auth                              | unset   |

---

## 🎥 Session Recording & Logging

| Variable            | Description                                        | Default |
|---------------------|----------------------------------------------------|---------|
| `RECORDING_PATH`    | Directory path to store session recordings         | unset   |
| `VERBOSITY_PROFILE` | Logging verbosity level (`Default`, `Debug`, `Tls`, `All`, `Quiet`) | unset   |

---

## 🔑 Provisioner Key Injection

Use these to inject a pre-generated key pair into the container:

| Variable                     | Description                            |
|------------------------------|----------------------------------------|
| `PROVISIONER_PUBLIC_KEY_B64`| Base64-encoded `.pem` public key       |
| `PROVISIONER_PRIVATE_KEY_B64`| Base64-encoded `.key` private key     |

- If neither is provided, a new key pair will be generated.

---

## 🔐 TLS Certificate Injection

Use these to inject a TLS certificate and private key into the container:

| Variable                  | Description                                |
|---------------------------|--------------------------------------------|
| `TLS_CERTIFICATE_B64`     | Base64-encoded TLS certificate `.pem`      |
| `TLS_PRIVATE_KEY_B64`     | Base64-encoded private key `.key`          |
| `TLS_CERTIFICATE_PASSWORD`| Optional password for encrypted certificate |

- If not set and `WEB_SCHEME=https`, a self-signed cert will be generated using OpenSSL.

---

## 🧪 Health Check

The Devolutions Gateway HTTP health check endpoint is `/jet/health`

---

## 🧪 Sample Usage

Launching Devolutions Gateway with a provisioner public key, an HTTP listener, a TCP listener, using a reverse proxy for HTTPS and external access:

```powershell
$Env:PROVISIONER_PUBLIC_KEY_B64  = [Convert]::ToBase64String([IO.File]::ReadAllBytes("provisioner.pem"))

docker run -it --rm `
  --name gateway-test `
  -p 7171:7171 `
  -p 8181:8181 `
  -e WEB_PORT=7171 `
  -e TCP_PORT=8181 `
  -e WEB_SCHEME=http `
  -e EXTERNAL_WEB_SCHEME=https `
  -e HOSTNAME=gateway.contoso.local `
  -e VERBOSITY_PROFILE=all `
  -e PROVISIONER_PUBLIC_KEY_B64=$Env:PROVISIONER_PUBLIC_KEY_B64 `
  devolutions-gateway:latest
```

Launching Devolutions Gateway with a provisioner public key, an HTTPS listener with a certificate, external hostname, and TCP listener:

```powershell
$Env:PROVISIONER_PUBLIC_KEY_B64  = [Convert]::ToBase64String([IO.File]::ReadAllBytes("provisioner.pem"))
$Env:TLS_CERTIFICATE_B64         = [Convert]::ToBase64String([IO.File]::ReadAllBytes("server.crt"))
$Env:TLS_PRIVATE_KEY_B64         = [Convert]::ToBase64String([IO.File]::ReadAllBytes("server.key"))

docker run -it --rm `
  --name gateway-test `
  -p 7171:7171 `
  -p 8181:8181 `
  -e WEB_PORT=7171 `
  -e TCP_PORT=8181 `
  -e WEB_SCHEME=https `
  -e HOSTNAME=gateway.contoso.local `
  -e VERBOSITY_PROFILE=all `
  -e PROVISIONER_PUBLIC_KEY_B64=$Env:PROVISIONER_PUBLIC_KEY_B64 `
  -e TLS_CERTIFICATE_B64=$Env:TLS_CERTIFICATE_B64 `
  -e TLS_PRIVATE_KEY_B64=$Env:TLS_PRIVATE_KEY_B64 `
  devolutions-gateway:latest
```

Launching Devolutions Gateway with a provisioner public key, with a custom TCP hostname and port used for external access:

```powershell
$Env:PROVISIONER_PUBLIC_KEY_B64  = [Convert]::ToBase64String([IO.File]::ReadAllBytes("provisioner.pem"))

docker run -it --rm `
  --name gateway-test `
  -p 7171:7171 `
  -p 8181:8181 `
  -e WEB_PORT=7171 `
  -e TCP_PORT=8181 `
  -e WEB_SCHEME=http `
  -e EXTERNAL_WEB_SCHEME=https `
  -e HOSTNAME=gateway.contoso.local `
  -e TCP_HOSTNAME=tcp.contoso.local `
  -e EXTERNAL_TCP_PORT=9191 `
  -e VERBOSITY_PROFILE=all `
  -e PROVISIONER_PUBLIC_KEY_B64=$Env:PROVISIONER_PUBLIC_KEY_B64 `
  devolutions-gateway:latest
```

Launching Devolutions Gateway with an injected provisioner key pair and certificate:

```powershell
$Env:PROVISIONER_PUBLIC_KEY_B64  = [Convert]::ToBase64String([IO.File]::ReadAllBytes("provisioner.pem"))
$Env:PROVISIONER_PRIVATE_KEY_B64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("provisioner.key"))
$Env:TLS_CERTIFICATE_B64         = [Convert]::ToBase64String([IO.File]::ReadAllBytes("server.crt"))
$Env:TLS_PRIVATE_KEY_B64         = [Convert]::ToBase64String([IO.File]::ReadAllBytes("server.key"))

docker run -it --rm `
  --name gateway-test `
  -p 7171:7171 `
  -e PORT=7171 `
  -e WEB_SCHEME=https `
  -e WEB_APP_ENABLED=true `
  -e RECORDING_PATH=/tmp/recording `
  -e VERBOSITY_PROFILE=all `
  -e PROVISIONER_PUBLIC_KEY_B64=$Env:PROVISIONER_PUBLIC_KEY_B64 `
  -e PROVISIONER_PRIVATE_KEY_B64=$Env:PROVISIONER_PRIVATE_KEY_B64 `
  -e TLS_CERTIFICATE_B64=$Env:TLS_CERTIFICATE_B64 `
  -e TLS_PRIVATE_KEY_B64=$Env:TLS_PRIVATE_KEY_B64 `
  devolutions-gateway:latest
```
