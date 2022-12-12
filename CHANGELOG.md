# Devolutions Gateway changelog

This document provides a list of notable changes introduced in Devolutions Gateway by release.

## [Unreleased]

## 2022.3.3 (2022-12-12)

### Improvements

- _dgw_: set default TCP port to 8181 ([#364](https://github.com/Devolutions/devolutions-gateway/issues/364)) (9df3a0e6d0b675043b1d4fcd46848701d03e27c1) ([DGW-66](https://devolutions.atlassian.net/browse/DGW-66))

- Normalize file extensions ([#367](https://github.com/Devolutions/devolutions-gateway/issues/367)) (5d26d7338fad9bbb5acfb6f267f7ae6a1051ca42) ([DGW-67](https://devolutions.atlassian.net/browse/DGW-67))

  By convention:

  - .pem -> public key
  - .key -> private key
  - .crt -> certificate

  Note that this is merely a convention, not a standard, and file openers
  should be able to select a .key file when choosing a public key (through
  the drop-down menu typically)

- _installer_: start the Gateway service at install time ([#363](https://github.com/Devolutions/devolutions-gateway/issues/363)) (b07ccd4ed9b9beabeb3fcac803705cc4d74837fe)

### Bug Fixes

- _dgw_: Accept header parsing in health route ([#366](https://github.com/Devolutions/devolutions-gateway/issues/366)) (136cfb040b72ae09a26e9bc470a4767222154cbf) ([DGW-68](https://devolutions.atlassian.net/browse/DGW-68))

## 2022.3.2 (2022-11-25)

### Improvements

- _installer_: install service as "Local Service" again (fewer permissions) ([#353](https://github.com/Devolutions/devolutions-gateway/pull/353), [#354](https://github.com/Devolutions/devolutions-gateway/pull/354))
- _jetsocat_: automatically clean old log files ([#346](https://github.com/Devolutions/devolutions-gateway/pull/346)) (d0325307e7c5c8d38b05ebf5218729e0d21795a2)
- _dgw_: IPv6 support ([#350](https://github.com/Devolutions/devolutions-gateway/pull/350)) (d591085a6974f1a9c59bf66a094a09cd3d4d9f3e)
- _dgw_: support for full TLS certificate chain ([#359](https://github.com/Devolutions/devolutions-gateway/pull/359)) (ee1f560fd534fd19d5704da96f0138be0247abc8)

### Features

- _installer_: enable configuration of Devolutions Gateway via installer UI on Windows ([#348](https://github.com/Devolutions/devolutions-gateway/pull/348)) (6392ed9f860e3df80adca1709bf8fda2b43d6035)

### Build

- _dgw_: disable sogar ([#355](https://github.com/Devolutions/devolutions-gateway/pull/355)) (90d57ac4d9d108f7196609e34d7802ecd7e8160f)

## 2022.3.1 (2022-10-03)

### Improvements

- _dgw_: improve CLI output ([#338](https://github.com/Devolutions/devolutions-gateway/pull/338)) (d7bd9dc67c25dc7b67d1f10d8ce77290ec32186a)

### Features

- _dgw_: extend subkey capabilities to KDC tokens ([#334](https://github.com/Devolutions/devolutions-gateway/pull/334)) (cdc53d0e989b091800f02489d2ce4d5ce9763ac1)

  With this change, a subkey is allowed to sign a short-lived KDC token.

### Build

- _jetsocat-nuget_: add win-arm64 to nuget package ([#339](https://github.com/Devolutions/devolutions-gateway/pull/339)) (2a676caddfd1ba8c437ed6f20e6f646bae64326f)

## 2022.3.0 (2022-09-21)

### Bug Fixes

- _dgw_: revert `service as "Local Service"` (c4f8d24d5d3599ce7cfa73d0c3169b65296b65f7) 

- _dgw_: Content-Type header present twice for Json responses ([#315](https://github.com/Devolutions/devolutions-gateway/pull/315)) (c0976d85f3e0bc344cc2c7e3f97d527b343493ac) 

  Indeed, `Content-Type` is a "singleton field": a single member is anticipated as the field value.
  
  RFC9110 says:
  
  > Although Content-Type is defined as a singleton field,
  > it is sometimes incorrectly generated multiple times,
  > resulting in a combined field value that appears to be a list.
  > Recipients often attempt to handle this error by using
  > the last syntactically valid member of the list, leading to
  > potential interoperability and security issues if different
  > implementations have different error handling behaviors.

- _jmux-proxy_: properly cancel proxy task ([#327](https://github.com/Devolutions/devolutions-gateway/pull/327)) (f62143eb4abeef104477cabfb1380573c5f0cceb) 

  Previously, JMUX proxy task wasn't properly shut down because tokio
  tasks are detached by default (similar to `std::thread::spawn`). This
  adds a helper wrapper to explicitely specify whether a task should be
  joined or detached.

### Features

- OpenAPI document and auto-generated C# and TypeScript clients

- _dgw_: retrieve KDC token from the path (f9b66c11f57028a54bbce22be443e07736d6890b) 

- _dgw_: subkey tokens ([#287](https://github.com/Devolutions/devolutions-gateway/pull/287)) (bebee0ed59cf0d150259f061c95e5d0c47eaa7bf) 

- _dgw_: support for CORS calls ([#288](https://github.com/Devolutions/devolutions-gateway/pull/288)) (388b1f6efb1f333bf0e7d6af4e6d43445914951c) 

- _dgw_: expose gateway ID in configuration endpoint (f15d33a072cbcf534d56331b18294adf6315ea1d) 

- _dgw_: add general claim `jet_gw_id` ([#293](https://github.com/Devolutions/devolutions-gateway/pull/293)) (7a22ea1d0d2011ca83a4162d569ee78aa25d1dc0) 

  When this claim is specified, a given token can only be used on a Gateway with the very same ID.

- _dgw_: wildcard scope tokens ([#294](https://github.com/Devolutions/devolutions-gateway/pull/294)) (1c98c151f93179a84873c74eba369bac3827410e) 

- _dgw_: config pushing endpoint (8ff1ebed0dc5c91180eeeba55ec1adf3ff803143) 

- _dgw_: lossless and simpler config DTO (ba6830144dd4f1bf4e1da9a84a0580d13aeb93b8) 

- _dgw_: subscriber API (a80282ebd71992ee7ee32e90e2943e836c9985ba) 

- _dgw_: add --config-init-only cli option (89cd2b775e6a39b3b6d8da51ba8f2ea6ac27b720) 

- _dgw_: limit JMUX wildcard addresses ([#302](https://github.com/Devolutions/devolutions-gateway/pull/302)) (8a95130e515d5625d76d1cb699c7b12d402b0266) 

  The same port must be used.

- _dgw_: `jet/health` endpoint now returns Gateway identity

  The `Accept` HTTP header must be set to `application/json` for this.

- _powershell_: update module (71e15a4d52c876a7ca35fcf8794ded6e4f624eca) 

  - Deprecate `PrivateKeyFile` and `CertificateFile` in favor of
  `TlsPrivateKeyFile` and `TlsCertificateFile`.  This change is backward
  compatible (older naming are recognized by cmdlets).
  
  - Add `Id`, `Subscriber` and `SubProvisionerPublicKey` to config class.
  
  - Allow `Set-DGatewayConfig` to set `Id`, `Subscriber` and
  `SubProvisionerPublicKey` values.

- _dgw_: forced session termination support (16c119b025620e5ebd3a9a2e877a9aab8533abba) 

  This adds the endpoint `POST /jet/session/<id>/terminate`.
  This is similar to what we had back in Wayk Bastion except it’s not P2P.

- _dgw_: maximum session lifetime enforcing (9b801624fc4eeaef34da822287f4ee814d9e63e6) 

  This adds a new claim `jet_ttl` specifying the maximum lifetime for a
  given session. Devolutions Gateway will kill the session if it is still
  running after the deadline.

- _jetsocat_: HTTP proxy listener (04bd6da206b71b130f8b535804b94771dcdd5f4f) 

  HTTP proxy listener now handles both HTTPS (tunneling) proxy requests
  and HTTP (regular forwarding).

### Security

- _dgw_: Smaller token reuse interval for RDP sessions (832d00b6c10680a50faa0e77c2db27a86f798741) 

  With this change, we do not allow reuse for RDP sessions more than a few
  seconds following the previous use. The interval is 10 seconds which is
  expected to give plenty of time to RDP handshake and negotiations. Once
  this interval is exceeded, we consider the RDP session is fully started
  and the same token can't be reused anymore.
  
  Two reasons why this is beneficial:
  
  - Security wise: the reuse interval is considerably shortened
  - Feature wise: more efficient forced RDP session termination
  
  Regarding the second point: Windows’ mstsc will keep alive the session
  by re-opening it immediately. Because we allow token reuse in a limited
  fashion for RDP, as long as the association token is not expired,
  the terminate action has effectively no visible effect (besides that
  multiple sessions occurred). Reducing the reuse interval greatly
  improves the situation.

## 2022.2.2 (2022-06-14)

- Update dependencies with CVE reports

- *pwsh*: update token generation cmdlet

- *dgw*: remove unused `/jet/sessions/count` route

- *dgw*: lossless unknown application strings

  With this change, unknown application protocols will display session information as well.
  Previously, any unknown value was just treated as the "unknown" string.

## 2022.2.1 (2022-05-30)

- Migrate logging infrastructure to `tracing`

- *dgw*: duplicate `/jmux` and `/KdcProxy` endpoints under `/jet`

- *dgw*: log files are now rotated on a daily basis (old log files are deleted automatically)

- *dgw*: new `LogDirective` config option

- *dgw*: downgrade health route logs to debug level

- *dgw*: JMUX filtering through claims (`*` is used to generate an "allow all" rule)

- *dgw*: optional application protocol claim in JMUX tokens to find good default ports

- *dgw*: PowerShell via SSH application protocol has been renamed from `pwsh` to `ssh-pwsh`

- *dgw*: new known application protocols

  - PowerShell via WinRM (`winrm-http-pwsh`, `winrm-https-pwsh`)
  - VNC (`vnc`)
  - SCP (`scp`)
  - HTTP (`http`)
  - HTTPS (`https`)

- *jetsocat*: process watcher option (`--watch-parent`, `--watch-process`)

- *jetsocat*: pipe timeout option (`--pipe-timeout`)

- *jetsocat*: HTTP(S) tunneling (proxy) listener for JMUX proxy (`http-listen://<BINDING_ADDRESS>`)

## 2022.1.1 (2022-03-09)

- `diagnostics/configuration` endpoint now also returns Gateway's version

- New `diagnostics/clock` endpoint to troubleshoot clock drift

- Initial KDC proxy implementation

- Windows installer (MSI) now installs Gateway service as "Local Service" (fewer permissions)

## 2021.1.7 (2021-12-07)

- JMUX multiplexing protocol implementation for `jetsocat` and gateway server

- Improve various startup validations and diagnostics

- Support for generic plain TCP forwarding (e.g.: raw `SSH` forwarding)

  This requires sending a preconnection PDU containing an appropriate token

- Duplicate root HTTP endpoints under /jet (this help simplifying routing configurations)

- Support for alternative hosts to try in successive order

- Token reuse mitigation based on IP address (RDP protocol requires to connect multiple times
  and previously used token can't just be rejected)

## 2021.1.6 (2021-08-11)

- `jetsocat` now builds for Apple Silicon (aarch64-apple-darwin)

- Update SOGAR and replace sogar-cli with sogar-core

- Authorization improvements (PR#174, PR#175)

- Add an endpoint to retrieve logs (GET /diagnostics/logs)

- Add an endpoint to retrieve configuration (GET /diagnostics/configuration)

- Add an endpoint to list sessions (GET /sessions)

## 2021.1.5 (2021-06-22)

- `jetsocat` tool has been rewritten and CLI overhauled

- SOGAR registry support

  - Recorded sessions can be pushed to a registry
  - Devolutions Gateway itself can be used as a registry

## 2021.1.4 (2021-05-04)

- Add logs to track all HTTP requests received and processed

- Add Linux service registration support in debian package

- Add Install/Uninstall package commands in PowerShell module

## 2021.1.3 (2021-04-13)

- Fix infinite loop issue when the precondition pdu was not completely received

- Fix possible stability issue with protocol peeking

## 2021.1.2 (2021-03-26)

- Fix broken Linux container image (missing executable)

- Add PowerShell module .zip/.nupkg to release artifacts

- Add experimental session recording plugin architecture

## 2021.1.1 (2021-02-19)

- Fix missing internal version number update

## 2021.1.0 (2021-02-19)

- Internal upgrade from futures 0.1 to 0.3

- TCP listener now routes both RDP and JET

- Remove unneeded dummy HTTP listener

## 2020.3.1 (2020-12-03)

- Fix IIS ARR websocket issue (SEC_WEBSOCKET_PROTOCOL header)

- Update Devolutions Gateway to internal version 0.14.0

## 2020.3.0 (2020-10-27)

- Initial PowerShell module public release

- Update Devolutions Gateway to internal version 0.14.0

- Support file to configure the Devolutions-Gateway (gateway.json)

- Update CLI parameters to match parameters defined in file

- WAYK-2211: candidate gathering jet token restriction

## 0.12.0 (2020-08-25)

- Add Jet V3 connection test support

- Add /jet/health route alias for /health (for simplified reverse proxy rules)

## 0.11.0 (2020-05-28)

- Fix websocket connection. Enable HTTP upgrade for the hyper connection.

- Add jet instance name in health response.

## 0.10.9 (2020-05-13)

- Fix websocket listener. An error was returned by the tls acceptor. Ignore those errors.

## 0.10.8 (2020-05-12)

- Don't panic if listeners future returns an error. Just print the error and close the application

## 0.10.7 (2020-05-12)

- Exactly same as 0.10.6 (forced re-deployment)

## 0.10.6 (2020-05-12)

- Exactly same as 0.10.5 (forced re-deployment)

## 0.10.5 (2020-05-11)

- Exactly same as 0.10.4 (forced re-deployment)

## 0.10.4 (2020-05-11)

- Add module name in logs.

- Add curl to Docker container.

## 0.10.3 (2020-05-08)

- Exactly same as 0.10.2 (forced re-deployment)

## 0.10.2 (2020-05-05)

- Remove color from logs

## 0.10.1 (2020-03-26)

- Exactly same as 0.10.0 (workaround to deploy a new version in prod without issue with ACI)

## 0.10.0 (2020-03-23)

- Add provisioner public key

- DVC with GFX integration

- Fixes an issue where some associations were not removed (ghost associations).
