# Devolutions Gateway changelog

This document provides a list of notable changes introduced in Devolutions Gateway by release.

## Unpublished

## 2022.2.1 (2022-05-30)
  * Migrate logging infrastructure to `tracing`
  * *dgw*: log files are now rotated on a daily basis (old log files are deleted automatically)
  * *dgw*: new `LogDirective` config option
  * *dgw*: downgrade health route logs to debug level
  * *dgw*: JMUX filtering through claims (`*` is used to generate an "allow all" rule)
  * *dgw*: optional application protocol claim in JMUX tokens to find good default ports
  * *dgw*: PowerShell via SSH application protocol has been renamed from `pwsh` to `ssh-pwsh`
  * *dgw*: new known application protocols
    * PowerShell via WinRM (`winrm-http-pwsh`, `winrm-https-pwsh`)
    * VNC (`vnc`)
    * SCP (`scp`)
    * HTTP (`http`)
    * HTTPS (`https`)
  * *jetsocat*: process watcher option (`--watch-parent`, `--watch-process`)
  * *jetsocat*: pipe timeout option (`--pipe-timeout`)
  * *jetsocat*: HTTP(S) tunneling (proxy) listener for JMUX proxy (`http-listen://<BINDING_ADDRESS>`)

## 2022.1.1 (2022-03-09)
  * `diagnostics/configuration` endpoint now also returns Gateway's version
  * New `diagnostics/clock` endpoint to troubleshoot clock drift
  * Initial KDC proxy implementation
  * Windows installer (MSI) now installs Gateway service as "Local Service" (fewer permissions)

## 2021.1.7 (2021-12-07)
  * JMUX multiplexing protocol implementation for `jetsocat` and gateway server
  * Improve various startup validations and diagnostics
  * Support for generic plain TCP forwarding (e.g.: raw `SSH` forwarding)
    This requires sending a preconnection PDU containing an appropriate token
  * Duplicate root HTTP endpoints under /jet (this help simplifying routing configurations)
  * Support for alternative hosts to try in successive order
  * Token reuse mitigation based on IP address (RDP protocol requires to connect multiple times
    and previously used token can't just be rejected)

## 2021.1.6 (2021-08-11)
  * `jetsocat` now builds for Apple Silicon (aarch64-apple-darwin)
  * Update SOGAR and replace sogar-cli with sogar-core
  * Authorization improvements (PR#174, PR#175)
  * Add an endpoint to retrieve logs (GET /diagnostics/logs)
  * Add an endpoint to retrieve configuration (GET /diagnostics/configuration)
  * Add an endpoint to list sessions (GET /sessions)

## 2021.1.5 (2021-06-22)
  * `jetsocat` tool has been rewritten and CLI overhauled
  * SOGAR registry support
    * Recorded sessions can be pushed to a registry
    * Devolutions Gateway itself can be used as a registry

## 2021.1.4 (2021-05-04)
  * Add logs to track all HTTP requests received and processed
  * Add Linux service registration support in debian package
  * Add Install/Uninstall package commands in PowerShell module

## 2021.1.3 (2021-04-13)
  * Fix infinite loop issue when the precondition pdu was not completely received
  * Fix possible stability issue with protocol peeking

## 2021.1.2 (2021-03-26)
  * Fix broken Linux container image (missing executable)
  * Add PowerShell module .zip/.nupkg to release artifacts
  * Add experimental session recording plugin architecture

## 2021.1.1 (2021-02-19)
  * Fix missing internal version number update

## 2021.1.0 (2021-02-19)
  * Internal upgrade from futures 0.1 to 0.3
  * TCP listener now routes both RDP and JET
  * Remove unneeded dummy HTTP listener

## 2020.3.1 (2020-12-03)
  * Fix IIS ARR websocket issue (SEC_WEBSOCKET_PROTOCOL header)
  * Update Devolutions Gateway to internal version 0.14.0

## 2020.3.0 (2020-10-27)
  * Initial PowerShell module public release
  * Update Devolutions Gateway to internal version 0.14.0
  * Support file to configure the Devolutions-Gateway (gateway.json)
  * Update CLI parameters to match parameters defined in file
  * WAYK-2211: candidate gathering jet token restriction

## 0.12.0 (2020-08-25)
  * Add Jet V3 connection test support
  * Add /jet/health route alias for /health (for simplified reverse proxy rules)

## 0.11.0 (2020-05-28)
  * Fix websocket connection. Enable HTTP upgrade for the hyper connection.
  * Add jet instance name in health response.

## 0.10.9 (2020-05-13)
  * Fix websocket listener. An error was returned by the tls acceptor. Ignore those errors.

## 0.10.8 (2020-05-12)
  * Don't panic if listeners future returns an error. Just print the error and close the application

## 0.10.7 (2020-05-12)
  * Exactly same as 0.10.6 (forced re-deployment)

## 0.10.6 (2020-05-12)
  * Exactly same as 0.10.5 (forced re-deployment)

## 0.10.5 (2020-05-11)
  * Exactly same as 0.10.4 (forced re-deployment)

## 0.10.4 (2020-05-11)
  * Add module name in logs.
  * Add curl to Docker container.

## 0.10.3 (2020-05-08)
  * Exactly same as 0.10.2 (forced re-deployment)

## 0.10.2 (2020-05-05)
  * Remove color from logs

## 0.10.1 (2020-03-26)
  * Exactly same as 0.10.0 (workaround to deploy a new version in prod without issue with ACI)

## 0.10.0 (2020-03-23)
  * Add provisioner public key
  * DVC with GFX integration
  * Fixes an issue where some associations were not removed (ghost associations).
