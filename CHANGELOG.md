# Devolutions Gateway changelog

This document provides a list of notable changes introduced in Devolutions Gateway by release.

## 2021.1.6 (2021-08-11)
  * `jetsocat` now builds for Apple Silicon (aarch64-apple-darwin)
  * Update SOGAR and replace sogar-cli with sogar-core
  * Authorization improvements (PR#174, PR#175)
  * Add an endpoint to retrieve logs (GET /diagnostics/logs)
  * Add an endpoint to retrive configuration (GET /diagnostics/configuration)
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
