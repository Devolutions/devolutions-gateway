# CI

This folder contains PowerShell scripts for CI, building, and packaging.

## Product Building Guide

- _build.ps1_ - wrapper around `cargo build` that saves to an output folder
  - handles all products and modules
- _copy-psmodule.ps1_ - copies the PowerShell module to a directory inside of `$Env:Temp`
- _package-gateway-windows.ps1_ - one-shot packaging the Gateway for Windows

| Product            | Platform            | Procedure                                              |
|--------------------|---------------------|--------------------------------------------------------|
| Gateway            | Windows (regular)   | `build.ps1 gateway`<br />`copy-ps-module.ps1`<br />`package-gateway-windows.ps1` |
| Gateway            | Windows (assembled) | `build.ps1 gateway`<br />`copy-ps-module.ps1`<br />`package-gateway-windows.ps1 -Generate`<br />`package-assembled.ps1 gateway` |
| Gateway            | Ubuntu/Debian       | `build.ps1 gateway`<br />`package-gateway-deb.ps1`     |
| Gateway            | RHEL                | `build.ps1 gateway`<br />`package-gateway-rpm.ps1`     |
| Agent       | Windows (regular)          | `build.ps1 agent`  <br />`build.ps1 pedm`<br />`build.ps1 session`<br />`package-agent-windows.ps1`          |
| Agent       | Windows (assembled)        | `build.ps1 agent`  <br />`build.ps1 pedm`<br />`build.ps1 session`<br />`package-agent-windows.ps1 -Generate`<br />`package-assembled.ps1 agent` |
| Jetsocat    | Windows/macOS/Linux        | `build.ps1 jetsocat`<br />Jetsocat is not packaged.           |
| Session     | Windows/macOS/Linux        | `build.ps1 session` <br />Session is not packaged.            |
| PEDM module        | Windows             | `build.ps1 pedm`                                              |
| PowerShell module  | Windows             | `copy-ps-module.ps1`                                          |

## What is the difference between _Windows (regular)_ and _Windows (assembled)_?

_Windows (regular)_ is the "normal" build process where the MSI is built by WiX but not signed. This is used in _ci.yaml_. _Windows (assembled)_ is a two-step process where the `-Generate` flag is used to build supporting files for the MSI, including DLLs, language transforms, and _cmd_ scripts. The MSI is assembled in second step using _package-assembled.ps1_. The two-step approach is described [here](https://github.com/oleg-shilo/wixsharp/wiki/Developer's-Guide#compiling-wix-project).

## Dependencies

To build on Windows:
- WiX Toolset v3
- MSBuild

To build on Linux:
- fpm (Ruby package)
- debhelper