# devolutions-gateway ci / cd

Devolutions Gateway and jetsocat are built and released using GitHub workflows.

There are three seperate workflows:

```
┌────┐   ┌─────────┐   ┌─────────┐
│ CI ├───► PACKAGE ├───► RELEASE │
└────┘   └─────────┘   └─────────┘
```

## CI

The "CI" workflow builds, tests and packages `devolutions-gateway` and builds `jetsocat`, for supported platforms. The workflow is run automatically for pull requests and merges, or may be run manually.

The build artifacts are **not** code-signed and not suitable for distribution.

## PACKAGE

The "Package" workflow downloads the artifacts from a **CI** workflow run, codesigning and repackaging them as appropriate. The workflow should be run manually, and will require approval.

The workflow will display a notice if `run` was not built from the main branch. Artifacts from the main branch are built with specific optimizations and are suitable for distribution.

### Parameters

- `run` The run-id of the **CI** workflow run containing the artifacts to package

### Developer Notes

- The `Codesign` job uses a matrix to code-sign and repackage in parallel. It's important to ensure that individual matrix jobs do not upload the same artifacts; otherwise the result may be unexpected. For example: each platform downloads the `jetsocat` artifact, which contains builds for several operating systems. The Windows job must only sign and upload the Windows builds. If it were allowed to upload the macOS builds, they will be unsigned and *may* overwrite the signed builds uploaded by the macOS job.
- The workflow makes a checkout of the repository at the commit that `run` was built from. This ensures consistency with the **CI** workflow when repackaging. Remember that tools invoked by the workflow (e.g. [tlk.ps1](../../ci/tlk.ps1)) will be from that commit too.

### TODO

- `jetsocat` builds for macOS are signed, but should be notarized as well 
- The `devolutions-gateway` PowerShell module should be signed

### RELEASE
