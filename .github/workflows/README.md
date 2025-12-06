# devolutions-gateway ci / cd

Devolutions Gateway and jetsocat are built and released using GitHub workflows.

There are three separate workflows:

```
┌────┐   ┌─────────┐   ┌─────────┐
│ CI ├───► PACKAGE ├───► RELEASE │
└────┘   └─────────┘   └─────────┘
```

## Making a Release

- Ensure that the [VERSION](../../VERSION) number and [CHANGELOG](../../CHANGELOG.md) are up-to-date.

Use the [Create New Release](create-new-release.yml) to run a full build and test, package the artifacts and release to GitHub, PSGallery and Docker Hub.

##### Parameters

- `ref` Optional SHA value of the commit to release.
- `dry-run` If selected, the workflow will only indicate the actions to be taken. No deployment will occur.

## Making a Release (manual)

It's possible to run the individual workflows and generate a release manually.

- Execute the [CI](#ci) workflow (either manually via the GitHub web UI or `gh`, or by creating or merging a pull request)

:warning: *For releases, the CI workflow should be run from a commit on `master`. This ensures the binaries are built with the proper optimizations*
- Find the run ID of the [CI](#ci) workflow run containing the artifacts you wish to release. You can use the GitHub web UI, or `gh` (e.g. `gh run list`)
- Run the [Package](#package) workflow, providing the run ID obtained in the previous step (either using the GitHub web UI, or `gh`. For example:

`gh workflow run package.yml -f run=123456`

 - Find the run ID of the [Package](#package) workflow and use it to call the [Release](#release) workflow. For example:
 
`gh workflow run release.yml -f run=654321`

### CI

The "CI" workflow builds, tests and packages `devolutions-gateway` and builds `jetsocat`, for supported platforms. The workflow is run automatically for pull requests and merges, or may be run manually.

The build artifacts are **not** code-signed and not suitable for distribution.

### PACKAGE

The "Package" workflow downloads the artifacts from a [CI](#ci) workflow run, codesigning and repackaging them as appropriate. The workflow should be run manually, and will require approval.

The workflow will display a notice if `run` was not built from the main branch. Artifacts from the main branch are built with specific optimizations and are suitable for distribution.

##### Parameters

- `run` The run-id of the [CI](#ci) workflow run containing the artifacts to package

##### Developer Notes

- The `Codesign` job uses a matrix to code-sign and repackage in parallel. It's important to ensure that individual matrix jobs do not upload the same artifacts; otherwise the result may be unexpected. For example: each platform downloads the `jetsocat` artifact, which contains builds for several operating systems. The Windows job must only sign and upload the Windows builds. If it were allowed to upload the macOS builds, they will be unsigned and *may* overwrite the signed builds uploaded by the macOS job.
- The workflow makes a checkout of the repository at the commit that `run` was built from. This ensures consistency with the [CI](#ci) workflow when repackaging. Remember that tools invoked by the workflow (e.g. [tlk.ps1](../../ci/tlk.ps1)) will be from that commit too.

##### TODO

- `jetsocat` builds for macOS are signed, but should be notarized as well 
- The `devolutions-gateway` PowerShell module should be signed

### RELEASE

The "Release" workflow downloads the artifacts from a [Package](#package) workflow run, and executes the release. The workflow should be run manually, and will require approval.

The following actions are taken:

- Build multi-architecture containers for Devolutions Gateway (AMD64 and ARM64) and publish to Docker
- Push the Devolutions Gateway PowerShell module to PSGallery
- Generate a GitHub release

Re-releasing the same version multiple times is not supported. The "Release" workflow checks for an existing GitHub release with the specified version and will not proceed if found.

##### Multi-Architecture Docker Images

Devolutions Gateway Docker images support both AMD64 (x86_64) and ARM64 (aarch64) architectures. The workflow:
1. Prepares separate build contexts for each architecture with appropriate binaries and native libraries
2. Uses Docker Buildx and QEMU to build both architectures on x86_64 runners
3. Creates multi-arch manifest lists so users automatically get the correct image for their platform

##### Parameters

- `run` The run-id of the [Package](#package) workflow run containing the artifacts to package
- `dry-run` If selected, the workflow will only indicate the actions to be taken. No deployment will occur.
