# PEDM Simulator

## Build and prepare the artifacts

```pwsh
.\prepare.ps1
```

## Limited test with no elevation

This mode is a stopgap until we have proper infrastructure for performing
the complete test in the CI. Indeed, there is no way to perform the complete
test using GitHub-hosted runners (or docker), because for security reasons
ContainerAdministrator is not assigned the SE_CREATE_TOKEN_NAME privilege, and
it’s not possible to perform nested virtualization either.

You can run the pedm-simulator.exe executable directly.

If you are running using an elevated account with the SE_CREATE_TOKEN_NAME
privilege assigned, you can build and run a container instead to ensure
the privilege is not available.

```pwsh
.\build-container.ps1
.\run-container.ps1
```

## Complete test with elevation

It is recommended to use a dedicated VM.

Visual C++ Redistribuable are required.

You can install that using this PowerShell snippet:

```pwsh
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "vc_redist.x64.exe"
Start-Process -filepath C:\vc_redist.x64.exe -ArgumentList "/install", "/passive", "/norestart" -Passthru | Wait-Process
Remove-Item -Force vc_redist.x64.exe
```

Retrieve the artifacts (including clang_rt.asan_dynamic-x86_64.dll).

For the next steps, make sure to use an account with the SE_CREATE_TOKEN_NAME
privilege assigned.

Set the `PEDM_SIMULATOR_EXPECT_ELEVATION` environment variable.

```pwsh
$Env:PEDM_SIMULATOR_EXPECT_ELEVATION = '1'
```

Run `pedm-simulator.exe`.

