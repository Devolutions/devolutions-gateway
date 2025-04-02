# PEDM Simulator

## Build and prepare the artifacts

```pwsh
.\prepare.ps1
```

## Limited test with no elevation

A limited test where the elevation procedure will fail. This test is still
useful because it will exercise a different code path than the "complete" test.
It’s also convenient for testing without using an elevated account with the
`SE_CREATE_TOKEN_NAME` privilege assigned.

When running under a user without the `SE_CREATE_TOKEN_NAME` privilege, you can
just run the `pedm-simulator.exe` executable directly.

If you are running using an elevated account with the `SE_CREATE_TOKEN_NAME`
privilege assigned, you can build and run a container instead to ensure
the privilege is not available.

```pwsh
.\build-container.ps1
.\run-container.ps1
```

You may also consider logging into a different user with lower privileges.

## Complete test with elevation

It is recommended to use a dedicated VM for this test.

Visual C++ Redistribuable are required.

You can install that using this PowerShell snippet:

```pwsh
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "vc_redist.x64.exe"
Start-Process -filepath C:\vc_redist.x64.exe -ArgumentList "/install", "/passive", "/norestart" -Passthru | Wait-Process
Remove-Item -Force vc_redist.x64.exe
```

Retrieve the artifacts (including `clang_rt.asan_dynamic-x86_64.dll`).

For the next steps, make sure to use an account with the `SE_CREATE_TOKEN_NAME`
privilege assigned.

Set the `PEDM_SIMULATOR_EXPECT_ELEVATION` environment variable.

```pwsh
$Env:PEDM_SIMULATOR_EXPECT_ELEVATION = '1'
```

Run `pedm-simulator.exe`.

