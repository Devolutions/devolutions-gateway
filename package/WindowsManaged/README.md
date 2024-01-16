# Devolutions Gateway Windows Installer

Windows Installer project for Devolutions Gateway.

## Overview

A [wixsharp](https://github.com/oleg-shilo/wixsharp) project to build a complete .msi for Devolutions Gateway. wixsharp has a comprehensive wiki and samples database.

A broad undertanding of the relevant technologies is recommended when working on the installer, but a brief overview is provided here:

wixsharp
- Project built on the [managed setup](https://github.com/oleg-shilo/wixsharp/wiki/Managed-Setup-Model) development model.
- Provides a [script file](./Program.cs) written in plain C# syntax which is transpiled into [WiX3](https://github.com/wixtoolset/wix3) source code (wxs).
- Managed [custom actions](./Actions/) are integrated directly into the project instead of as sub-modules.
- Installer custom interface is built using WinForms. This uses the WiX/MSI `EmbeddedUI` feature with the interop interface abstracted by wixsharp. The default dialogs are recreated in WinForms (and extended by this project).

WiX3
- wixsharp generates standard WiX source code. This can be viewed at or after build time by setting `PreserveTempFiles` to `true` on the top-level wixsharp `ManagedProject`, which is helpful in understanding the transpilation process.
- wixsharp automatically invokes the standard WiX toolchain to generate the final mst/msi files.

Windows Installer
- The WiX toolchain builds a standard [Windows Installer](https://en.wikipedia.org/wiki/Windows_Installer) package.

## Build

### MSBuild

`msbuild` must be in your PATH; it's easiest to use the Developer Command Prompt for VS 2022.

The following environment variables should be defined:

`DGATEWAY_EXECUTABLE`
The absolute path to the main executable (DevolutionsGateway.exe) to be packaged

`DGATEWAY_PSMODULE_PATH`
The absolute path to the top-level directory containing the PowerShell module to be package

`DGATEWAY_VERSION`
The version to use for the installer. Note that in Windows Installer, the product version is restricted as follows:

[0-255].[0-255].[0-65535]

### Visual Studio

Tested on Visual Studio 2022. It may be necessary to install the ".NET Framework 4.6 Targetting Pack" using "Tools > Get tools and features".

Either configure the environment variables detailed above, or override the relevant properties in Program.cs.

> When building with VS, I get System.IO.IOException: The process cannot access the file '...DevolutionsGateway.msi' because it is being used by another process.

- Ensure you don't have the previously built MSI open. Close it if you do.
- This appears to be a bug in the latest wixsharp versions. Try the build again and it should work.
- If it still doesn't work, it's possible a crash in a prior run is causing msiexec to keep a handle open to the msi file. Either use Task Manager to kill all `msiexec` processes, or reboot your machine.

### Nuget and references

It's possible to include managed references in the installer project and use them in the mananged UI and custom actions.

The references are added as normal but it's necessary to declare them to the installer script, e.g.

```
/// Add Devolutions.Picky to be available at runtinme
project.DefaultRefAssemblies.Add(typeof(PickyError).Assembly.Location);
```

Native references are trickier. First they must be embedded in the MSI as binaries:

```
string pickyPath = Path.GetDirectoryName(typeof(PickyError).Assembly.Location;
string nativePath = Path.Combine(pickyPath, "runtimes", "win-x64", "native", "DevolutionsPicky.dll");
project.AddBinary(new Binary(nativePath)); // optionally specify an ID here
```

But the binary won't be copied to the installer's temp directory at runtime. It's necessary to extract it manually, this can be done in the `UIInitialized` event for example:

```
byte[] pickyBytes = e.Session.GetEmbeddedData("DevolutionsPicky.dll");
System.IO.File.WriteAllBytes(Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "DevolutionsPicky.dll"),pickyBytes);
```

## Compatibility

The custom UI targets .NET Framework 4.5.1; which is available out-of-the-box on Windows. The provides compatiblity with Windows 8.1 and Windows Server 2012 R2, but it's an additional download on Windows 8 / Windows Server 2012.

> [!IMPORTANT]  
> The managed installer UI and actions are currently run as x86, meaning x64-only references cannot be used. Additionally, when querying the registry, it's important to ensure you don't check the WoW64 view.

The MSI project only targets the x64 architecture and the install won't execute on an x86 operating system. Behaviour on arm64 is currently undefined.

## Debugging

### Installation script

Script generation can be debugged in the normal way using breakpoints and the Debug > Start New Instance in Visual Studio.

It doesn't seem straightforward to debug the event driven custom actions (`OnLoad`, `BeforeInstall`, `AfterInstall`). For complex code, regular managed custom actions should be used instead.

### Debugging UI

1. You must run VS as an elevated (administrator) user. 
2. Launch the compiled MSI
3. "Attach to process" in Visual Studio
4. Filter the process list by "msiexec" and look for the proper Window title ("Devolutions Gateway Setup")
5. Attach the debugger and debug as normal

While developing custom UI, it can be faster to use "Demo mode" to "play" dialogs without running the full msi:

`UIShell.Play(typeof(CertificateDialog));`

### Custom Actions

You won't be able to attach the debugger manually. Instead, (again ensure that VS is run elevated) insert a `System.Diagnostics.Debugger.Break()` call at the site you wish to debug, and then run the MSI.

Once the `Break()` call is hit, the just-in-time debugger will be invoked and you can select your VS instance and proceed as normal.

_Ensure_ that you remove any break statements after debugging is complete. A helpful macro to use might be:

```
private static void Breakpoint()
{
#if DEBUG
    System.Diagnostics.Debugger.Break();
#endif
}
```