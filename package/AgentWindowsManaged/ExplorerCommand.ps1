<#
    Register or unregister the shell extension from the system context menu.

    This is useful for debugging: unregister the shell extension, swap in your debug DLL, and then re-register

    Must run as administrator

    e.g.

    . ./ExplorerCommand.ps1
    Register-ExplorerCommand -FilePath "$Env:ProgramFiles\Devolutions\Agent\DevolutionsPedmShellExt.dll" -CLSID "{0ba604fd-4a5a-4abb-92b1-09ac5c3bf356}" -Verb "RunElevated" -MenuText "Run Elevated"
    Unregister-ExplorerCommand -CLSID "{0ba604fd-4a5a-4abb-92b1-09ac5c3bf356}" -Verb "RunElevated"
#>

function Register-ExplorerCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$CLSID,

        [Parameter(Mandatory = $true)]
        [string]$Verb,

        [Parameter(Mandatory = $false)]
        [string]$MenuText = "Run Elevated",

        [Parameter(Mandatory = $false)]
        [string[]]$Extensions = @(".exe", ".msi", ".lnk", ".ps1", ".bat")  # Restrict to these
    )

    # Validate the DLL Path
    if (!(Test-Path $FilePath)) {
        Write-Error "ERROR: DLL path '$FilePath' does not exist. Exiting."
        return
    }

    Write-Host "✅ DLL Path verified: $FilePath" -ForegroundColor Green

    # Register CLSID in HKEY_CLASSES_ROOT\CLSID
    $clsidPathHKCR = "Registry::HKEY_CLASSES_ROOT\CLSID\$CLSID"
    if (Test-Path $clsidPathHKCR) {
        Write-Host "⚠️ CLSID already exists in registry: $CLSID" -ForegroundColor Yellow
    } else {
        Write-Host "🆕 Registering CLSID: $CLSID" -ForegroundColor Cyan
        New-Item -Path $clsidPathHKCR -Force | Out-Null
        Set-ItemProperty -Path $clsidPathHKCR -Name "(Default)" -Value "PedmShellExt"
        Write-Host "✅ CLSID registered in HKCR" -ForegroundColor Green
    }

    # Register InprocServer32
    $inprocPathHKCR = "$clsidPathHKCR\InprocServer32"
    if (!(Test-Path $inprocPathHKCR)) {
        Write-Host "🆕 Registering InprocServer32..." -ForegroundColor Cyan
        New-Item -Path $inprocPathHKCR -Force | Out-Null
        Set-ItemProperty -Path $inprocPathHKCR -Name "(Default)" -Value $FilePath
        Set-ItemProperty -Path $inprocPathHKCR -Name "ThreadingModel" -Value "Apartment"
        Write-Host "✅ InprocServer32 registered" -ForegroundColor Green
    }

    # Register Explorer Command for Specific File Extensions
    foreach ($ext in $Extensions) {
        $extKeyPath = "Registry::HKEY_CLASSES_ROOT\$ext"

        # Find the associated file class (e.g., exefile for .exe)
        try {
            $fileClass = (Get-ItemProperty -Path $extKeyPath -ErrorAction Stop)."(Default)"
        } catch {
            Write-Host "⚠️ No registry entry found for $ext. Skipping." -ForegroundColor Yellow
            continue
        }

        # If no file class is found, assume the extension itself
        if (-not $fileClass) { $fileClass = $ext }

        $commandPath = "Registry::HKEY_CLASSES_ROOT\$fileClass\shell\$Verb"

        Write-Host "🆕 Registering ExplorerCommand for: $ext -> $fileClass at $commandPath" -ForegroundColor Cyan

        # Ensure the shell key exists
        if (!(Test-Path "$commandPath")) {
            New-Item -Path $commandPath -Force | Out-Null
        }

        # Set menu text and ExplorerCommandHandler CLSID
        Set-ItemProperty -Path $commandPath -Name "(Default)" -Value $MenuText
        Set-ItemProperty -Path $commandPath -Name "ExplorerCommandHandler" -Value $CLSID
        Set-ItemProperty -Path $commandPath -Name "MUIVerb" -Value "@FilePath,-150"
    }

    Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @"
    [System.Runtime.InteropServices.DllImport("shell32.dll")]
    public static extern void SHChangeNotify(int wEventId, int uFlags, IntPtr dwItem1, IntPtr dwItem2);
"@

    [Win32.NativeMethods]::SHChangeNotify(0x8000000, 0x1000, [IntPtr]::Zero, [IntPtr]::Zero)

    Write-Host "✅ ExplorerCommand registered successfully for selected file types!" -ForegroundColor Green
}

function Unregister-ExplorerCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CLSID,

        [Parameter(Mandatory = $true)]
        [string]$Verb,

        [Parameter(Mandatory = $false)]
        [string[]]$Extensions = @(".exe", ".msi", ".lnk", ".ps1", ".bat")  # Restrict to these
    )

    Write-Host "Unregistering ExplorerCommand with CLSID: $CLSID" -ForegroundColor Yellow

    # Remove CLSID registration
    $clsidPathHKCR = "Registry::HKEY_CLASSES_ROOT\CLSID\$CLSID"
    if (Test-Path $clsidPathHKCR) {
        Remove-Item -Path $clsidPathHKCR -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "✅ Removed CLSID from HKCR" -ForegroundColor Green
    } else {
        Write-Host "⚠️ CLSID not found in HKCR, skipping." -ForegroundColor Yellow
    }

    # Remove ExplorerCommand registry entry for specific file types
    foreach ($ext in $Extensions) {
        $extKeyPath = "Registry::HKEY_CLASSES_ROOT\$ext"

        # Find the associated file class (e.g., exefile for .exe)
        try {
            $fileClass = (Get-ItemProperty -Path $extKeyPath -ErrorAction Stop)."(Default)"
        } catch {
            Write-Host "⚠️ No registry entry found for $ext. Skipping." -ForegroundColor Yellow
            continue
        }

        # If no file class is found, assume the extension itself
        if (-not $fileClass) { $fileClass = $ext }

        $commandPath = "Registry::HKEY_CLASSES_ROOT\$fileClass\shell\$Verb"

        if (Test-Path $commandPath) {
            Write-Host "🗑 Removing ExplorerCommand for: $ext -> $fileClass at $commandPath" -ForegroundColor Cyan
            Remove-Item -Path $commandPath -Force -Recurse -ErrorAction SilentlyContinue
        } else {
            Write-Host "⚠️ No registered menu for $ext ($fileClass), skipping." -ForegroundColor Yellow
        }
    }

    Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @"
    [System.Runtime.InteropServices.DllImport("shell32.dll")]
    public static extern void SHChangeNotify(int wEventId, int uFlags, IntPtr dwItem1, IntPtr dwItem2);
"@

    [Win32.NativeMethods]::SHChangeNotify(0x8000000, 0x1000, [IntPtr]::Zero, [IntPtr]::Zero)

    Write-Host "✅ ExplorerCommand unregistered successfully!" -ForegroundColor Cyan
}