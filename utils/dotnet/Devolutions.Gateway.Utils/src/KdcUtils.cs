namespace Devolutions.Gateway.Utils;

public static class KdcUtils
{
    /// <summary>Builds the KDC proxy URL from the Devolutions Gateway url and a KDC token</summary>
    public static Uri BuildProxyUrl(Uri gatewayUrl, string kdcToken)
    {
        // NOTE: Make sure we have a slash at the end. Indeed, all characters after the right-most '/' in the base URI
        // are excluded when combined with the second part.
        //
        // Reference:
        // - https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclient.baseaddress?view=net-5.0#remarks
        // - https://tools.ietf.org/html/rfc3986

        Uri withSlash;
        string lastSegment = gatewayUrl.Segments.Last() ?? "/";

        if (lastSegment.EndsWith("/"))
        {
            withSlash = gatewayUrl;
        }
        else
        {
            withSlash = new Uri(gatewayUrl, $"{lastSegment}/");
        }

        return new Uri(withSlash, $"jet/KdcProxy/{kdcToken}");
    }

    /// <summary>Converts the given URL to the Kerberos format used in Windows registry</summary>
    public static string ToRegistryFormat(Uri url)
    {
        return $"<https {url.Host}:{url.Port}:{url.AbsolutePath.TrimStart('/')} />";
    }

    /// <summary>Builds a PowerShell script to install the KDC token on user’s machine</summary>
    public static string BuildSetupPwshScript(string kerberosRealm, Uri kdcServerUrl)
    {
        return $@"#!/bin/env pwsh

param(
	[switch] $Uninstall,
	[bool] $ForceProxy = $true
)

$ErrorActionPreference = ""Stop""

$KerberosRealm = ""{kerberosRealm}""
$KerberosReg = ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos""

if ($Uninstall) {{
	Write-Host ""Uninstalling...""

	Remove-ItemProperty -Path $KerberosReg -Name ""KdcProxyServer_Enabled"" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path ""$KerberosReg\KdcProxy\ProxyServers"" -Name $KerberosRealm -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path ""$KerberosReg\Parameters"" -Name ""ForceProxy"" -Force -ErrorAction SilentlyContinue
}} else {{
	Write-Host ""Installing...""

	$KdcServerUrl = ""{kdcServerUrl}""

	$KdcUrl = [Uri] $KdcServerUrl
	$KdcHost = $KdcUrl.Host
	$KdcPort = $KdcUrl.Port
	$KdcPath = $KdcUrl.AbsolutePath.TrimStart('/')

	if ([string]::IsNullOrEmpty($KdcPath)) {{
    	$KdcPath = ""KdcProxy""
	}}

	$KdcProxyServer = ""<https $KdcHost`:$KdcPort`:$KdcPath />""

	New-Item -Path ""$KerberosReg\Parameters"" -Force
	New-Item -Path ""$KerberosReg\KdcProxy\ProxyServers"" -Force
	New-ItemProperty -Path $KerberosReg -Name ""KdcProxyServer_Enabled"" -Type DWORD -Value 1 -Force
	New-ItemProperty -Path ""$KerberosReg\KdcProxy\ProxyServers"" -Name $KerberosRealm -Value $KdcProxyServer -Force
	if ($ForceProxy) {{
		New-ItemProperty -Path ""$KerberosReg\Parameters"" -Name ""ForceProxy"" -Type DWORD -Value 1 -Force
	}}
}}

Write-Host ""Success!""
";
    }

    /// <summary>Builds a registration file (.reg) to install the KDC token on user’s machine</summary>
    public static string BuildSetupRegistrationFile(string kerberosRealm, Uri kdcServerUrl)
    {
        string urlRegistryFormat = ToRegistryFormat(kdcServerUrl);

        return $@"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos]
""KdcProxyServer_Enabled""=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\KdcProxy]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\KdcProxy\ProxyServers]
""{kerberosRealm}""=""{urlRegistryFormat}""

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters]
""ForceProxy""=dword:00000001

";
    }
}