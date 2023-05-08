using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

[JsonConverter(typeof(ApplicationProtocolJsonConverter))]
public struct ApplicationProtocol
{
    public string Value { get; internal set; }

    internal ApplicationProtocol(string value)
    {
        Value = value;
    }

    public static ApplicationProtocol Rdp = new ApplicationProtocol("rdp");
    public static ApplicationProtocol Ard = new ApplicationProtocol("ard");
    public static ApplicationProtocol Vnc = new ApplicationProtocol("vnc");
    public static ApplicationProtocol Ssh = new ApplicationProtocol("ssh");
    public static ApplicationProtocol SshPwsh = new ApplicationProtocol("ssh-pwsh");
    public static ApplicationProtocol Sftp = new ApplicationProtocol("sftp");
    public static ApplicationProtocol Scp = new ApplicationProtocol("scp");
    public static ApplicationProtocol Telnet = new ApplicationProtocol("telnet");
    public static ApplicationProtocol WinrmHttpPwsh = new ApplicationProtocol("winrm-http-pwsh");
    public static ApplicationProtocol WinrmHttpsPwsh = new ApplicationProtocol("winrm-https-pwsh");
    public static ApplicationProtocol Http = new ApplicationProtocol("http");
    public static ApplicationProtocol Https = new ApplicationProtocol("https");
    public static ApplicationProtocol Ldap = new ApplicationProtocol("ldap");
    public static ApplicationProtocol Ldaps = new ApplicationProtocol("ldaps");

    public override string? ToString()
    {
        return this.Value;
    }
}