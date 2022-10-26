using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

[JsonConverter(typeof(AccessScopeJsonConverter))]
public struct AccessScope
{
    public string Value { get; internal set; }

    internal AccessScope(string value)
    {
        Value = value;
    }

    public static AccessScope Star = new AccessScope("*");
    public static AccessScope GatewaySessionsRead = new AccessScope("gateway.sessions.read");
    public static AccessScope GatewaySessionTerminate = new AccessScope("gateway.session.terminate");
    public static AccessScope GatewayAssociationsRead = new AccessScope("gateway.associations.read");
    public static AccessScope GatewayDiagnosticsRead = new AccessScope("gateway.diagnostics.read");
    public static AccessScope GatewayJrlRead = new AccessScope("gateway.jrl.read");
    public static AccessScope GatewayConfigWrite = new AccessScope("gateway.config.write");

    public override string? ToString()
    {
        return this.Value;
    }
}