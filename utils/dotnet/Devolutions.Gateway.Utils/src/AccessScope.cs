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
    public static AccessScope GatewayHeartbeatRead = new AccessScope("gateway.heartbeat.read");
    public static AccessScope GatewayRecordingDelete = new AccessScope("gateway.recording.delete");
    public static AccessScope GatewayRecordingsRead = new AccessScope("gateway.recordings.read");
    public static AccessScope GatewayUpdate = new AccessScope("gateway.update");
    public static AccessScope GatewayPreflight = new AccessScope("gateway.preflight");
    public static AccessScope GatewayTrafficClaim = new AccessScope("gateway.traffic.claim");
    public static AccessScope GatewayTrafficAck = new AccessScope("gateway.traffic.ack");
    public static AccessScope GatewayNetMonitorConfig = new AccessScope("gateway.net.monitor.config");
    public static AccessScope GatewayNetMonitorDrain = new AccessScope("gateway.net.monitor.drain");

    public override string? ToString()
    {
        return this.Value;
    }
}