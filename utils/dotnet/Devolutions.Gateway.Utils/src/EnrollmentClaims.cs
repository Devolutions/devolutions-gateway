using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

/// <summary>
/// Claims carried by an agent-tunnel enrollment JWT.
///
/// DVLS signs this with the gateway's provisioner private key and hands the
/// resulting JWT to the operator. The operator pastes the JWT into
/// <c>devolutions-agent up --enrollment-string &lt;jwt&gt;</c>; the agent uses
/// it as the Bearer token on <c>POST /jet/tunnel/enroll</c>, where the
/// gateway verifies the signature and the <c>scope</c> claim.
///
/// Use <see cref="AccessScope.GatewayAgentEnroll"/> for <see cref="Scope"/>.
/// The agent reads <see cref="JetGwUrl"/>, <see cref="JetAgentName"/>, and
/// <see cref="JetQuicEndpoint"/> locally without verifying the signature
/// (it is the intended recipient).
/// </summary>
public class EnrollmentClaims : IGatewayClaims
{
    [JsonPropertyName("scope")]
    public AccessScope Scope { get; set; }

    /// <summary>Gateway HTTP base URL the agent calls for enrollment.</summary>
    [JsonPropertyName("jet_gw_url")]
    public string JetGwUrl { get; set; }

    /// <summary>Optional agent display-name hint.</summary>
    [JsonPropertyName("jet_agent_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? JetAgentName { get; set; }

    /// <summary>
    /// Optional QUIC endpoint (<c>host:port</c>) the agent dials after enrollment.
    /// The gateway never reports this itself; the operator (DVLS) supplies it
    /// because only they know the agent-reachable address.
    /// </summary>
    [JsonPropertyName("jet_quic_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? JetQuicEndpoint { get; set; }

    public EnrollmentClaims(string jetGwUrl, string? jetAgentName = null, string? jetQuicEndpoint = null)
    {
        this.Scope = AccessScope.GatewayAgentEnroll;
        this.JetGwUrl = jetGwUrl;
        this.JetAgentName = jetAgentName;
        this.JetQuicEndpoint = jetQuicEndpoint;
    }

    public string GetContentType()
    {
        return "ENROLLMENT";
    }
}
