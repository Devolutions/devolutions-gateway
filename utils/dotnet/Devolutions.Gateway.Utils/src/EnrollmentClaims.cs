using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

/// <summary>
/// Claims carried by an agent-tunnel enrollment JWT.
///
/// DVLS signs this with the gateway's provisioner private key and hands the
/// resulting JWT to the operator. The operator pastes the JWT into
/// <c>devolutions-agent up --enrollment-string &lt;jwt&gt;</c>; the agent uses
/// it as the Bearer token on <c>POST /jet/tunnel/enroll</c>, where the
/// gateway verifies the signature, content type, and lifetime.
///
/// The agent reads <see cref="JetGwUrl"/> and <see cref="JetAgentName"/>
/// locally without verifying the signature (it is the intended recipient).
/// </summary>
public class EnrollmentClaims : IGatewayClaims
{
    /// <summary>Gateway HTTP base URL the agent calls for enrollment.</summary>
    [JsonPropertyName("jet_gw_url")]
    public string JetGwUrl { get; set; }

    /// <summary>
    /// Authoritative agent display name.
    ///
    /// The gateway reads this signed claim on <c>POST /jet/tunnel/enroll</c>
    /// and stamps it into the signed client certificate's CN.
    ///
    /// The agent-side CLI parses this claim out of the JWT it receives via
    /// <c>--enrollment-string</c> and uses it as the local enrollment name.
    /// Setting it here lets DVLS bind the name the admin typed in the
    /// "Generate Enrollment String" dialog so the agent shows up under that
    /// name in the registry.
    /// </summary>
    [JsonPropertyName("jet_agent_name")]
    public string JetAgentName { get; set; }

    public EnrollmentClaims(string jetGwUrl, string jetAgentName)
    {
        this.JetGwUrl = jetGwUrl;
        this.JetAgentName = jetAgentName;
    }

    public string GetContentType()
    {
        return "ENROLLMENT";
    }

    /// <summary>
    /// One hour. The operator typically generates the enrollment string in
    /// the admin UI, copies it, walks to the target machine, installs the
    /// agent, and pastes it — the 5-minute interface default is too short
    /// for that flow. Callers can still override via <c>TokenUtils.Sign</c>.
    /// </summary>
    public long? GetDefaultLifetime()
    {
        return 3600;
    }
}
