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
    /// Optional agent display-name hint.
    ///
    /// The gateway never reads this claim — it only verifies the JWT
    /// signature, content type, and expiry on <c>POST /jet/tunnel/enroll</c>; the
    /// authoritative agent name is the one the agent sends in its
    /// <c>EnrollRequest</c> body (which the gateway also stamps into the
    /// signed client certificate's CN).
    ///
    /// The agent-side CLI parses this claim out of the JWT it receives via
    /// <c>--enrollment-string</c> and uses it as the default for
    /// <c>--name</c> when the operator did not pass one explicitly. Setting
    /// it here lets DVLS pre-fill the name the admin typed in the "Generate
    /// Enrollment String" dialog so the agent shows up under that name in
    /// the registry without an extra CLI flag.
    ///
    /// Name resolution order at install time is: explicit name (CLI
    /// <c>--name</c> / installer dialog value) &gt; this <c>jet_agent_name</c>
    /// claim &gt; the local computer name. The computer-name fallback is
    /// applied by the Windows installer when neither an explicit name nor
    /// this claim is present; if it is omitted, the agent CLI's own
    /// <c>up</c> command instead requires <c>--name</c> to be passed.
    /// </summary>
    [JsonPropertyName("jet_agent_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? JetAgentName { get; set; }

    public EnrollmentClaims(string jetGwUrl, string? jetAgentName = null)
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
