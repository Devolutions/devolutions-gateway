using DevolutionsAgent.Dialogs;
using DevolutionsAgent.Properties;

using System;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows.Forms;

using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class AgentTunnelDialog : AgentDialog
{
    public AgentTunnelDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);
    }

    public override bool ToProperties()
    {
        // The Gateway URL override field was removed in the identity refactor: the JWT
        // is now the single source of truth for the agent-facing URL. Overriding it
        // server-side would defeat the whole point of validating that the agent reached
        // the gateway through one of `AgentTunnel.AdvertisedNames`.
        //
        // Important: the enrollment string is persisted with ALL internal whitespace
        // removed — not just edge `.Trim()`. The validation in `DoValidate` already
        // works on the whitespace-stripped form (browsers and password managers
        // routinely wrap long JWTs across lines on paste), so the value handed off
        // to `agent.exe up --enrollment-string` must match what was validated.
        // Otherwise a multiline pasted JWT passes validation here and then fails at
        // enrollment with an opaque error from the agent's JWT parser.
        Runtime.Session[AgentProperties.AgentTunnelEnrollmentString] = StripAllWhitespace(enrollmentString.Text);
        Runtime.Session[AgentProperties.AgentTunnelAgentName] = agentName.Text.Trim();
        Runtime.Session[AgentProperties.AgentTunnelAdvertiseSubnets] = advertiseSubnets.Text.Trim();
        Runtime.Session[AgentProperties.AgentTunnelAdvertiseDomains] = advertiseDomains.Text.Trim();

        return true;
    }

    /// <summary>
    /// Strip every whitespace character from <paramref name="value"/>. Used to
    /// canonicalize pasted JWTs (which often arrive wrapped onto multiple lines)
    /// so that validation and the value persisted into the MSI session refer to
    /// the exact same string.
    /// </summary>
    private static string StripAllWhitespace(string value) =>
        DevolutionsAgent.Helpers.EnrollmentStringSanitizer.StripAllWhitespace(value);

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        enrollmentString.Text = Runtime.Session.Property(AgentProperties.AgentTunnelEnrollmentString);
        agentName.Text = Runtime.Session.Property(AgentProperties.AgentTunnelAgentName);
        advertiseSubnets.Text = Runtime.Session.Property(AgentProperties.AgentTunnelAdvertiseSubnets);
        advertiseDomains.Text = Runtime.Session.Property(AgentProperties.AgentTunnelAdvertiseDomains);

        base.OnLoad(sender, e);
    }

    public override bool DoValidate()
    {
        // The dialog is only reached when the Agent Tunnel feature is selected (see Wizard.ShouldSkip),
        // so an enrollment string is required at this point.
        if (string.IsNullOrWhiteSpace(enrollmentString.Text))
        {
            ShowValidationErrorString("Enrollment string is required. Paste a JWT from Devolutions Server, Hub, or Gateway, or go back and deselect the Agent Tunnel feature.");
            return false;
        }

        // JWT shape: three base64url segments separated by dots. The agent's `up --enrollment-string`
        // parses the JWT claims for jet_gw_url / jet_agent_name, so the dialog only sanity-checks
        // shape and base64url decodability here; signature verification happens at the gateway.
        //
        // Use the same whitespace-stripping helper as `ToProperties` so validation and
        // persistence operate on byte-identical input.
        string text = StripAllWhitespace(enrollmentString.Text);
        string[] parts = text.Split('.');
        if (parts.Length != 3 || parts.Any(string.IsNullOrEmpty))
        {
            ShowValidationErrorString("Enrollment string must be a JWT (three base64url segments separated by dots).");
            return false;
        }
        foreach (string seg in parts)
        {
            string b64 = seg.Replace('-', '+').Replace('_', '/');
            b64 = b64.PadRight((b64.Length + 3) & ~3, '=');
            try { _ = Convert.FromBase64String(b64); }
            catch (FormatException)
            {
                ShowValidationErrorString("Enrollment string is not valid base64url.");
                return false;
            }
        }

        return true;
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Back_Click(object sender, EventArgs e) => base.Back_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Next_Click(object sender, EventArgs e) => base.Next_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Cancel_Click(object sender, EventArgs e) => base.Cancel_Click(sender, e);
}
