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
        Runtime.Session[AgentProperties.AgentTunnelEnrollmentString] = enrollmentString.Text.Trim();
        Runtime.Session[AgentProperties.AgentTunnelAgentName] = agentName.Text.Trim();
        Runtime.Session[AgentProperties.AgentTunnelAdvertiseSubnets] = advertiseSubnets.Text.Trim();
        Runtime.Session[AgentProperties.AgentTunnelAdvertiseDomains] = advertiseDomains.Text.Trim();
        Runtime.Session[AgentProperties.AgentTunnelGatewayUrl] = gatewayUrl.Text.Trim();

        return true;
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        enrollmentString.Text = Runtime.Session.Property(AgentProperties.AgentTunnelEnrollmentString);
        agentName.Text = Runtime.Session.Property(AgentProperties.AgentTunnelAgentName);
        advertiseSubnets.Text = Runtime.Session.Property(AgentProperties.AgentTunnelAdvertiseSubnets);
        advertiseDomains.Text = Runtime.Session.Property(AgentProperties.AgentTunnelAdvertiseDomains);
        gatewayUrl.Text = Runtime.Session.Property(AgentProperties.AgentTunnelGatewayUrl);

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
        string text = Regex.Replace(enrollmentString.Text, @"\s+", "");
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
