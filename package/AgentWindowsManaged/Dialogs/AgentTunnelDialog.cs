using DevolutionsAgent.Dialogs;
using DevolutionsAgent.Properties;

using System;
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

        return true;
    }

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
        // The dialog is only reached when the Agent Tunnel feature is selected
        // (see Wizard.ShouldSkip), so an enrollment string is required here.
        // Structural validation of the string itself happens server-side at
        // enrollment time — surface that gateway error verbatim rather than
        // half-validating implementation details (signature, encoding, etc.)
        // here.
        if (string.IsNullOrWhiteSpace(enrollmentString.Text))
        {
            ShowValidationErrorString("An enrollment string is required. Paste the enrollment string provided by your gateway operator, or go back and deselect the Agent Tunnel feature.");
            return false;
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
