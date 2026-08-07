using DevolutionsAgent.Dialogs;
using DevolutionsAgent.Helpers;
using DevolutionsAgent.Properties;
using DevolutionsAgent.Resources;

using System;
using System.Linq;
using System.Windows.Forms;

using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class AgentTunnelDialog : AgentDialog
{
    private string detectedDomain = string.Empty;

    public AgentTunnelDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);
        advertiseDomains.TextChanged += (_, _) => UpdateDetectedDomainState();
        detectedDomainOption.Click += (_, _) => includeDetectedDomain.Checked = !includeDetectedDomain.Checked;
    }

    public override bool ToProperties()
    {
        Runtime.Session[AgentProperties.AgentTunnelEnrollmentString] = enrollmentString.Text.Trim();
        Runtime.Session[AgentProperties.AgentTunnelAdvertiseSubnets] = advertiseSubnets.Text.Trim();
        Runtime.Session[AgentProperties.AgentTunnelAdvertiseDomains] = advertiseDomains.Text.Trim();
        Runtime.Session[AgentProperties.AgentTunnelIncludeDetectedDomain] = includeDetectedDomain.Checked ? "1" : "0";

        return true;
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        enrollmentString.Text = Runtime.Session.Property(AgentProperties.AgentTunnelEnrollmentString);
        advertiseSubnets.Text = Runtime.Session.Property(AgentProperties.AgentTunnelAdvertiseSubnets);

        detectedDomain = DomainDetection.Detect();
        Runtime.Session[AgentProperties.AgentTunnelDetectedDomain] = detectedDomain;

        advertiseDomains.Text = Runtime.Session.Property(AgentProperties.AgentTunnelAdvertiseDomains);
        includeDetectedDomain.Checked =
            Runtime.Session.Property(AgentProperties.AgentTunnelIncludeDetectedDomain) == "1";
        UpdateDetectedDomainState();

        base.OnLoad(sender, e);
    }

    private void UpdateDetectedDomainState()
    {
        if (detectedDomain.Length == 0)
        {
            includeDetectedDomain.Checked = false;
            detectedDomainOptionPanel.Visible = false;
            detectedDomainStatus.Text = I18n(Strings.AgentTunnelDlgNoDetectedDomain);
            detectedDomainStatus.Visible = true;
            return;
        }

        string suggestedRoute = DomainDetection.ToWildcardRoute(detectedDomain);
        bool alreadyIncluded = advertiseDomains.Text
            .Split(',')
            .Select(domain => domain.Trim())
            .Any(domain => string.Equals(domain, suggestedRoute, StringComparison.OrdinalIgnoreCase));

        if (alreadyIncluded)
        {
            includeDetectedDomain.Checked = false;
            detectedDomainOptionPanel.Visible = false;
            detectedDomainStatus.Text =
                string.Format(I18n(Strings.AgentTunnelDlgDetectedDomainAlreadyIncluded), suggestedRoute);
            detectedDomainStatus.Visible = true;
            return;
        }

        detectedDomainStatus.Visible = false;
        detectedDomainOption.Text =
            string.Format(I18n(Strings.AgentTunnelDlgDetectedDomainOption), detectedDomain, suggestedRoute);
        detectedDomainOptionPanel.Visible = true;
    }

    public override bool DoValidate()
    {
        // The dialog is only reached when the Agent Tunnel feature is selected
        // (see Wizard.ShouldSkip), so an enrollment string is required here.
        // We only check for non-emptiness: `agent.exe up` parses the JWT locally
        // (requiring jet_gw_url and jet_agent_name) and the gateway then verifies
        // the signature, content type, and expiry — surface those errors verbatim
        // rather than half-validating implementation details here.
        if (string.IsNullOrWhiteSpace(enrollmentString.Text))
        {
            ShowValidationErrorString("An enrollment string is required. Paste the enrollment string provided by your gateway operator, or go back and deselect the Agent Tunnel feature.");
            return false;
        }

        return true;
    }

    // WixSharp's ManagedForm wires Back/Next/Cancel button clicks via reflection on the
    // *concrete* dialog type rather than the base class, so each leaf dialog must surface
    // these three overrides even when they only delegate to base. The ReSharper hint
    // suppresses the noise flag.

    // ReSharper disable once RedundantOverriddenMember
    protected override void Back_Click(object sender, EventArgs e) => base.Back_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Next_Click(object sender, EventArgs e) => base.Next_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Cancel_Click(object sender, EventArgs e) => base.Cancel_Click(sender, e);
}
