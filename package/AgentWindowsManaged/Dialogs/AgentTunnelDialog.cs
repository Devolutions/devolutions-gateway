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
        Runtime.Session[AgentProperties.AgentTunnelAdvertiseSubnets] = advertiseSubnets.Text.Trim();

        return true;
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        enrollmentString.Text = Runtime.Session.Property(AgentProperties.AgentTunnelEnrollmentString) ?? "";
        advertiseSubnets.Text = Runtime.Session.Property(AgentProperties.AgentTunnelAdvertiseSubnets) ?? "";

        base.OnLoad(sender, e);
    }

    public override bool DoValidate()
    {
        // Tunnel is optional — if enrollment string is empty, skip tunnel setup entirely.
        if (string.IsNullOrWhiteSpace(enrollmentString.Text))
        {
            return true;
        }

        string text = enrollmentString.Text.Trim();

        if (!text.StartsWith("dgw-enroll:v1:"))
        {
            ShowValidationErrorString("Invalid enrollment string. Expected format: dgw-enroll:v1:<base64>");
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
