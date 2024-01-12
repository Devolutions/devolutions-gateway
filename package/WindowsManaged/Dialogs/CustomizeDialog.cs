using DevolutionsGateway.Actions;
using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;

using System;

using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class CustomizeDialog : GatewayDialog
{
    public CustomizeDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);
    }

    public override void FromProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);
        this.rbConfigLater.Checked = !properties.ConfigureGateway;
        this.rbConfigNow.Checked = properties.ConfigureGateway;
    }

    public override bool ToProperties()
    {
        new GatewayProperties(this.Runtime.Session)
        {
            ConfigureGateway = this.rbConfigNow.Checked
        };

        return true;
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        if (!CustomActions.CheckPowerShellVersion())
        {
            this.rbConfigNow.Enabled = false;
        }

        this.FromProperties();

        base.OnLoad(sender, e);
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Back_Click(object sender, EventArgs e) => base.Back_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Next_Click(object sender, EventArgs e) => base.Next_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Cancel_Click(object sender, EventArgs e) => base.Cancel_Click(sender, e);
}
