using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;
using System;
using System.ServiceProcess;
using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class ServiceDialog : GatewayDialog
{
    public ServiceDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);
    }

    public override void FromProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);
        this.rbServiceManualStart.Checked = properties.ServiceStart == (int)ServiceStartMode.Manual;
        this.rbServiceAutoStart.Checked = properties.ServiceStart == (int)ServiceStartMode.Automatic;
    }

    public override bool ToProperties()
    {
        GatewayProperties _ = new(this.Runtime.Session)
        {
            ServiceStart = this.rbServiceManualStart.Checked ? (int)ServiceStartMode.Manual : (int)ServiceStartMode.Automatic,
        };

        return true;
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        base.OnLoad(sender, e);
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Back_Click(object sender, EventArgs e) => base.Back_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Next_Click(object sender, EventArgs e) => base.Next_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Cancel_Click(object sender, EventArgs e) => base.Cancel_Click(sender, e);
}
