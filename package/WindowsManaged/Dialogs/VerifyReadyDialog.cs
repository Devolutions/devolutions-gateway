using DevolutionsGateway.Dialogs;
using System;
using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class VerifyReadyDialog : GatewayDialog
{
    public VerifyReadyDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
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
