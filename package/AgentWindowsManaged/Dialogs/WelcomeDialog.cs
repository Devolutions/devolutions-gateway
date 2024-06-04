using System;
using System.Drawing;

using DevolutionsAgent.Dialogs;

namespace WixSharpSetup.Dialogs;

public partial class WelcomeDialog : AgentDialog
{
    public WelcomeDialog()
    {
        InitializeComponent();

        this.textPanel.BackColor = Color.FromArgb(233, 233, 233);
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        image.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Dialog");

        base.OnLoad(sender, e);
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Back_Click(object sender, EventArgs e) => base.Back_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Next_Click(object sender, EventArgs e) => base.Next_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Cancel_Click(object sender, EventArgs e) => base.Cancel_Click(sender, e);
}
