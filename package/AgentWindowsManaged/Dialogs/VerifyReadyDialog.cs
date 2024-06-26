using DevolutionsAgent.Dialogs;
using System;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using DevolutionsAgent.Properties;
using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class VerifyReadyDialog : AgentDialog
{
    public VerifyReadyDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);

#if DEBUG
        this.generateCli.Visible = true;
#endif
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        base.OnLoad(sender, e);
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Back_Click(object sender, EventArgs e) => base.Back_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Next_Click(object sender, EventArgs e)
    {
        Shell.GoNext();
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Cancel_Click(object sender, EventArgs e) => base.Cancel_Click(sender, e);

    private void generateCli_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
    {
        StringBuilder builder = new();
        builder.Append("msiexec /i DevolutionsAgent.msi /qb /l*v install.log");

        foreach (IWixProperty property in AgentProperties.Properties.Where(p => p.Public))
        {
            string propertyValue = this.Session().Property(property.Id);

            if (propertyValue.Equals(property.DefaultValue))
            {
                continue;
            }

            builder.Append($" {property.Id}=\"{propertyValue}\"");
        }

        builder.AppendLine();
        builder.AppendLine();
        builder.Append("Copy to clipboard?");

        if (MessageBox.Show(builder.ToString(), "", MessageBoxButtons.YesNo) == DialogResult.Yes)
        {
            Clipboard.SetText(builder.ToString());
        }
    }
}
