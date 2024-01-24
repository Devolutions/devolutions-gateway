using DevolutionsGateway.Actions;
using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Helpers;
using DevolutionsGateway.Properties;

using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class CustomizeDialog : GatewayDialog
{
    private static Icon warningIcon;

    public static Icon WarningSmall => warningIcon ??= StockIcon.GetStockIcon(StockIcon.SIID_INFO, StockIcon.SHGSI_SMALLICON);
    
    public CustomizeDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);

        pictureBox1.Image = WarningSmall.ToBitmap();
    }

    public override void FromProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);
        this.rbConfigLater.Checked = !properties.ConfigureGateway;
        this.rbConfigNow.Checked = properties.ConfigureGateway;
        this.chkWebApp.Checked = properties.ConfigureWebApp;
        this.chkGenerateCertificate.Checked = properties.GenerateCertificate;
        this.chkGenerateKeyPair.Checked = properties.GenerateKeyPair;
    }

    public override bool ToProperties()
    {
        new GatewayProperties(this.Runtime.Session)
        {
            ConfigureGateway = this.rbConfigNow.Checked,
            ConfigureWebApp = this.chkWebApp.Checked,
            GenerateCertificate = this.chkGenerateCertificate.Checked,
            GenerateKeyPair = this.chkGenerateKeyPair.Checked,
            ServiceStart = this.rbConfigNow.Checked ? (int)ServiceStartMode.Automatic : (int)ServiceStartMode.Manual,
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

    private void SetControlStates()
    {
        this.chkWebApp.Enabled = this.rbConfigNow.Checked;

        this.chkGenerateCertificate.Enabled = this.chkWebApp.Checked && this.chkWebApp.Enabled;
        this.chkGenerateKeyPair.Enabled = this.chkWebApp.Checked && this.chkWebApp.Enabled;
    }

    private void rbConfigLater_CheckedChanged(object sender, EventArgs e)
    {
        this.SetControlStates();
    }

    private void rbConfigNow_CheckedChanged(object sender, EventArgs e)
    {
        this.SetControlStates();
    }

    private void chkWebApp_CheckedChanged(object sender, EventArgs e)
    {
        this.SetControlStates();
    }
}
