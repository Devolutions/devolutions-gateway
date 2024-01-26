using DevolutionsGateway.Actions;
using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Helpers;
using DevolutionsGateway.Properties;

using System;
using System.Drawing;
using System.ServiceProcess;
using System.Windows.Forms;
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

        this.lnkNgrok.Text = "Read more at ngrok.com";
        this.lnkNgrok.LinkArea = new LinkArea(13, 9);
    }

    public override void FromProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);
        this.rbConfigLater.Checked = !properties.ConfigureGateway;
        this.rbConfigNow.Checked = properties.ConfigureGateway;
        this.chkConfigureNgrok.Checked = properties.ConfigureNgrok;
        this.chkWebApp.Checked = properties.ConfigureWebApp;
        this.chkGenerateCertificate.Checked = properties.GenerateCertificate;
        this.chkGenerateKeyPair.Checked = properties.GenerateKeyPair;

        this.SetControlStates();
    }

    public override bool ToProperties()
    {
        new GatewayProperties(this.Runtime.Session)
        {
            ConfigureGateway = this.rbConfigNow.Checked,
            ConfigureNgrok = this.chkConfigureNgrok.Checked,
            ConfigureWebApp = this.chkWebApp.Checked,
            GenerateCertificate = this.chkGenerateCertificate.Checked && !this.chkConfigureNgrok.Checked,
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
        this.chkConfigureNgrok.Enabled = this.rbConfigNow.Checked;
        this.chkWebApp.Enabled = this.rbConfigNow.Checked;

        this.chkGenerateCertificate.Enabled = this.chkWebApp.Checked && this.chkWebApp.Enabled && !this.chkConfigureNgrok.Checked;
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

    private void lnkNgrok_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
    {
        this.lnkNgrok.Links[lnkNgrok.Links.IndexOf(e.Link)].Visited = true; 
        System.Diagnostics.Process.Start("www.ngrok.com");
    }

    private void chkConfigureNgrok_CheckedChanged(object sender, EventArgs e)
    {
        this.SetControlStates();
    }
}
