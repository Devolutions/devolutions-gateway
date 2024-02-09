using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Helpers;
using DevolutionsGateway.Properties;

using System;
using System.ServiceProcess;
using System.Windows.Forms;
using DevolutionsGateway.Resources;
using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class CustomizeDialog : GatewayDialog
{
    private bool ConfigureNow => this.cmbConfigure.Selected<Constants.CustomizeMode>() == Constants.CustomizeMode.Now;

    public CustomizeDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);
    }

    public override void FromProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);
        this.cmbConfigure.SelectedIndex = properties.ConfigureGateway ? 0 : 1;
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
            ConfigureGateway = this.ConfigureNow,
            ConfigureNgrok = this.chkConfigureNgrok.Checked,
            ConfigureWebApp = this.chkWebApp.Checked,
            GenerateCertificate = this.chkGenerateCertificate.Checked && !this.chkConfigureNgrok.Checked,
            GenerateKeyPair = this.chkGenerateKeyPair.Checked,
            ServiceStart = this.ConfigureNow ? ServiceStartMode.Automatic : ServiceStartMode.Manual,
        };

        return true;
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        this.cmbConfigure.Source<Constants.CustomizeMode>(this.MsiRuntime);

        this.lnkNgrok.SetLink(this.MsiRuntime, Strings.NgrokReadMoreAtX, Strings.NgrokReadMoreLink);

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
        this.chkConfigureNgrok.Enabled = this.ConfigureNow;
        this.chkWebApp.Enabled = this.ConfigureNow;

        this.chkGenerateCertificate.Enabled = this.chkWebApp.Checked && this.chkWebApp.Enabled && !this.chkConfigureNgrok.Checked;
        this.chkGenerateKeyPair.Enabled = this.chkWebApp.Checked && this.chkWebApp.Enabled;

        if (this.ConfigureNow)
        { 
            this.gbConfigure.Visible = true;
            this.lblConfigureDescription.Text = I18n(Strings.RecommendedForStandaloneInstallations);
        }
        else
        {
            this.gbConfigure.Visible = false;
            this.lblConfigureDescription.Text = I18n(Strings.RecommendedForCompanionInstallations);
        }
    }

    private void chkWebApp_CheckedChanged(object sender, EventArgs e)
    {
        this.SetControlStates();

        if (this.chkWebApp.Checked)
        {
            this.chkGenerateCertificate.Checked = this.chkGenerateCertificate.Enabled;
            this.chkGenerateKeyPair.Checked = this.chkGenerateKeyPair.Enabled;
        }
    }

    private void lnkNgrok_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
    {
        this.lnkNgrok.Links[lnkNgrok.Links.IndexOf(e.Link)].Visited = true; 
        System.Diagnostics.Process.Start(Constants.NgrokUrl);
    }

    private void chkConfigureNgrok_CheckedChanged(object sender, EventArgs e)
    {
        this.SetControlStates();

        if (this.chkConfigureNgrok.Checked)
        {
            this.chkGenerateCertificate.Checked = false;
        }
    }

    private void cmbConfigure_SelectedIndexChanged(object sender, EventArgs e)
    {
        this.SetControlStates();
    }
}
