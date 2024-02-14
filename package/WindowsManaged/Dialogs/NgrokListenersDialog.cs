using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;

using System;
using DevolutionsGateway.Actions;
using WixSharp;
using System.Windows.Forms;
using DevolutionsGateway.Helpers;
using DevolutionsGateway.Resources;

namespace WixSharpSetup.Dialogs;

public partial class NgrokListenersDialog : GatewayDialog
{
    public NgrokListenersDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);
    }

    public override bool DoValidate()
    {
        if (string.IsNullOrWhiteSpace(this.txtAuthToken.Text.Trim()))
        {
            ShowValidationErrorString(I18n(Strings.AuthenticationTokenIsRequired));
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.txtDomain.Text.Trim()) || 
            Uri.CheckHostName(this.txtDomain.Text.Trim()) == UriHostNameType.Unknown)
        {
            ShowValidationErrorString(I18n(Strings.DomainIsRequiredAndMustBeValid));
            return false;
        }

        if (this.cmbNativeClient.SelectedIndex == 0)
        {
            if (string.IsNullOrWhiteSpace(this.txtRemoteAddress.Text.Trim()))
            {
                ShowValidationErrorString(I18n(Strings.RemoteAddressIsRequired));
                return false;
            }

            if (!Uri.TryCreate($"tcp://{this.txtRemoteAddress.Text.Trim()}", UriKind.Absolute, out Uri uri) ||
                !uri.Authority.Contains(":"))
            {
                ShowValidationErrorString(I18n(Strings.RemoteAddressMustBeInTheFormat));
                return false;
            }
        }

        return true;
    }

    public override void FromProperties()
    {
        GatewayProperties properties = new(Runtime.Session);

        this.txtAuthToken.Text = properties.NgrokAuthToken;
        this.txtDomain.Text = properties.NgrokHttpDomain;
        this.cmbNativeClient.SetSelected(properties.NgrokEnableTcp ? Constants.CustomizeMode.Now : Constants.CustomizeMode.Later);
        this.txtRemoteAddress.Text = properties.NgrokRemoteAddress;

        this.SetControlStates();
    }

    public override bool ToProperties()
    {
        GatewayProperties properties = new(Runtime.Session)
        {
            NgrokAuthToken = this.txtAuthToken.Text.Trim(),
            NgrokHttpDomain = this.txtDomain.Text.Trim(),
            NgrokRemoteAddress = this.txtRemoteAddress.Text.Trim(),
        };

        properties.NgrokEnableTcp = this.cmbNativeClient.Selected<Constants.CustomizeMode>() == Constants.CustomizeMode.Now || !properties.ConfigureWebApp;

        return true;
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");
        
        this.lnkAuthToken.SetLink(this.MsiRuntime, Strings.NgrokProvideYourX, Strings.NgrokAuthTokenLink);
        this.lnkDomain.SetLink(this.MsiRuntime, Strings.NgrokXForWebClientAccess, Strings.NgrokDomainLink);
        this.lnkRemoteAddr.SetLink(this.MsiRuntime, Strings.NgroXForNativeClientAccess, Strings.NgrokTcpAddressLink);

        this.cmbNativeClient.Source<Constants.CustomizeMode>(this.MsiRuntime);

        WinAPI.SendMessage(this.txtAuthToken.Handle, WinAPI.EM_SETCUEBANNER, 0, "4nq9771bPxe8ctg7LKr_2ClH7Y15Zqe4bWLWF9p");
        WinAPI.SendMessage(this.txtDomain.Handle, WinAPI.EM_SETCUEBANNER, 0, "demo.devolutions.net");
        WinAPI.SendMessage(this.txtRemoteAddress.Handle, WinAPI.EM_SETCUEBANNER, 0, "1.tcp.ngrok.io:12345");

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
        if (new GatewayProperties(this.Session()).ConfigureWebApp)
        {
            this.cmbNativeClient.Enabled = true;
        }
        else
        {
            this.cmbNativeClient.Enabled = false;
            this.cmbNativeClient.SetSelected(Constants.CustomizeMode.Now);
        }
        
        this.lblRemoteAddress.Enabled = this.txtRemoteAddress.Enabled = this.lnkRemoteAddr.Enabled = 
            this.cmbNativeClient.Selected<Constants.CustomizeMode>() == Constants.CustomizeMode.Now;
    }
    
    private void cmbNativeClient_SelectedIndexChanged(object sender, EventArgs e)
    {
        this.SetControlStates();
    }

    private void lnk_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
    {
        string address = null;

        if (sender == this.lnkAuthToken)
        {
            address = Constants.NgrokAuthTokenUrl;
        }
        else if (sender == this.lnkDomain)
        {
            address = Constants.NgrokDomainsUrl;
        }
        else if (sender == this.lnkRemoteAddr)
        {
            address = Constants.NgrokTcpAddressesUrl;
        }

        if (!string.IsNullOrEmpty(address))
        {
            System.Diagnostics.Process.Start(address);
        }
    }
}
