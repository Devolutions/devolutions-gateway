using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;

using System;
using DevolutionsGateway.Actions;
using WixSharp;
using System.Windows.Forms;

namespace WixSharpSetup.Dialogs;

public partial class NgrokListenersDialog : GatewayDialog
{
    public NgrokListenersDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);

        this.lnkAuthToken.Text = "Provide your authentication token";
        this.lnkAuthToken.LinkArea = new LinkArea(13, 20);

        this.lnkDomain.Text = "The domain for web client access";
        this.lnkDomain.LinkArea = new LinkArea(4, 6);

        this.lnkRemoteAddr.Text = "The TCP address for native client access";
        this.lnkRemoteAddr.LinkArea = new LinkArea(4, 11);

        this.cmbNativeClient.DataSource = new[] {"Now", "Later"};
    }

    public override bool DoValidate()
    {
        if (string.IsNullOrWhiteSpace(this.txtAuthToken.Text.Trim()))
        {
            ShowValidationErrorString("The auth token is required");
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.txtDomain.Text.Trim()) || 
            Uri.CheckHostName(this.txtDomain.Text.Trim()) == UriHostNameType.Unknown)
        {
            ShowValidationErrorString("The domain is required and must be a valid hostname");
            return false;
        }

        if (this.cmbNativeClient.SelectedIndex == 0)
        {
            if (string.IsNullOrWhiteSpace(this.txtRemoteAddress.Text.Trim()))
            {
                ShowValidationErrorString("The remote address is required");
                return false;
            }

            if (!Uri.TryCreate($"tcp://{this.txtRemoteAddress.Text.Trim()}", UriKind.Absolute, out Uri uri) ||
                !uri.Authority.Contains(":"))
            {
                ShowValidationErrorString("The remote address must be a valid host and port in the format {host}:{port}");
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
        this.cmbNativeClient.SelectedIndex = properties.NgrokEnableTcp ? 0 : 1;
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

        properties.NgrokEnableTcp = this.cmbNativeClient.SelectedIndex == 0 || !properties.ConfigureWebApp;

        return true;
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

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
            this.cmbNativeClient.SelectedIndex = 0;
        }
        
        this.lblRemoteAddress.Enabled = this.txtRemoteAddress.Enabled = this.lnkRemoteAddr.Enabled = this.cmbNativeClient.SelectedIndex == 0;
    }
    
    private void cmbNativeClient_SelectedIndexChanged(object sender, EventArgs e)
    {
        this.SetControlStates();
    }
}
