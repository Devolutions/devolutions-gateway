using DevolutionsGateway.Dialogs;
using System;
using System.ComponentModel;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Windows.Forms;
using DevolutionsGateway.Properties;
using DevolutionsGateway.Resources;
using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class PublicKeyServerDialog : GatewayDialog
{
    private readonly ErrorProvider errorProvider = new ErrorProvider();

    private readonly HttpClient httpClient;

    private CancellationTokenSource cts = new CancellationTokenSource();

    private bool isValidUrl = false;

    public PublicKeyServerDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);

        this.httpClient = new HttpClient();
        this.httpClient.Timeout = TimeSpan.FromSeconds(10);
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;

        this.errorProvider.BlinkStyle = ErrorBlinkStyle.NeverBlink;
        this.errorProvider.SetIconAlignment(this.butValidate, ErrorIconAlignment.MiddleLeft);
        this.errorProvider.SetIconPadding(this.butValidate, 6);
    }

    public override bool DoValidate()
    {
        if (this.rbAutoConfig.Checked && !this.isValidUrl)
        {
            // Should be blocked by UI
            return false;
        }

        return true;
    }

    public override void FromProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);

        string devolutionsServerUrl = properties.DevolutionsServerUrl;
        this.txtUrl.Text = devolutionsServerUrl;

        this.rbAutoConfig.Checked = !string.IsNullOrEmpty(devolutionsServerUrl) || !properties.DidChooseServerConfig;
        this.rbManualConfig.Checked = !this.rbAutoConfig.Checked;

        this.SetControlStates();
    }

    public override bool ToProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);

        properties.DevolutionsServerUrl = this.rbAutoConfig.Checked ? this.txtUrl.Text.Trim() : string.Empty;
        properties.DidChooseServerConfig = true;

        return true;
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        base.OnLoad(sender, e);
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Back_Click(object sender, EventArgs e)
    {
        this.cts?.Cancel();

        base.Back_Click(sender, e);
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Next_Click(object sender, EventArgs e) => base.Next_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Cancel_Click(object sender, EventArgs e)
    {
        this.cts?.Cancel();

        base.Cancel_Click(sender, e);
    }

    private void SetControlStates()
    {
        if (this.rbManualConfig.Checked)
        {
            this.txtUrl.Enabled = false;
            this.butValidate.Enabled = false;
            this.next.Enabled = true;
        }
        else if (this.rbAutoConfig.Checked)
        {
            this.txtUrl.Enabled = true;
            this.butValidate.Enabled = true;
            this.next.Enabled = this.isValidUrl;
        }
    }

    private void txtUrl_TextChanged(object sender, EventArgs e)
    {
        this.isValidUrl = false;
        this.SetControlStates();
    }

    private void butValidate_Click(object sender, EventArgs e)
    {
        this.isValidUrl = false;

        if (string.IsNullOrEmpty(this.txtUrl.Text) ||
            !Uri.TryCreate(this.txtUrl.Text.Trim(), UriKind.Absolute, out Uri result))
        {
            this.errorProvider.SetError(this.butValidate, I18n(Strings.YouMustEnterAValidUrl));
            return;
        }

        // WinForms "feature"; disabling the button on the next line will shift focus to the next tab stop.
        // If it's a radio button it will get selected. We don't want that.
        this.label3.Focus();

        this.butValidate.Enabled = false;
        this.next.Enabled = false;

        try
        {
            UriBuilder builder = new UriBuilder(result);

            if (!builder.Path.EndsWith("/"))
            {
                builder.Path += "/";
            }

            builder.Path += Constants.DVLSPublicKeyEndpoint;

            this.Cursor = Cursors.WaitCursor;

            httpClient.GetAsync(builder.Uri, this.cts.Token).ContinueWith(t =>
            {
                if (t.IsCanceled)
                {
                    return;
                }

                this.Invoke(() =>
                {
                    this.Cursor = Cursors.Default;

                    if (t.IsFaulted)
                    {
                        Exception ex = t.Exception!.GetBaseException();

                        if (ex is HttpRequestException { InnerException: SocketException se })
                        {
                            this.errorProvider.SetError(this.butValidate, new Win32Exception(se.ErrorCode).Message);
                        }
                        else
                        {
                            this.errorProvider.SetError(this.butValidate, ex.Message);
                        }
                    }
                    else
                    {
                        using HttpResponseMessage response = t.Result;

                        if (!response.IsSuccessStatusCode)
                        {
                            this.errorProvider.SetError(this.butValidate, $"{response.ReasonPhrase} {builder.Uri} ({response.StatusCode})");
                        }
                        else
                        {
                            this.isValidUrl = true;
                            this.errorProvider.SetError(this.butValidate, string.Empty);
                        }
                    }

                    this.SetControlStates();
                });
            });
        }
        catch
        {
            this.Cursor = Cursors.Default;

            this.butValidate.Enabled = true;
            this.next.Enabled = true;
        }
    }

    private void rbAutoConfig_CheckedChanged(object sender, EventArgs e) => this.SetControlStates();

    private void rbManualConfig_CheckedChanged(object sender, EventArgs e) => this.SetControlStates();
}
