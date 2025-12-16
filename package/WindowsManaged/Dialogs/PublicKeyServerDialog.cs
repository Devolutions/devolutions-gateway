using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Helpers;
using DevolutionsGateway.Properties;
using DevolutionsGateway.Resources;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Windows.Forms;
using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class PublicKeyServerDialog : GatewayDialog
{
    private readonly ErrorProvider errorProvider = new ErrorProvider();

    private readonly HttpClient httpClient;

    private readonly HttpClientHandler httpClientHandler;

    private CancellationTokenSource cts = new CancellationTokenSource();

    private CertificateExceptionStore certificateExceptionStore;

    private bool isValidUrl = false;

    public PublicKeyServerDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);

        this.httpClientHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = this.CertificateValidationCallback,
            SslProtocols = SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12
        };

        this.httpClient = new HttpClient(this.httpClientHandler, true);
        this.httpClient.Timeout = TimeSpan.FromSeconds(10);

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
        this.certificateExceptionStore = CertificateExceptionStore.Deserialize(properties.DevolutionsServerCertificateExceptions);

        this.txtUrl.Text = devolutionsServerUrl;

        this.rbAutoConfig.Checked = !string.IsNullOrEmpty(devolutionsServerUrl) || !properties.DidChooseServerConfig;
        this.rbManualConfig.Checked = !this.rbAutoConfig.Checked;

        this.SetControlStates();
    }

    public override bool ToProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);

        properties.DevolutionsServerUrl = this.rbAutoConfig.Checked ? this.txtUrl.Text.Trim() : string.Empty;
        properties.DevolutionsServerCertificateExceptions = this.certificateExceptionStore.Serialize();
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

    private bool CertificateValidationCallback(HttpRequestMessage request, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
    {
        if (certificate is null)
        {
            return false;
        }

        if (sslPolicyErrors == SslPolicyErrors.None)
        {
           return true;
        }

        X509Certificate2 certificate2 = certificate as X509Certificate2 ?? new X509Certificate2(certificate);

        if (this.certificateExceptionStore.IsTrusted(request.RequestUri.Host, request.RequestUri.Port, certificate2.Thumbprint))
        {
            return true;
        }

        bool trust = this.PromptForCertificateTrust(request,
            certificate2,
            chain,
            sslPolicyErrors);

        if (trust)
        {
            this.certificateExceptionStore.TryAdd(request.RequestUri.Host, request.RequestUri.Port, certificate2.Thumbprint);
        }

        return trust;
    }

    private bool PromptForCertificateTrust(HttpRequestMessage request, X509Certificate2 certificate, X509Chain _, SslPolicyErrors sslPolicyErrors)
    {
        bool result = false;
        
        this.Invoke(() =>
        {
            string message = string.Format(I18n(Strings.TheCertificateForXIsNotTrustedDoYouWishToProceed), request.RequestUri.Host);

            result = MessageBox.Show(this,
                $"{message}{Environment.NewLine}{Environment.NewLine}{certificate}{Environment.NewLine}{Environment.NewLine}{sslPolicyErrors}",
                I18n(Strings.UntrustedCertificate),
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning) == DialogResult.Yes;
        });

        return result;
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
                        Exception ex = ErrorHelper.GetInnermostException(t.Exception);

                        if (ex is SocketException se)
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
