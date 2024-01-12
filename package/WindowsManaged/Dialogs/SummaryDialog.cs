using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;
using System;
using System.ServiceProcess;
using System.Windows.Forms;
using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class SummaryDialog : GatewayDialog
{
    public SummaryDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);
    }

    public override void FromProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);

        this.lblAccessUri.Text = $"{properties.AccessUriScheme}://{properties.AccessUriHost}:{properties.AccessUriPort}";
        this.lblHttpUri.Text = $"{properties.HttpListenerScheme}://*:{properties.HttpListenerPort}";
        this.lblTcpUrl.Text = $"{properties.TcpListenerScheme}://*:{properties.TcpListenerPort}";

        this.lblPublicKey.Text = properties.PublicKeyFile;

        this.lblServiceStart.Text = properties.ServiceStart == (int)ServiceStartMode.Manual ? "Manually" : "Automatically";

        if (properties.HttpListenerScheme == Constants.HttpsProtocol)
        {
            this.lblCertificateFile.Text = properties.CertificateFile;

            if (!string.IsNullOrEmpty(properties.CertificatePassword))
            {
                using TextBox tb = new() { UseSystemPasswordChar = true };
                char passwordChar = tb.PasswordChar;

                for (int i = 0; i < properties.CertificatePassword.Length; i++)
                {
                    this.lblCertificatePassword.Text += passwordChar;
                }

                this.lblPrivateKeyLabel.Visible = this.lblPrivateKey.Visible = false;
            }
            else
            {
                this.lblPrivateKey.Text = properties.CertificatePrivateKeyFile;

                this.lblCertificatePasswordLabel.Visible = this.lblCertificatePassword.Visible = false;
            }
        }
        else
        {
            this.lblCertificateLabel.Visible =
                this.lblCertificateFileLabel.Visible = this.lblCertificateFileLabel.Visible =
                    this.lblCertificatePasswordLabel.Visible = this.lblCertificatePassword.Visible =
                        this.lblPrivateKeyLabel.Visible = this.lblPrivateKey.Visible = false;
        }
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
