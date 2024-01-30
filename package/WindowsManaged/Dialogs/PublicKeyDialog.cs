using System;
using System.Windows.Forms;
using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;
using WixSharp;
using File = System.IO.File;

namespace WixSharpSetup.Dialogs;

public partial class PublicKeyDialog : GatewayDialog
{
    public PublicKeyDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);
    }

    public override bool DoValidate()
    {
        if (string.IsNullOrWhiteSpace(this.txtPublicKeyFile.Text) || !File.Exists(this.txtPublicKeyFile.Text.Trim()))
        {
            ShowValidationError("Error29996");
            return false;
        }

        if (new GatewayProperties(this.Session()).ConfigureWebApp)
        {
            if (string.IsNullOrWhiteSpace(this.txtPrivateKeyFile.Text) || !File.Exists(this.txtPrivateKeyFile.Text.Trim()))
            {
                ShowValidationError("Error29996");
                return false;
            }
        }

        return true;
    }

    public override void FromProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);
        this.txtPublicKeyFile.Text = properties.PublicKeyFile;
        this.txtPrivateKeyFile.Text = properties.PrivateKeyFile;

        this.lblPrivateKeyDescription.Visible =
            this.lblPrivateKeyFile.Visible =
                this.txtPrivateKeyFile.Visible =
                    this.butBrowsePrivateKeyFile.Visible = properties.ConfigureWebApp;

        if (properties.ConfigureWebApp)
        {
            this.lblKeysDescription.Text = "Provide an encryption key pair for token generation and verification.";
        }
        else
        {
            this.lblKeysDescription.Text = "Provide a public key for token verification. The private key for token generation is provisioned by a companion service (e.g. Devolutions Server).";
        }

        this.SetControlStates();
    }

    public override bool ToProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session)
        {
            PublicKeyFile = this.txtPublicKeyFile.Text.Trim(),
            PrivateKeyFile = this.txtPrivateKeyFile.Text.Trim(),
        };

        if (properties.ConfigureWebApp && properties.GenerateKeyPair)
        {
            properties.PublicKeyFile = string.Empty;
            properties.PrivateKeyFile = string.Empty;
        }

        if (!properties.ConfigureWebApp)
        {
            properties.PrivateKeyFile = string.Empty;
        }

        return true;
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

    private void SetControlStates()
    {

    }

    private void butBrowsePublicKeyFile_Click(object sender, EventArgs e)
    {
        // TODO: (rmarkiewicz) localization
        const string filter = "Public Key Files (*.pem)|*.pem|Private Key Files (*.key)|*.key|All Files|*.*";
        string file = this.BrowseForFile(filter);

        if (!string.IsNullOrEmpty(file))
        {
            this.txtPublicKeyFile.Text = file;
        }
    }

    private void butBrowsePrivateKeyFile_Click(object sender, EventArgs e)
    {
        // TODO: (rmarkiewicz) localization
        const string filter = "Public Key Files (*.pem)|*.pem|Private Key Files (*.key)|*.key|All Files|*.*";
        string file = this.BrowseForFile(filter);

        if (!string.IsNullOrEmpty(file))
        {
            this.txtPrivateKeyFile.Text = file;
        }
    }

    private string BrowseForFile(string filter)
    {
        using OpenFileDialog ofd = new();
        ofd.CheckFileExists = true;
        ofd.Multiselect = false;
        ofd.Title = base.Localize("BrowseDlg_Title");
        ofd.Filter = filter;

        return ofd.ShowDialog(this) == DialogResult.OK ? ofd.FileName : null;
    }
}
