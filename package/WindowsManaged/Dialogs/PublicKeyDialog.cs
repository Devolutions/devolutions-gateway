using System;
using System.Windows.Forms;
using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;
using DevolutionsGateway.Resources;
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
            ShowValidationError(I18n(Strings.TheSpecifiedFileWasInvalidOrNotAccessible));
            return false;
        }

        if (new GatewayProperties(this.Session()).ConfigureWebApp)
        {
            if (string.IsNullOrWhiteSpace(this.txtPrivateKeyFile.Text) || !File.Exists(this.txtPrivateKeyFile.Text.Trim()))
            {
                ShowValidationError(I18n(Strings.TheSpecifiedFileWasInvalidOrNotAccessible));
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
            this.lblKeysDescription.Text = I18n(Strings.ProvideAnEncryptionKeyPairForTokenCreationVerification);
        }
        else
        {
            this.lblKeysDescription.Text = I18n(Strings.ProvideAPublicKeyForTokenVerification);
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
        string filter = $"{I18n(Strings.Filter_PublicKeyFiles)}|*.pem|{I18n(Strings.Filter_PrivateKeyFiles)}|*.key|{I18n(Strings.Filter_AllFiles)}|*.*";
        string file = this.BrowseForFile(filter);

        if (!string.IsNullOrEmpty(file))
        {
            this.txtPublicKeyFile.Text = file;
        }
    }

    private void butBrowsePrivateKeyFile_Click(object sender, EventArgs e)
    {
        string filter = $"{I18n(Strings.Filter_PublicKeyFiles)}|*.pem|{I18n(Strings.Filter_PrivateKeyFiles)}|*.key|{I18n(Strings.Filter_AllFiles)}|*.*";
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
        ofd.Title = I18n("[BrowseDlg_Title]");
        ofd.Filter = filter;

        return ofd.ShowDialog(this) == DialogResult.OK ? ofd.FileName : null;
    }
}
