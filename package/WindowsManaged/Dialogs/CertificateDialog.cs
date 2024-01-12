using System;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;
using WixSharp;
using File = System.IO.File;

namespace WixSharpSetup.Dialogs;

public partial class CertificateDialog : GatewayDialog
{
    public CertificateDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);
    }

    public override bool DoValidate()
    {
        if (string.IsNullOrWhiteSpace(this.txtCertificateFile.Text) ||
            !File.Exists(this.txtCertificateFile.Text.Trim()))
        {
            ShowValidationError("Error29995");
            return false;
        }


        if (this.NeedsPassword())
        {
            // We could validate the certificate directly at this point....
            // Empty password might be valid
            if (string.IsNullOrEmpty(this.txtCertificatePassword.Text))
            {
                ShowValidationError("Error29995");
                return false;
            }
        }
        else
        {
            if (string.IsNullOrWhiteSpace(this.txtPrivateKeyFile.Text) ||
                !File.Exists(this.txtPrivateKeyFile.Text.Trim()))
            {
                ShowValidationError("Error29995");
                return false;
            }
        }

        return true;
    }

    public override void FromProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);
        this.txtCertificateFile.Text = properties.CertificateFile;
        this.txtPrivateKeyFile.Text = properties.CertificatePrivateKeyFile;
        this.txtCertificatePassword.Text = properties.CertificatePassword;

        this.SetControlStates();
    }

    public override bool ToProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session)
        {
            CertificateFile = this.txtCertificateFile.Text.Trim()
        };

        if (this.NeedsPassword())
        {
            properties.CertificatePassword = this.txtCertificatePassword.Text;
            properties.CertificatePrivateKeyFile = string.Empty;
        }
        else
        {
            properties.CertificatePassword = string.Empty;
            properties.CertificatePrivateKeyFile = this.txtPrivateKeyFile.Text.Trim();
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

    private void butBrowseCertificateFile_Click(object sender, EventArgs e)
    {
        // TODO: (rmarkiewicz) localization
        const string filter = "PFX Files (*.pfx, *.p12)|*.pfx;*.p12|Certificate Files (*.pem, *.crt, *.cer)|*.pem;*.crt;*.cer|All Files|*.*";
        string file = this.BrowseForFile(filter);

        if (!string.IsNullOrEmpty(file))
        {
            this.txtCertificateFile.Text = file;
        }

        this.SetControlStates();
    }

    private void butBrowsePrivateKeyFile_Click(object sender, EventArgs e)
    {
        // TODO: (rmarkiewicz) localization
        const string filter = "Private Key Files (*.key)|*.key|All Files|*.*";
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

        if (ofd.ShowDialog(this) == DialogResult.OK)
        {
            return ofd.FileName;
        }

        return null;
    }

    private bool NeedsPassword()
    {
        string certificatePath = this.txtCertificateFile.Text.Trim();

        if (string.IsNullOrWhiteSpace(certificatePath))
        {
            return false;
        }

        string extension = Path.GetExtension(certificatePath);

        return !string.IsNullOrEmpty(extension) &&
               new[] { ".pfx", ".p12" }.Any(x => x.Equals(extension, StringComparison.CurrentCultureIgnoreCase));
    }

    private void SetControlStates()
    {
        this.SuspendLayout();

        try
        {
            this.lblCertificatePassword.Visible = this.txtCertificatePassword.Visible = this.NeedsPassword();
            this.lblPrivateKeyFile.Visible = this.txtPrivateKeyFile.Visible = this.butBrowsePrivateKeyFile.Visible = !this.NeedsPassword();
        }
        finally
        {
            this.ResumeLayout(true);
        }
    }

    private void txtCertificateFile_TextChanged(object sender, EventArgs e)
    {
        this.SetControlStates();
    }
}
