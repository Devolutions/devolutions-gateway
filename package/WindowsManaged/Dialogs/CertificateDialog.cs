using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using DevolutionsGateway.Helpers;
using DevolutionsGateway.Resources;
using WixSharp;
using static DevolutionsGateway.Properties.Constants;
using File = System.IO.File;
using StoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation;
using StoreName = System.Security.Cryptography.X509Certificates.StoreName;
using DevolutionsGateway.Actions;

namespace WixSharpSetup.Dialogs;

public partial class CertificateDialog : GatewayDialog
{
    private bool UseExternalCertificate => this.cmbCertificateSource.Selected<CertificateMode>() == CertificateMode.External;

    private bool UseSystemCertificate => this.cmbCertificateSource.Selected<CertificateMode>() == CertificateMode.System;

    private X509Certificate2 SelectedCertificate
    {
        get;
        set;
    }

    public CertificateDialog()
    {
        InitializeComponent();

        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);

        this.pictureBox1.Image =
            StockIcon.GetStockIcon(StockIcon.SIID_WARNING, StockIcon.SHGSI_SMALLICON).ToBitmap();
    }

    public override bool DoValidate()
    {
        if (this.UseExternalCertificate)
        {
            if (string.IsNullOrWhiteSpace(this.txtCertificateFile.Text) ||
                !File.Exists(this.txtCertificateFile.Text.Trim()))
            {
                ShowValidationError(I18n(Strings.YouMustProvideAValidCertificateAndPasswordOrKey));
                return false;
            }

            if (this.NeedsPassword())
            {
                // We could validate the certificate directly at this point....
                // Empty password might be valid
                if (string.IsNullOrEmpty(this.txtCertificatePassword.Text))
                {
                    ShowValidationError(I18n(Strings.YouMustProvideAValidCertificateAndPasswordOrKey));
                    return false;
                }
            }
            else
            {
                if (string.IsNullOrWhiteSpace(this.txtPrivateKeyFile.Text) ||
                    !File.Exists(this.txtPrivateKeyFile.Text.Trim()))
                {
                    ShowValidationError(I18n(Strings.YouMustProvideAValidCertificateAndPasswordOrKey));
                    return false;
                }
            }
        }
        else
        {
            if (this.SelectedCertificate is null)
            {
                ShowValidationError(I18n(Strings.YouMustSelectACertificateFromTheSystemCertificateStore));
                return false;
            }
        }

        return true;
    }

    public override void FromProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);

        this.cmbCertificateSource.SetSelected(properties.CertificateMode);
        this.txtCertificateFile.Text = properties.CertificateFile;
        this.txtPrivateKeyFile.Text = properties.CertificatePrivateKeyFile;
        this.txtCertificatePassword.Text = properties.CertificatePassword;
        this.cmbStoreLocation.SetSelected(properties.CertificateLocation);
        this.cmbStore.SetSelected(properties.CertificateStore);
        this.cmbSearchBy.SetSelected(properties.CertificateFindType);
        this.txtSearch.Text = properties.CertificateSearchText;

        if (this.UseSystemCertificate)
        {
            try
            {
                X509Certificate2Collection certificates = this.SearchCertificate(
                    (StoreLocation) this.cmbStoreLocation.SelectedIndex + 1,
                    this.cmbStore.Selected<StoreName>(),
                    CertificateFindType.Thumbprint,
                    properties.CertificateThumbprint);

                if (certificates?.Count == 1)
                {
                    this.SetSelectedCertificate(certificates[0]);
                }
            }
            catch // Failed to restore state, don't crash
            {
            }
        }

        this.SetControlStates();
    }

    public override bool ToProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session)
        {
            CertificateMode = this.cmbCertificateSource.Selected<CertificateMode>(),
        };

        if (this.UseExternalCertificate)
        {
            properties.CertificateFile = this.txtCertificateFile.Text.Trim();

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
        }
        else
        {
            properties.CertificateLocation = this.cmbStoreLocation.Selected<StoreLocation>();
            properties.CertificateStore = this.cmbStore.Selected<StoreName>();
            properties.CertificateName = this.SelectedCertificate?.GetNameInfo(X509NameType.SimpleName, false);
            properties.CertificateThumbprint = this.SelectedCertificate?.Thumbprint;
        }

        properties.CertificateFindType = this.cmbSearchBy.Selected<CertificateFindType>();
        properties.CertificateSearchText = this.txtSearch.Text;

        return true;
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        WinAPI.SendMessage(this.txtSearch.Handle, WinAPI.EM_SETCUEBANNER, 0, I18n(Strings.EnterTextToSearch));

        this.cmbCertificateSource.Source<CertificateMode>(this.MsiRuntime);
        this.cmbCertificateSource.SetSelected(CertificateMode.External);

        this.cmbStoreLocation.Source<StoreLocation>(this.MsiRuntime);
        this.cmbStoreLocation.SetSelected(StoreLocation.LocalMachine);

        this.cmbStore.Source<StoreName>(this.MsiRuntime);
        this.cmbStore.SetSelected(StoreName.My);

        this.cmbSearchBy.Source<CertificateFindType>(this.MsiRuntime);
        this.cmbSearchBy.SetSelected(CertificateFindType.Thumbprint);

        this.ttCertVerify.SetToolTip(this.pictureBox1, I18n(Strings.CertificateCouldNotBeVerified));

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
        string filter = $"{I18n(Strings.Filter_PfxFiles)}|*.pfx; *.p12|{I18n(Strings.Filter_CertificateFiles)}|*.pem; *.crt; *.cer|{I18n(Strings.Filter_AllFiles)}|*.*";
        string file = this.BrowseForFile(filter);

        if (!string.IsNullOrEmpty(file))
        {
            this.txtCertificateFile.Text = file;
        }

        this.SetControlStates();
    }

    private void butBrowsePrivateKeyFile_Click(object sender, EventArgs e)
    {
        string filter = $"{I18n(Strings.Filter_PrivateKeyFiles)}|*.key|{I18n(Strings.Filter_AllFiles)}|*.*";
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
        ofd.Title = I18n("BrowseDlg_Title");
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
               new[] {".pfx", ".p12"}.Any(x => x.Equals(extension, StringComparison.CurrentCultureIgnoreCase));
    }

    private void SetControlStates()
    {
        if (this.UseExternalCertificate)
        {
            this.gbExternal.Visible = true;
            this.gbSystem.Visible = false;

            bool needsPassword = this.NeedsPassword();

            this.lblCertificatePassword.Visible = this.txtCertificatePassword.Visible = needsPassword;
            this.lblPrivateKeyFile.Visible = this.txtPrivateKeyFile.Visible = this.butBrowsePrivateKeyFile.Visible = !needsPassword;
            this.lblHint.Text = needsPassword ? 
                string.Empty : 
                I18n(Strings.EncryptedPrivateKeysAreNotSupported);
        }

        else
        {
            this.gbExternal.Visible = false;
            this.gbSystem.Visible = true;
            
            this.butSearchCertificate.Enabled = !string.IsNullOrWhiteSpace(this.txtSearch.Text);
        }
    }

    private void txtCertificateFile_TextChanged(object sender, EventArgs e)
    {
        this.SetControlStates();
    }

    private void cmbCertificateSource_SelectedIndexChanged(object sender, EventArgs e)
    {
        this.SetControlStates();
    }

    private void txtSubjectName_TextChanged(object sender, EventArgs e)
    {
        this.SetControlStates();
    }

    private X509Certificate2Collection SearchCertificate(StoreLocation location, StoreName storeName,
        CertificateFindType findType, string findValue)
    {
        X509Store store = null;

        try
        {
            store = new X509Store(storeName, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            X509FindType x509FindType = findType == CertificateFindType.Thumbprint
                ? X509FindType.FindByThumbprint
                : X509FindType.FindBySubjectName;

            if (x509FindType == X509FindType.FindByThumbprint)
            {
                findValue = Regex.Replace(findValue.ToUpper(), @"[^0-9A-F]+", string.Empty);
            }

            return store.Certificates.Find(x509FindType, findValue, false);
        }
        finally
        {
            store?.Close();
        }
    }

    private void butSearchCertificate_Click(object sender, EventArgs e)
    {
        try
        {
            X509Certificate2Collection certificates = SearchCertificate(
                (StoreLocation) this.cmbStoreLocation.SelectedIndex + 1,
                this.cmbStore.Selected<StoreName>(),
                this.cmbSearchBy.Selected<CertificateFindType>(),
                this.txtSearch.Text);
            
            if (certificates.Count == 0)
            {
                this.SetSelectedCertificate(null);

                MessageBox.Show(I18n(Strings.NoMatchingCertificatesFound), I18n("GatewayDlg_Title"));
            }
            else if (certificates.Count == 1)
            {
                this.SetSelectedCertificate(certificates[0]);
            }
            else
            {
                X509Certificate2Collection selection = X509Certificate2UI.SelectFromCollection(certificates,
                    I18n("GatewayDlg_Title"),
                    I18n(Strings.SelectTheCertificateToUse), X509SelectionFlag.SingleSelection, this.Handle);

                if (selection.Count > 0)
                {
                    this.SetSelectedCertificate(selection[0]);
                }
            }
        }
        catch (Exception exception)
        {
            ShowValidationErrorString(string.Format(I18n(Strings.AnUnexpectedErrorOccurredAccessingTheSystemCertificateStoreX), exception));
        }
    }

    private void SetSelectedCertificate(X509Certificate2 certificate)
    {
        this.SelectedCertificate = certificate;

        this.lblCertificateDescription.Text = string.Empty;
        this.pictureBox1.Visible = false;
        this.lblSelectedCertificate.Visible = this.lblCertificateDescription.Visible = this.butViewCertificate.Visible = this.SelectedCertificate is not null;

        if (this.SelectedCertificate is not null)
        {
            this.pictureBox1.Visible = !this.SelectedCertificate.Verify();
            this.lblCertificateDescription.Text = this.SelectedCertificate?.GetNameInfo(X509NameType.SimpleName, false);
        }
    }

    private void butViewCertificate_Click(object sender, EventArgs e)
    {
        X509Certificate2UI.DisplayCertificate(this.SelectedCertificate, this.Handle);
    }
}
