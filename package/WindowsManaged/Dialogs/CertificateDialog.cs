using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using WixSharp;
using static DevolutionsGateway.Properties.Constants;
using File = System.IO.File;
using StoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation;
using StoreName = System.Security.Cryptography.X509Certificates.StoreName;

namespace WixSharpSetup.Dialogs;

public partial class CertificateDialog : GatewayDialog
{
    private static readonly string[] Locations =
    {
        "Current User", // StoreLocation.currentUser
        "Local Machine", // StoreLocation.localMachine
    };

    private static readonly List<KeyValuePair<StoreName, string>> Stores = new()
    {
        new KeyValuePair<StoreName, string>(StoreName.My, "Personal"),
        new KeyValuePair<StoreName, string>(StoreName.Root, "Trusted Root Certification Authorities"),
        new KeyValuePair<StoreName, string>(StoreName.CertificateAuthority, "Intermediate Certification Authorities"),
        new KeyValuePair<StoreName, string>(StoreName.TrustedPublisher, "Trusted Publishers"),
        new KeyValuePair<StoreName, string>(StoreName.Disallowed, "Untrusted Certificates"),
        new KeyValuePair<StoreName, string>(StoreName.AuthRoot, "Third-Party Root Certification Authorities"),
        new KeyValuePair<StoreName, string>(StoreName.TrustedPeople, "Trusted People"),
        new KeyValuePair<StoreName, string>(StoreName.AddressBook, "Other People")
    };

    private static string[] StoreNames => Stores.Select(x => x.Value).ToArray();

    private static readonly List<KeyValuePair<Constants.CertificateFindType, string>> CertificateFindTypes = new()
    {
        new KeyValuePair<CertificateFindType, string>(CertificateFindType.Thumbprint, "Thumbprint"),
        new KeyValuePair<CertificateFindType, string>(CertificateFindType.SubjectName, "Subject Name")
    };

    private static readonly string[] FindTypes = CertificateFindTypes.Select(x => x.Value).ToArray();
    
    private bool UseExternalCertificate => (Constants.CertificateMode)this.cmbCertificateSource.SelectedIndex == Constants.CertificateMode.External;

    private bool UseSystemCertificate => (Constants.CertificateMode)this.cmbCertificateSource.SelectedIndex == Constants.CertificateMode.System;

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

        this.cmbCertificateSource.DataSource = Enum.GetValues(typeof(Constants.CertificateMode));
        this.cmbCertificateSource.SelectedIndex = 0;

        this.cmbStoreLocation.DataSource = Locations;
        this.cmbCertificateSource.SelectedIndex = 0;

        this.cmbStore.DataSource = StoreNames;
        this.cmbStore.SelectedIndex = 0;

        this.cmbSearchBy.DataSource = FindTypes;
        this.cmbSearchBy.SelectedIndex = 0;
    }

    public override bool DoValidate()
    {
        if (this.UseExternalCertificate)
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
        }
        else
        {
            if (this.SelectedCertificate is null)
            {
                ShowValidationError("You must select a certificate from the system certificate store");
                return false;
            }
        }

        return true;
    }

    public override void FromProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);

        this.cmbCertificateSource.SelectedIndex = (int) properties.CertificateMode;
        this.txtCertificateFile.Text = properties.CertificateFile;
        this.txtPrivateKeyFile.Text = properties.CertificatePrivateKeyFile;
        this.txtCertificatePassword.Text = properties.CertificatePassword;
        this.cmbStoreLocation.SelectedIndex = (int)properties.CertificateLocation - 1;
        this.cmbStore.SelectedIndex = Stores.IndexOf(Stores.First(x => x.Key == properties.CertificateStore));
        this.cmbSearchBy.SelectedIndex =
            CertificateFindTypes.IndexOf(CertificateFindTypes.First(x => x.Key == properties.CertificateFindType));
        this.txtSearch.Text = properties.CertificateSearchText;

        if (this.UseSystemCertificate)
        {
            try
            {
                X509Certificate2Collection certificates = this.SearchCertificate(
                    (StoreLocation) this.cmbStoreLocation.SelectedIndex + 1,
                    Stores[this.cmbStore.SelectedIndex].Key,
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
            CertificateMode = (Constants.CertificateMode)this.cmbCertificateSource.SelectedIndex,
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
            properties.CertificateLocation = (StoreLocation)(this.cmbStoreLocation.SelectedIndex + 1);
            properties.CertificateStore = Stores[this.cmbStore.SelectedIndex].Key;
            properties.CertificateName = this.SelectedCertificate?.GetNameInfo(X509NameType.SimpleName, false);
            properties.CertificateThumbprint = this.SelectedCertificate?.Thumbprint;
        }

        properties.CertificateFindType = CertificateFindTypes[this.cmbSearchBy.SelectedIndex].Key;
        properties.CertificateSearchText = this.txtSearch.Text;

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
        const string filter =
            "PFX Files (*.pfx, *.p12)|*.pfx;*.p12|Certificate Files (*.pem, *.crt, *.cer)|*.pem;*.crt;*.cer|All Files|*.*";
        string file = this.BrowseForFile(filter);

        if (!string.IsNullOrEmpty(file))
        {
            this.txtCertificateFile.Text = file;
        }

        this.SetControlStates();
    }

    private void butBrowsePrivateKeyFile_Click(object sender, EventArgs e)
    {
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
                "Encrypted private keys are not supported";
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

            return store.Certificates.Find(x509FindType, findValue, true);
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
                Stores[this.cmbStore.SelectedIndex].Key,
                CertificateFindTypes[this.cmbSearchBy.SelectedIndex].Key,
                this.txtSearch.Text);
            
            if (certificates.Count == 0)
            {
                this.SetSelectedCertificate(null);

                MessageBox.Show("No matching certificates found", base.Localize("CertificateDlg_Title"));
            }
            else if (certificates.Count == 1)
            {
                this.SetSelectedCertificate(certificates[0]);
            }
            else
            {
                X509Certificate2Collection selection = X509Certificate2UI.SelectFromCollection(certificates,
                    base.Localize("CertificateDlg_Title"),
                    "Select the certificate to use", X509SelectionFlag.SingleSelection, this.Handle);

                if (selection.Count > 0)
                {
                    this.SetSelectedCertificate(selection[0]);
                }
            }
        }
        catch (Exception exception)
        {
            ShowValidationErrorString($"An unexpected error occurred accessing the system certificate store: {exception}");
        }
    }

    private void SetSelectedCertificate(X509Certificate2 certificate)
    {
        // this.SelectedCertificate?.Dispose(); TODO: .net48
        this.SelectedCertificate = certificate;

        this.lblCertificateDescription.Text = string.Empty;
        this.lblSelectedCertificate.Visible = this.lblCertificateDescription.Visible = this.butViewCertificate.Visible = this.SelectedCertificate is not null;

        if (this.SelectedCertificate is not null)
        {
            this.lblCertificateDescription.Text = this.SelectedCertificate?.GetNameInfo(X509NameType.SimpleName, false);
        }
    }

    private void butViewCertificate_Click(object sender, EventArgs e)
    {
        X509Certificate2UI.DisplayCertificate(this.SelectedCertificate, this.Handle);
    }
}
