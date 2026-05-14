using DevolutionsGateway.Actions;
using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Helpers;
using DevolutionsGateway.Properties;
using DevolutionsGateway.Resources;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;
using WixSharp;
using static DevolutionsGateway.Properties.Constants;
using File = System.IO.File;
using StoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation;
using StoreName = System.Security.Cryptography.X509Certificates.StoreName;

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
    }

    private enum ValidationOutcome
    {
        Ok,
        KeyAccessOnly,
        Warnings,
    }

    public override bool DoValidate()
    {
        ValidationOutcome outcome;
        string[] messages;

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

            outcome = ValidateExternalCertificate(out messages);
        }
        else
        {
            if (this.SelectedCertificate is null)
            {
                ShowValidationError(I18n(Strings.YouMustSelectACertificateFromTheSystemCertificateStore));
                return false;
            }

            outcome = ValidateSystemCertificate(out messages);
        }

        switch (outcome)
        {
            case ValidationOutcome.Ok:
                return true;

            case ValidationOutcome.KeyAccessOnly:
                MessageBox.Show(
                    messages[0],
                    this.Localize("[GatewayDlg_Title]"),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return true;

            case ValidationOutcome.Warnings:
            default:
                StringBuilder sb = new();
                sb.AppendLine(I18n(Strings.ValidationProducedWarnings));
                sb.AppendLine("");
                for (int i = 0; i < messages.Length; i++)
                {
                    sb.AppendLine($"{i + 1}. {messages[i]}");
                }
                sb.AppendLine("");
                sb.AppendLine(I18n(Strings.DoYouWantToProceedAnyway));

                return MessageBox.Show(
                    sb.ToString(),
                    this.Localize("[GatewayDlg_Title]"),
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2) == DialogResult.Yes;
        }
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
        this.txtSearch.Text = properties.CertificateSearchText;

        if (this.UseSystemCertificate && !string.IsNullOrWhiteSpace(properties.CertificateSearchText))
        {
            try
            {
                this.SearchCertificate(false);
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
        }

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

        this.FormClosed += (s, e) => this.SelectedCertificate?.Dispose();
        this.lblResults.Text = string.Empty;

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

    private void txtCertificatePassword_TextChanged(object sender, EventArgs e)
    {
        this.SetControlStates();
    }

    private void txtPrivateKeyFile_TextChanged(object sender, EventArgs e)
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

    private void SearchCertificate(bool userAction)
    {
        try
        {
            CertificateSelection.Result selection = CertificateSelection.Select(
                (StoreLocation)this.cmbStoreLocation.SelectedIndex + 1,
                this.cmbStore.Selected<StoreName>(),
                this.txtSearch.Text,
                strictMode: true);

            this.lblResults.Visible = true;
            this.lblResults.Text = string.Format(
                selection.MatchCount == 1 ? I18n(Strings.SearchResultSingular) : I18n(Strings.SearchResultPlural),
                selection.MatchCount);

            if (selection.Selected != null)
            {
                this.SetSelectedCertificate(selection.Selected);
            }
            else
            {
                this.SetSelectedCertificate(null);

                if (userAction)
                {
                    if (selection.AllFiltered)
                    {
                        StringBuilder sb = new();
                        sb.AppendLine(string.Format(I18n(Strings.CertificatesFoundButUnusable), selection.MatchCount));
                        sb.AppendLine("");
                        DisplayEnum<CertificateIssues> display = new DisplayEnum<CertificateIssues>(this.MsiRuntime);
                        display.Items
                            .Where(i => i.Value != CertificateIssues.None)
                            .Where(i => selection.FilteredReasons.HasFlag(i.Value))
                            .Select((i, index) => $"{index + 1}. {i.Name}")
                            .ForEach(sb.AppendLine);

                        ShowValidationErrorString(sb.ToString());
                    }
                    else
                    {
                        ShowValidationErrorString(I18n(Strings.NoMatchingCertificatesFound));
                    }
                }
            }
        }
        catch (Exception exception)
        {
            if (userAction)
            {
                ShowValidationErrorString(string.Format(I18n(Strings.AnUnexpectedErrorOccurredAccessingTheSystemCertificateStoreX), exception));
            }
        }
    }

    private void butSearchCertificate_Click(object sender, EventArgs e)
    {
        this.SearchCertificate(true);
    }

    private void SetSelectedCertificate(X509Certificate2 certificate)
    {
        this.SelectedCertificate?.Dispose();

        this.SelectedCertificate = certificate;

        this.butViewCertificate.Enabled = this.SelectedCertificate is not null;
        this.lblCertificateDescription.Text = I18n(Strings.NoCertificateSelected);

        if (this.SelectedCertificate is null)
        {
            return;
        }

        this.lblCertificateDescription.Text = this.SelectedCertificate.GetNameInfo(X509NameType.SimpleName, false);
    }

    private ValidationOutcome ValidateExternalCertificate(out string[] errors)
    {
        string certificateFile = this.txtCertificateFile.Text.Trim();
        string certificatePassword = this.NeedsPassword() ? this.txtCertificatePassword.Text : null;
        List<string> messages = [];
        X509Certificate2Collection certificates = null;

        try
        {
            if (!CertificateChain.TryLoad(certificateFile, certificatePassword, out certificates, out Exception error))
            {
                errors = [string.Format(I18n(Strings.CertificateFileCouldNotBeRead), error.Message.Trim())];
                return ValidationOutcome.Warnings;
            }

            if (CertificateChain.FindLeaf(certificates) is not X509Certificate2 leaf)
            {
                errors = [I18n(Strings.NoUsableCertificateFoundInFile)];
                return ValidationOutcome.Warnings;
            }

            if (CertificateChain.IsCertificateAuthority(leaf))
            {
                errors = [I18n(Strings.CertificateIsCaNotServer)];
                return ValidationOutcome.Warnings;
            }

            if (CertificateChain.IsSelfSigned(leaf))
            {
                messages.Add(I18n(Strings.CertificateIsSelfSigned));
            }
            else
            {
                CertificateChainStatus chainStatus = CertificateChain.CheckChain(leaf, certificates);
                if (chainStatus != CertificateChainStatus.Ok)
                {
                    messages.Add(new DisplayEnum<CertificateChainStatus>(this.MsiRuntime)
                        .Items.First(i => i.Value == chainStatus).Name);
                }
            }

            CertificateIssues issues = CertificateChain.CheckCertificate(leaf);
            DisplayEnum<CertificateIssues> display = new DisplayEnum<CertificateIssues>(this.MsiRuntime);
            display.Items
                .Where(i => i.Value != CertificateIssues.None)
                .Where(i => issues.HasFlag(i.Value))
                .Select(i => i.Name)
                .ForEach(messages.Add);

            errors = messages.ToArray();
            return messages.None() ? ValidationOutcome.Ok : ValidationOutcome.Warnings;
        }
        finally
        {
            CertificateChain.DisposeAll(certificates);
        }
    }

    private ValidationOutcome ValidateSystemCertificate(out string[] errors)
    {
        bool valid = this.SelectedCertificate.Verify();
        CertificateIssues issues = CertificateChain.CheckCertificate(this.SelectedCertificate);
        bool keyRead = PrivateKeyPermissions.HasNetworkServiceReadPermission(this.SelectedCertificate);

        if (valid && issues == CertificateIssues.None)
        {
            if (keyRead)
            {
                errors = Array.Empty<string>();
                return ValidationOutcome.Ok;
            }

            errors = [I18n(Strings.PrivateKeyPermissionWillBeGranted)];
            return ValidationOutcome.KeyAccessOnly;
        }

        List<string> messages = [];

        if (!valid)
        {
            messages.Add(I18n(Strings.CertificateCouldNotBeVerified));
        }

        DisplayEnum<CertificateIssues> display = new DisplayEnum<CertificateIssues>(this.MsiRuntime);
        display.Items
            .Where(i => i.Value != CertificateIssues.None)
            .Where(i => issues.HasFlag(i.Value))
            .Select(i => i.Name)
            .ForEach(messages.Add);

        if (!keyRead)
        {
            messages.Add(I18n(Strings.PrivateKeyPermissionWillBeGranted));
        }

        errors = messages.ToArray();
        return ValidationOutcome.Warnings;
    }

    private void butViewCertificate_Click(object sender, EventArgs e)
    {
        X509Certificate2UI.DisplayCertificate(this.SelectedCertificate, this.Handle);
    }
}
