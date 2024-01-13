using System;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using WixSharp;
using WixSharp.UI.Forms;

namespace DevolutionsGateway.Dialogs;

public class GatewayDialog : ManagedForm
{
    public GatewayDialog()
    {
        this.AutoScaleMode = AutoScaleMode.Font;
    }

    public virtual void FromProperties()
    {
    }

    public virtual bool ToProperties() => true;

    public virtual bool DoValidate() => true;

    public virtual void OnLoad(object sender, EventArgs e)
    {
        this.FromProperties();
    }

    protected virtual void Back_Click(object sender, EventArgs e)
    {
        if (this.ToProperties())
        {
            Shell.GoPrev();
        }
    }

    protected virtual void Next_Click(object sender, EventArgs e)
    {
        if (!this.DoValidate())
        {
            return;
        }

        if (this.ToProperties())
        {
            Shell.GoNext();
        }
    }

    protected virtual void Cancel_Click(object sender, EventArgs e)
    {
        if (MessageBox.Show(
                this.Localize("CancelDlgText"),
                this.Localize("CancelDlg_Title"),
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning) == DialogResult.Yes)
        {
            Shell.Cancel();
        }
    }

    protected void ShowValidationError(string message = null)
    {
        string errorMessage = this.Localize(string.IsNullOrEmpty(message) ? "InvalidConfigurationDlgInfoLabel" : message);

        this.ShowValidationErrorString(errorMessage);
    }

    protected void ShowValidationErrorString(string message)
    {
        MessageBox.Show(
            message,
            this.Localize("InvalidConfigurationDlg_Title"),
            MessageBoxButtons.OK,
            MessageBoxIcon.Warning);
    }

    protected string Localize(string message) => ResolveVariables(MsiRuntime.Localize(message));

    private string ResolveVariables(string message)
    {
        return Regex.Replace(message, @"\[(.*?)]", (match) =>
        {
            string property = match.Groups[1].Value;
            string value = this.Session()[property];

            return string.IsNullOrEmpty(value) ? property : value;
        });
    }
}
