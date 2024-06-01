using System;
using System.Windows.Forms;
using DevolutionsAgent.Resources;
using WixSharp;
using WixSharp.UI.Forms;

namespace DevolutionsAgent.Dialogs;

public class AgentDialog : ManagedForm
{
    public AgentDialog()
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
        this.Text = "[AgentDlg_Title]".LocalizeWith(this.MsiRuntime.Localize);

        this.FromProperties();
    }

    protected virtual void Back_Click(object sender, EventArgs e)
    {
        if (this.ToProperties())
        {
            Shell.GoTo(Wizard.GetPrevious(this));
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
            Shell.GoTo(Wizard.GetNext(this));
        }
    }

    protected virtual void Cancel_Click(object sender, EventArgs e)
    {
        if (MessageBox.Show(
                this.Localize("[CancelDlgText]"),
                this.Localize("[CancelDlg_Title]"),
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning) == DialogResult.Yes)
        {
            Shell.Cancel();
        }
    }

    protected string I18n(string key) => MsiRuntime.I18n(key);

    protected void ShowValidationError(string message = null)
    {
        string errorMessage = string.IsNullOrEmpty(message) ? MsiRuntime.I18n(Strings.ThereIsAProblemWithTheEnteredData) : message;

        this.ShowValidationErrorString(errorMessage);
    }

    protected void ShowValidationErrorString(string message)
    {
        MessageBox.Show(
            message,
            this.Localize("[AgentDlg_Title]"),
            MessageBoxButtons.OK,
            MessageBoxIcon.Warning);
    }

    protected string Localize(string message) => message.LocalizeWith(MsiRuntime.Localize);
}
