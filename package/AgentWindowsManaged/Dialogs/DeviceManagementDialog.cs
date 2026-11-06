using DevolutionsAgent.Actions;
using DevolutionsAgent.Dialogs;
using DevolutionsAgent.Properties;
using DevolutionsAgent.Resources;

using System;
using System.Drawing;
using System.Net.Sockets;
using System.Threading.Tasks;

using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class DeviceManagementDialog : AgentDialog
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);

    public DeviceManagementDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);
    }

    public override bool ToProperties()
    {
        _ = new AgentProperties(Runtime.Session)
        {
            DeviceManagementGrpcUrl = grpcUrl.Text.Trim(),
        };

        return true;
    }

    public override void FromProperties()
    {
        AgentProperties properties = new(Runtime.Session);

        grpcUrl.Text = properties.DeviceManagementGrpcUrl;
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        base.OnLoad(sender, e);
    }

    public override bool DoValidate()
    {
        string grpcUrlText = grpcUrl.Text.Trim();

        if (grpcUrlText.Length == 0)
        {
            ShowValidationErrorString(this.I18n(Strings.DeviceManagementDlgGrpcUrlRequired));
            return false;
        }

        if (!CustomActions.IsValidHttpUrl(grpcUrlText))
        {
            ShowValidationErrorString(this.I18n(Strings.DeviceManagementDlgGrpcUrlInvalid));
            return false;
        }

        return true;
    }

    private async void testConnection_Click(object sender, EventArgs e)
    {
        string grpcUrlText = grpcUrl.Text.Trim();

        if (!CustomActions.IsValidHttpUrl(grpcUrlText))
        {
            ShowTestResult(false, this.I18n(Strings.DeviceManagementDlgGrpcUrlInvalid));
            return;
        }

        testConnection.Enabled = false;
        testResult.ForeColor = SystemColors.ControlText;
        testResult.Text = this.I18n(Strings.DeviceManagementDlgTestingConnection);

        string error;
        try
        {
            error = await Task.Run(() => TestConnectionAsync(new Uri(grpcUrlText)));
        }
        catch (Exception ex)
        {
            error = (ex as AggregateException)?.GetBaseException().Message ?? ex.Message;
        }

        if (InvokeRequired)
        {
            BeginInvoke(new System.Action(() => CompleteTest(error)));
        }
        else
        {
            CompleteTest(error);
        }
    }

    private void CompleteTest(string error)
    {
        testConnection.Enabled = true;

        if (error is null)
        {
            ShowTestResult(true, this.I18n(Strings.DeviceManagementDlgConnectionSuccessful));
        }
        else
        {
            ShowTestResult(false, string.Format(this.I18n(Strings.DeviceManagementDlgConnectionFailed), error));
        }
    }

    private void ShowTestResult(bool success, string message)
    {
        testResult.ForeColor = success ? Color.Green : Color.Red;
        testResult.Text = message;
    }

    /// <summary>
    /// Open a TCP connection to the gRPC endpoint. The .NET Framework installer cannot speak gRPC over h2c,
    /// so this only checks that the host and port are reachable. Returns null on success, or an error message.
    /// </summary>
    private static async Task<string> TestConnectionAsync(Uri uri)
    {
        using TcpClient client = new();

        Task connectTask = client.ConnectAsync(uri.DnsSafeHost, uri.Port);
        Task completed = await Task.WhenAny(connectTask, Task.Delay(ConnectTimeout)).ConfigureAwait(false);

        if (completed != connectTask)
        {
            // Observe the abandoned task so its eventual failure is not reported as unobserved.
            _ = connectTask.ContinueWith(static task => _ = task.Exception, TaskContinuationOptions.OnlyOnFaulted);
            return $"timed out connecting to {uri.Host}:{uri.Port}";
        }

        await connectTask.ConfigureAwait(false);

        return null;
    }

    // WixSharp's ManagedForm wires Back/Next/Cancel button clicks via reflection on the
    // *concrete* dialog type rather than the base class, so each leaf dialog must surface
    // these three overrides even when they only delegate to base.

    // ReSharper disable once RedundantOverriddenMember
    protected override void Back_Click(object sender, EventArgs e) => base.Back_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Next_Click(object sender, EventArgs e) => base.Next_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Cancel_Click(object sender, EventArgs e) => base.Cancel_Click(sender, e);
}
