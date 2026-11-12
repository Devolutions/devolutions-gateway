using Devolutions.Agent.Desktop.Properties;
using System;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Devolutions.Agent.Desktop.Diagnostics
{
    internal sealed class ChannelProbeForm : Form
    {
        private readonly TextBox output;

        private readonly Button btnRun;

        private readonly Button btnCopy;

        public ChannelProbeForm()
        {
            Text = "Virtual channel diagnostics";
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = MinimizeBox = false;
            ShowInTaskbar = false;
            Icon = ImageResources.AppIcon;
            AutoScaleMode = AutoScaleMode.Dpi;
            ClientSize = new Size(640, 420);
            Padding = new Padding(12);

            this.output = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 9f),
                Dock = DockStyle.Fill,
            };

            this.btnRun = new Button { Text = "Run again", AutoSize = true };
            this.btnRun.Click += async (_, _) => await this.RunProbes();

            this.btnCopy = new Button { Text = "Copy", AutoSize = true };
            this.btnCopy.Click += (_, _) => this.CopyReport();

            Button btnClose = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };

            FlowLayoutPanel buttons = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.RightToLeft,
                Dock = DockStyle.Fill,
                AutoSize = true,
            };

            buttons.Controls.Add(btnClose);
            buttons.Controls.Add(this.btnCopy);
            buttons.Controls.Add(this.btnRun);

            TableLayoutPanel layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 2,
            };

            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.Controls.Add(this.output, 0, 0);
            layout.Controls.Add(buttons, 0, 1);

            Controls.Add(layout);
            CancelButton = btnClose;

            Shown += async (_, _) => await this.RunProbes();
        }

        private async Task RunProbes()
        {
            this.btnRun.Enabled = false;
            this.btnCopy.Enabled = false;
            this.output.Text = "Running...";

            string report;

            try
            {
                report = await Task.Run(() => ChannelProbe.Run());
                Program.Log.Info(report);
            }
            catch (Exception e)
            {
                Program.Log.Error(e.ToString());
                report = $"Virtual channel diagnostics failed: {e.Message}";
            }

            if (this.IsDisposed)
            {
                return;
            }

            this.output.Text = report;
            this.btnRun.Enabled = true;
            this.btnCopy.Enabled = true;
        }

        private void CopyReport()
        {
            try
            {
                Clipboard.SetText(this.output.Text);
            }
            catch (Exception e)
            {
                Program.Log.Warn($"Failed to copy the report: {e.Message}");
            }
        }
    }
}
