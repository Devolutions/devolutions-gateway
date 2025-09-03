using Devolutions.Agent.Desktop.Properties;
using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

namespace Devolutions.Agent.Desktop
{
    internal class About : Form
    {
        public About()
        {
            this.Text = Resources.lblAbout;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterScreen;
            this.MaximizeBox = this.MinimizeBox = false;
            this.Icon = Resources.AppIcon;
            this.ShowInTaskbar = false;
            this.AutoSize = true;
            this.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            this.MinimumSize = new Size(260, 100);

            using MemoryStream ms = new MemoryStream(Resources.devolutions_agent_icon_shadow);

            PictureBox pbLogo = new PictureBox()
            {
                Image = Image.FromStream(ms),
                SizeMode = PictureBoxSizeMode.Zoom,
                Dock = DockStyle.Top,
            };

            Label lblName = new Label()
            {
                Text = Resources.lblProductName,
                Dock = DockStyle.Top,
                Height = 40,
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font(Font.FontFamily, 12, FontStyle.Bold),
            };

            Version version = Assembly.GetExecutingAssembly().GetName().Version;

            Label lblVersion = new Label
            {
                Text = $@"{version.Major}.{version.Minor}.{version.Build}.{version.Revision}",
                Dock = DockStyle.Top,
                Height = 30,
                TextAlign = ContentAlignment.MiddleCenter,
            };

            Label lblVendor = new Label
            {
                Text = Resources.lblVendor,
                Dock = DockStyle.Top,
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font(Font.FontFamily, 7, FontStyle.Regular),
            };

            Label lblCopyright = new Label
            {
                Text = $@"{Resources.lblCopyright} © 2006 - {DateTime.Now.Year}",
                Dock = DockStyle.Top,
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font(Font.FontFamily, 7, FontStyle.Regular),
            };

            this.Controls.Add(lblCopyright);
            this.Controls.Add(lblVendor);
            this.Controls.Add(lblVersion);
            this.Controls.Add(lblName);
            this.Controls.Add(pbLogo);

            this.FormClosed += (_, _) => this.DialogResult = DialogResult.OK;
        }
    }
}
