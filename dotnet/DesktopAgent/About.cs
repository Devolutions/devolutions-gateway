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
            Text = Resources.lblAbout;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = MinimizeBox = false;
            Icon = ImageResources.AppIcon;
            ShowInTaskbar = false;

            AutoScaleMode = AutoScaleMode.Dpi;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;

            MinimumSize = new Size(320, 180);
            Padding = new Padding(12);

            DpiAwareImageBox pbLogo = new DpiAwareImageBox
            {
                Image = ImageResources.devolutions_agent_icon_shadow,
                Dock = DockStyle.Fill,
                MinimumSize = new Size(0, 96),
            };

            Label lblName = new Label
            {
                Text = StaticResources.DevolutionsAgent,
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleCenter,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 0, 0, 6),
                Font = new Font(Font.FontFamily, 12f, FontStyle.Bold),
            };

            Version version = Assembly.GetExecutingAssembly().GetName().Version;

            Label lblVersion = new Label
            {
                Text = $@"{version.Major}.{version.Minor}.{version.Build}.{version.Revision}",
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleCenter,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 0, 0, 6),
            };

            Label lblVendor = new Label
            {
                Text = StaticResources.DevolutionsInc,
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleCenter,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 0, 0, 2),
                Font = new Font(Font.FontFamily, 8f, FontStyle.Regular),
            };

            Label lblCopyright = new Label
            {
                Text = $@"{Resources.lblCopyright} © 2006 - {DateTime.Now.Year}",
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleCenter,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 0, 0, 0),
                Font = new Font(Font.FontFamily, 8f, FontStyle.Regular),
            };

            TableLayoutPanel layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                ColumnCount = 1,
                RowCount = 5,
                Padding = new Padding(0),
                Margin = new Padding(0),
            };

            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

            layout.Controls.Add(pbLogo, 0, 0);
            layout.Controls.Add(lblName, 0, 1);
            layout.Controls.Add(lblVersion, 0, 2);
            layout.Controls.Add(lblVendor, 0, 3);
            layout.Controls.Add(lblCopyright, 0, 4);

            Controls.Add(layout);

            FormClosed += (_, _) => DialogResult = DialogResult.OK;
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);

            if (Utils.Theme() == Utils.ThemeMode.Dark)
            {
                Utils.UseImmersiveDarkMode(Handle, true);
                DarkTheme.Apply(this);
            }
        }
    }

    internal static class DarkTheme
    {
        public static readonly Color WindowBack = Color.FromArgb(32, 32, 32);

        public static readonly Color PanelBack = Color.FromArgb(32, 32, 32);

        public static readonly Color Text = Color.FromArgb(240, 240, 240);

        public static void Apply(Control root)
        {
            root.BackColor = WindowBack;
            root.ForeColor = Text;

            ApplyToChildren(root);
        }

        private static void ApplyToChildren(Control parent)
        {
            foreach (Control c in parent.Controls)
            {
                switch (c)
                {
                    case LinkLabel link:
                        link.LinkColor = Text;
                        link.ActiveLinkColor = Text;
                        link.VisitedLinkColor = Text;
                        link.BackColor = Color.Transparent;
                        break;

                    case Label lbl:
                        lbl.BackColor = Color.Transparent;
                        break;

                    case TableLayoutPanel tlp:
                        tlp.BackColor = PanelBack;
                        break;

                    case Panel p:
                        p.BackColor = PanelBack;
                        break;

                    case Button btn:
                        btn.FlatStyle = FlatStyle.Flat;
                        btn.BackColor = Color.FromArgb(45, 45, 45);
                        btn.ForeColor = Text;
                        btn.FlatAppearance.BorderColor = Color.FromArgb(80, 80, 80);
                        btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(55, 55, 55);
                        btn.FlatAppearance.MouseDownBackColor = Color.FromArgb(65, 65, 65);
                        break;

                    default:
                        c.BackColor = parent.BackColor;
                        c.ForeColor = parent.ForeColor;
                        break;
                }

                if (c.HasChildren)
                {
                    ApplyToChildren(c);
                }
            }
        }
    }

    internal sealed class DpiAwareImageBox : Control
    {
        private Image image;

        public Image Image
        {
            get => image;
            set
            {
                image = value;
                Invalidate();
            }
        }

        public DpiAwareImageBox()
        {
            DoubleBuffered = true;
            SetStyle(ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);

            if (image == null)
                return;

            e.Graphics.InterpolationMode =
                System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
            e.Graphics.SmoothingMode =
                System.Drawing.Drawing2D.SmoothingMode.HighQuality;
            e.Graphics.PixelOffsetMode =
                System.Drawing.Drawing2D.PixelOffsetMode.HighQuality;

            Rectangle dest = GetScaledRect(ClientRectangle, image.Size);
            e.Graphics.DrawImage(image, dest);
        }

        private static Rectangle GetScaledRect(Rectangle bounds, Size imageSize)
        {
            float ratio = Math.Min(
                (float)bounds.Width / imageSize.Width,
                (float)bounds.Height / imageSize.Height);

            int w = (int)(imageSize.Width * ratio);
            int h = (int)(imageSize.Height * ratio);

            int x = bounds.X + (bounds.Width - w) / 2;
            int y = bounds.Y + (bounds.Height - h) / 2;

            return new Rectangle(x, y, w, h);
        }
    }
}
