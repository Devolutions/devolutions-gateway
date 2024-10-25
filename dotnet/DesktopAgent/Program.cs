using Devolutions.Agent.Desktop.Properties;

using Microsoft.Toolkit.Uwp.Notifications;

using System;
using System.Windows.Forms;

namespace Devolutions.Agent.Desktop
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new AppContext());
        }
    }

    public class AppContext : ApplicationContext
    {
        private readonly NotifyIcon trayIcon;

        public AppContext()
        {
            this.trayIcon = new NotifyIcon()
            {
                Icon = Resources.AppIcon,
                ContextMenu = new ContextMenu(new []
                {
                    new MenuItem("Show Toast", OnShowToast_Click),
                    new MenuItem("Exit", OnExit_Click),
                }),
                Visible = true,
            };
        }

        private void OnExit_Click(object sender, EventArgs e)
        {
            trayIcon.Visible = false;

            Application.Exit();
        }

        private void OnShowToast_Click(object sender, EventArgs e)
        {
            new ToastContentBuilder()
                .AddText("Andrew sent you a picture")
                .AddText("Check this out, The Enchantments in Washington!")
                .Show();
        }
    }
}
