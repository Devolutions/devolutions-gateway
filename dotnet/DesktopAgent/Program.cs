using Devolutions.Agent.Desktop.Properties;
using Devolutions.Agent.Desktop.Service;
using Devolutions.Pedm.Client.Model;
using Microsoft.Toolkit.Uwp.Notifications;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Ipc;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;
using Application = System.Windows.Forms.Application;

namespace Devolutions.Agent.Desktop
{
    internal static class Program
    {
        private const string MutexId = "BF3262DE-F439-455F-B67F-9D32D9FD5E58";

        private const string MutexName = $"Local\\{MutexId}";

        private static string[] Args { get; set; }

        private static EventWaitHandle ExitEvent = new(false, EventResetMode.ManualReset, $"{MutexId}_{Process.GetCurrentProcess().Id}");

        internal static AppContext AppContext { get; private set; }

        internal static Logger Log = new(new FileLogger());

        [STAThread]
        private static void Main(string[] args)
        {
            Log.Debug("Starting...");

            Args = args;

            using Mutex mutex = new(false, MutexName);
            const string serviceUri = "RemotingServer";

            if (!mutex.WaitOne(0))
            {
                Log.Debug("Forwarding arguments to existing instance");

                try
                {
                    IpcChannel clientChannel = new();
                    ChannelServices.RegisterChannel(clientChannel, false);
                    SingleInstance app = (SingleInstance)Activator.GetObject(typeof(SingleInstance),
                        $"ipc://{MutexName}/{serviceUri}");
                    app.Execute(args);
                }
                catch (Exception e)
                {
                    Log.Error(e.ToString());
                }

                return;
            }

            Log.Debug("Starting IPC server");

            try
            {
                IpcChannel serverChannel = new(MutexName);
                ChannelServices.RegisterChannel(serverChannel, false);
                RemotingConfiguration.RegisterWellKnownServiceType(typeof(SingleInstance),
                    serviceUri, WellKnownObjectMode.Singleton);
            }
            catch (Exception e)
            {
                Log.Error(e.ToString());
            }

            Thread exitMonitor = new Thread(() =>
            {
                ExitEvent.WaitOne();
                Application.Exit();
            });

            exitMonitor.Start();

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Idle += Application_OnIdle;

            AppContext = new AppContext();

            Application.Run(AppContext);

            ExitEvent.Set();
        }

        private static void Application_OnIdle(object sender, EventArgs e)
        {
            Application.Idle -= Application_OnIdle;

            AppContext.Dispatch(Args);
        }
    }

    public class AppContext : ApplicationContext
    {
        private readonly RootConfig config;

        private readonly ContextMenu contextMenu;

        private readonly SynchronizationContext synchronizationContext;

        private readonly NotifyIcon trayIcon;

        public AppContext()
        {
            config = Utils.LoadConfig();

            Version version = Assembly.GetExecutingAssembly().GetName().Version;

            this.synchronizationContext = new WindowsFormsSynchronizationContext();
            this.contextMenu = new();
            this.contextMenu.Popup += ContextMenuOnPopup;
            this.trayIcon = new NotifyIcon()
            {
                Icon = ImageResources.AppIcon,
                ContextMenu = contextMenu,
                Text = $"{StaticResources.DevolutionsAgent} v{version.Major}.{version.Minor}.{version.Build}",
                Visible = true,
            };
        }

        private void ContextMenuOnPopup(object sender, EventArgs e)
        {
            bool ctrl = (Control.ModifierKeys & Keys.Control) == Keys.Control;

            this.contextMenu.MenuItems.Clear();

            this.contextMenu.MenuItems.Add(Resources.mnuAbout, (_, _) =>
            {
                using About aboutWindow = new();
                aboutWindow.ShowDialog();
            });

            this.contextMenu.MenuItems.Add(new MenuItem("-"));
            this.contextMenu.MenuItems.Add(new MenuItem(Utils.IsServiceRunning("DevolutionsAgent") ? Resources.mnuServiceAvailable : Resources.mnuServiceUnavailable) { Enabled = false });

            if (ctrl)
            {
                this.contextMenu.MenuItems.Add(new MenuItem("-"));
                this.contextMenu.MenuItems.Add(new MenuItem("Updater") { Enabled = false, Checked = config?.Updater?.Enabled ?? false });
                this.contextMenu.MenuItems.Add(new MenuItem("Session") { Enabled = false, Checked = config?.Session?.Enabled ?? false });
                this.contextMenu.MenuItems.Add(new MenuItem("PEDM") { Enabled = false, Checked = config?.Pedm?.Enabled ?? false });
            }

            if (config?.Pedm?.Enabled ?? false)
            {
                this.contextMenu.MenuItems.Add(new MenuItem("-"));

                if (Client.Available)
                {
                    List<(long, string)> profiles = new List<(long, string)>();
                    profiles.Add((0, Resources.mnuProfileNone));

                    MenuItem mnuProfiles = new MenuItem(Resources.mnuProfiles);

                    GetProfilesMeResponse currentProfiles = null;

                    try
                    {
                        currentProfiles = Client.CurrentProfiles();
                        profiles.AddRange(currentProfiles.Available.Select(z => (z, Client.GetProfile(z).Name)));
                    }
                    catch (Exception exception)
                    {
                        Program.Log.Error(exception.ToString());
                    }

                    foreach (var profile in profiles)
                    {
                        MenuItem mnuProfile = new MenuItem(profile.Item2);
                        mnuProfile.Tag = profile.Item1;

                        if (profile.Item1 == currentProfiles?.Active)
                        {
                            mnuProfile.Checked = true;
                        }

                        mnuProfile.Click += (o, _) =>
                        {
                            try
                            {
                                long profileId = (long)((MenuItem)o).Tag;
                                Client.SetCurrentProfile(profileId);
                            }
                            catch (Exception exception)
                            {
                                Program.Log.Error(exception.ToString());
                            }
                        };

                        mnuProfiles.MenuItems.Add(mnuProfile);
                    }

                    this.contextMenu.MenuItems.Add(mnuProfiles);
                }
                else
                {
                    this.contextMenu.MenuItems.Add(new MenuItem(Resources.mnuPEDMUnavailable) { Enabled = false });
                }
            }

            this.contextMenu.MenuItems.Add(new MenuItem("-"));
            this.contextMenu.MenuItems.Add(new MenuItem(Resources.mnuExit, OnExit_Click));
        }

        internal void Dispatch(string[] args)
        {
            if (args?.Length < 3)
            {
                Program.Log.Debug("Args is null or has less than 3 elements");

                return;
            }

            string title;
            string text;

            try
            {
                Program.Log.Debug($"Arguments: {string.Join(", ", args)}");

                SecurityIdentifier sid = new SecurityIdentifier(args[1]);
                string verb = args[2];
                IEnumerable<string> commandArgs = args.Skip(3);

                Program.Log.Debug($"Parsed arguments: {sid.Value} {verb} {string.Join(", ", commandArgs)}");

                switch (verb)
                {
                    case "error":
                    {
                        if (int.TryParse(commandArgs.FirstOrDefault(), out int errorCode))
                        {
                            switch (errorCode)
                            {
                                case 1260:
                                {
                                    title = Resources.msgElevationBlocked;
                                    text = Resources.msgElevationBlockedDescription;
                                    break;
                                }

                                default:
                                {
                                    title = Resources.msgElevationFailed;
                                    text = new Win32Exception(errorCode).Message;
                                    break;
                                }
                            }
                        }
                        else
                        {
                            title = Resources.msgElevationFailed;
                            text = Resources.msgUnexpectedErrorDescription;
                        }

                        break;
                    }

                    default:
                    {
                        Program.Log.Error($"Unhandled command verb: {verb}");

                        return;
                    }
                }
            }
            catch (Exception e)
            {
                Program.Log.Error($"Failed to parse arguments: {e}");

                return;
            }

            this.synchronizationContext.Post(_ =>
            {
                new ToastContentBuilder()
                    .AddText(title, hintMaxLines: 1)
                    .AddText(text)
                    .Show();
            }, null);
        }

        protected override void Dispose(bool disposing)
        {
            Program.Log.Dispose();

            this.trayIcon?.Dispose();

            base.Dispose(disposing);
        }

        private void OnExit_Click(object sender, EventArgs e)
        {
            trayIcon.Visible = false;

            Application.Exit();
        }
    }

    public class SingleInstance : MarshalByRefObject
    {
        public void Execute(string[] args)
        {
            Program.AppContext.Dispatch(args);
        }
    }

    internal interface ILogger
    {
        void Log(string message, string level);
    }

    internal class Logger : IDisposable
    {
        private readonly ILogger logger;

        public Logger(ILogger logger)
        {
            this.logger = logger;
        }

        public void Debug(string message)
        {
            this.logger.Log(message, "DEBUG");
        }

        public void Info(string message)
        {
            this.logger.Log(message, "INFO");
        }

        public void Error(string message)
        {
            this.logger.Log(message, "ERROR");
        }

        public void Dispose()
        {
            if (this.logger is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }

    internal sealed class FileLogger : ILogger, IDisposable
    {
        private readonly FileStream fs;

        private readonly TextWriter writer;

        public FileLogger()
        {
            string tempPath = Path.GetTempPath();
            string path = Path.Combine(tempPath, $"DevolutionsDesktopAgent_{Guid.NewGuid()}.log");

            try
            {
                this.fs = new FileStream(path, FileMode.CreateNew);
                this.writer = new StreamWriter(this.fs);
            }
            catch
            {
                // ignored
            }
        }

        public void Log(string message, string level)
        {
            this.writer?.WriteLine($"{DateTime.Now:O} [{level}] {message}");
            this.writer?.Flush();
        }

        public void Dispose()
        {
            writer?.Dispose();
            fs?.Dispose();
        }
    }
}
