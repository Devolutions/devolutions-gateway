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
using System.Security.Principal;
using Devolutions.Agent.Desktop.SingleInstance;
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

        internal static AppContext AppContext { get; private set; }

        internal static Logger Log = new(new FileLogger());

        [STAThread]
        private static void Main(string[] args)
        {
            Log.Debug("Starting...");

            Args = args;

            ProcessIdentity identity = null;

            try
            {
                identity = ProcessIdentity.Current();
            }
            catch (Exception e)
            {
                Log.Error($"Failed to query process identity: {e}");
            }

            using Mutex mutex = new(false, MutexName);

            if (!mutex.WaitOne(0))
            {
                Log.Debug("Forwarding arguments to existing instance");

                try
                {
                    if (identity is not null)
                    {
                        SingleInstancePipe.Forward(identity, args, Log);
                    }
                }
                catch (Exception e)
                {
                    Log.Error(e.ToString());
                }

                return;
            }

            using EventWaitHandle exitEvent = CreateExitEvent();

            if (exitEvent is not null)
            {
                Thread exitMonitor = new Thread(() =>
                {
                    exitEvent.WaitOne();
                    Application.Exit();
                })
                {
                    IsBackground = true,
                };

                exitMonitor.Start();
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Idle += Application_OnIdle;

            AppContext = new AppContext();

            using SingleInstanceServer server = identity is null ? null : SingleInstanceServer.TryStart(identity, AppContext.Dispatch, Log);

            Application.Run(AppContext);
        }

        /// <summary>
        /// Creates the event the installer signals to close this instance.
        /// </summary>
        /// <returns>The event, or null if it could not be created by this process.</returns>
        private static EventWaitHandle CreateExitEvent()
        {
            string name = $"{MutexId}_{Process.GetCurrentProcess().Id}";

            try
            {
                EventWaitHandle exitEvent = new(false, EventResetMode.ManualReset, name, out bool createdNew);

                if (createdNew)
                {
                    return exitEvent;
                }

                // Do not use an event that already existed before this process created it.
                exitEvent.Dispose();
                Log.Warn($"Exit event {name} already exists; ignoring it");
            }
            catch (Exception e)
            {
                Log.Warn($"Failed to create exit event {name}: {e.Message}");
            }

            return null;
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

        public void Warn(string message)
        {
            this.logger.Log(message, "WARN");
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
        private readonly object sync = new();

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
            lock (this.sync)
            {
                this.writer?.WriteLine($"{DateTime.Now:O} [{level}] {message}");
                this.writer?.Flush();
            }
        }

        public void Dispose()
        {
            writer?.Dispose();
            fs?.Dispose();
        }
    }
}
