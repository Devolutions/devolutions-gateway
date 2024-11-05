using Devolutions.Agent.Desktop.Properties;

using Microsoft.Toolkit.Uwp.Notifications;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Ipc;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;

namespace Devolutions.Agent.Desktop
{
    internal static class Program
    {
        private const string MutexId = "Local\\BF3262DE-F439-455F-B67F-9D32D9FD5E58";

        private static string[] Args { get; set; }

        internal static AppContext AppContext { get; private set; }

        internal static Logger Log = new(new FileLogger());

        [STAThread]
        private static void Main(string[] args)
        {
            Log.Debug("Starting...");

            Args = args;

            using Mutex mutex = new(false, MutexId);
            const string serviceUri = "RemotingServer";

            if (!mutex.WaitOne(0))
            {
                Log.Debug("Forwarding arguments to existing instance");

                try
                {
                    IpcChannel clientChannel = new();
                    ChannelServices.RegisterChannel(clientChannel, false);
                    SingleInstance app = (SingleInstance)Activator.GetObject(typeof(SingleInstance),
                        $"ipc://{MutexId}/{serviceUri}");
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
                IpcChannel serverChannel = new(MutexId);
                ChannelServices.RegisterChannel(serverChannel, false);
                RemotingConfiguration.RegisterWellKnownServiceType(typeof(SingleInstance),
                    serviceUri, WellKnownObjectMode.Singleton);
            }
            catch (Exception e)
            {
                Log.Error(e.ToString());
            }


            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Idle += Application_OnIdle;

            AppContext = new AppContext();

            Application.Run(AppContext);
        }

        private static void Application_OnIdle(object sender, EventArgs e)
        {
            Application.Idle -= Application_OnIdle;

            AppContext.Dispatch(Args);
        }
    }

    public class AppContext : ApplicationContext
    {
        private readonly SynchronizationContext synchronizationContext;

        private readonly NotifyIcon trayIcon;

        public AppContext()
        {
            string title =
                $"{Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyTitleAttribute>().Title} {Assembly.GetExecutingAssembly().GetName().Version}";

            this.synchronizationContext = new WindowsFormsSynchronizationContext();
            this.trayIcon = new NotifyIcon()
            {
                Icon = Resources.AppIcon,
                ContextMenu = new ContextMenu(new []
                {
                    new MenuItem(title) { Enabled = false},
                    new MenuItem("Exit", OnExit_Click),
                }),
                Visible = true,
            };
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
                        // TODO: Better error handling than just HRESULT conversion
                        title = "Unexpected Error";
                        text = new Win32Exception(int.Parse(commandArgs.First())).Message;
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
