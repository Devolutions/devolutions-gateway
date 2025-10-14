using System;
using System.Threading;

namespace DevolutionsGateway.Helpers
{
    public sealed class Debouncer : IDisposable
    {
        private readonly TimeSpan delay;

        private readonly Action<object> action;

        private readonly object arg;

        private readonly SynchronizationContext ui;

        private readonly object @lock = new object();

        private Timer timer;

        private bool disposed;

        public Debouncer(TimeSpan delay, Action<object> action, object arg, SynchronizationContext uiContext)
        {
            this.delay = delay;
            this.action = action;
            this.arg = arg;
            ui = uiContext;
            timer = new Timer(this.OnTimer, null, Timeout.Infinite, Timeout.Infinite);
        }

        public void Invoke()
        {
            lock (@lock)
            {
                if (disposed)
                {
                    return;
                }

                timer.Change(delay, Timeout.InfiniteTimeSpan);
            }
        }

        private void OnTimer(object state)
        {
            lock (@lock)
            {
                if (disposed)
                {
                    return;
                }
            }

            try
            {
                ui.Post(_ => action(this.arg), null);
            }
            catch
            {
            }
        }

        public void Dispose()
        {
            lock (@lock)
            {
                if (disposed)
                {
                    return;
                }

                disposed = true;
                timer.Change(Timeout.Infinite, Timeout.Infinite);
                timer.Dispose();
                timer = null;
            }
        }
    }
}
