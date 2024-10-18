using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace DevolutionsAgent.Helpers
{
    public class Debouncer : IDisposable
    {
        private readonly TimeSpan ts;
        private readonly Action<object> action;
        private readonly object parameter;
        private readonly HashSet<ManualResetEvent> resets = new();
        private readonly object mutex = new();

        public Debouncer(TimeSpan timespan, Action<object> action, object parameter)
        {
            this.ts = timespan;
            this.action = action;
            this.parameter = parameter;
        }

        public void Invoke()
        {
            var thisReset = new ManualResetEvent(false);

            lock (mutex)
            {
                while (resets.Count > 0)
                {
                    var otherReset = resets.First();
                    resets.Remove(otherReset);
                    otherReset.Set();
                }

                resets.Add(thisReset);
            }

            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    if (!thisReset.WaitOne(ts))
                    {
                        this.action(this.parameter);
                    }
                }
                finally
                {
                    lock (mutex)
                    {
                        using (thisReset)
                        {
                            resets.Remove(thisReset);
                        }
                    }
                }
            });
        }

        public void Dispose()
        {
            lock (mutex)
            {
                while (resets.Count > 0)
                {
                    var reset = resets.First();
                    resets.Remove(reset);
                    reset.Set();
                    reset.Dispose();
                }
            }
        }
    }
}
