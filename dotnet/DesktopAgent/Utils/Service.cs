using System.ServiceProcess;

namespace Devolutions.Agent.Desktop
{
    internal partial class Utils
    {
        public static bool IsServiceRunning(string serviceName)
        {
            using (ServiceController sc = new ServiceController(serviceName))
            {
                try
                {
                    return sc.Status == ServiceControllerStatus.Running;
                }
                catch
                {
                    return false;
                }
            }
        }
    }
}
