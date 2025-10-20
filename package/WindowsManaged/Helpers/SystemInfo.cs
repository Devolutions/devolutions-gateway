using System;
using System.Runtime.InteropServices;

namespace DevolutionsGateway.Helpers
{
    internal static class SystemInfo
    {
        private const int PRODUCT_DATACENTER_SERVER_CORE = 0x0000000C;

        private const int PRODUCT_ENTERPRISE_SERVER_CORE = 0x0000000E;

        private const int PRODUCT_STANDARD_SERVER_CORE = 0x0000000D;

        private static bool? isServerCore;

        internal static bool IsServerCore
        {
            get
            {
                if (isServerCore.HasValue)
                {
                    return isServerCore.Value;
                }

                if (GetProductInfo(
                        Environment.OSVersion.Version.Major,
                        Environment.OSVersion.Version.Minor,
                        0,
                        0,
                        out int productType))
                {
                    isServerCore = productType == PRODUCT_DATACENTER_SERVER_CORE ||
                           productType == PRODUCT_ENTERPRISE_SERVER_CORE ||
                           productType == PRODUCT_STANDARD_SERVER_CORE;
                }
                else
                {
                    isServerCore = false;
                }

                return isServerCore.Value;
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetProductInfo(
            int dwOSMajorVersion,
            int dwOSMinorVersion,
            int dwSpMajorVersion,
            int dwSpMinorVersion,
            out int pdwReturnedProductType
        );
    }
}
