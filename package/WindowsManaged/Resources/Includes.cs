using System;

namespace DevolutionsGateway.Resources
{
    internal static class Includes
    {
        internal static string VENDOR_NAME = "Devolutions";

        internal static string PRODUCT_NAME = "Devolutions Gateway";

        internal static string SHORT_NAME = "Gateway";

        internal static string SERVICE_NAME = "DevolutionsGateway";

        internal static string SERVICE_DISPLAY_NAME = "Devolutions Gateway Service";

        internal static string SERVICE_DESCRIPTION = "Devolutions Gateway Service";

        internal static string EXECUTABLE_NAME = "DevolutionsGateway.exe";

        internal static Guid UPGRADE_CODE = new("db3903d6-c451-4393-bd80-eb9f45b90214");

        internal static string INFO_URL = "https://server.devolutions.net";

        /// <summary>
        /// SDDL string representing desired %programdata%\devolutions\gateway ACL
        /// Easiest way to generate an SDDL is to configure the required access, and then query the path with PowerShell: `Get-Acl | Format-List`
        /// SYSTEM/BuiltInAdministrators = Full Control, LocalService = Read / Write / Execute, BuiltInUsers - Read/Execute
        /// </summary>
        internal static string PROGRAM_DATA_SDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;0x1201bf;;;LS)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
    }
}
