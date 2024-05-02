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

        internal static string EMAIL_SUPPORT = "support@devolutions.net";

        internal static string FORUM_SUPPORT = "forum.devolutions.net";

        internal static Guid UPGRADE_CODE = new("db3903d6-c451-4393-bd80-eb9f45b90214");

        internal static string INFO_URL = "https://server.devolutions.net";

        /// <summary>
        /// SDDL string representing desired %programdata%\devolutions\gateway ACL
        /// Easiest way to generate an SDDL is to configure the required access, and then query the path with PowerShell: `Get-Acl | Format-List`
        /// </summary>
        /// <remarks>
        /// Owner  : NT AUTHORITY\SYSTEM
        /// Group  : NT AUTHORITY\SYSTEM
        /// Access :
        ///    NT AUTHORITY\SYSTEM Allow  FullControl
        ///    NT AUTHORITY\LOCAL SERVICE Allow Write, ReadAndExecute, Synchronize
        ///    NT AUTHORITY\NETWORK SERVICE Allow Modify, Synchronize
        ///    BUILTIN\Administrators Allow  FullControl
        ///    BUILTIN\Users Allow ReadAndExecute, Synchronize
        /// </remarks>
        internal static string PROGRAM_DATA_SDDL = "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;0x1201bf;;;LS)(A;OICI;0x1301bf;;;NS)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

        /// <remarks>
        /// Owner  : NT AUTHORITY\SYSTEM
        /// Group  : NT AUTHORITY\SYSTEM
        /// Access :
        ///    NT AUTHORITY\SYSTEM Allow  FullControl
        ///    NT AUTHORITY\LOCAL SERVICE Allow Write, ReadAndExecute, Synchronize
        ///    NT AUTHORITY\NETWORK SERVICE Allow Write, ReadAndExecute, Synchronize
        ///    BUILTIN\Administrators Allow  FullControl
        /// </remarks>
        internal static string USERS_FILE_SDDL = "O:SYG:SYD:PAI(A;;FA;;;SY)(A;;0x1201bf;;;LS)(A;;0x1201bf;;;NS)(A;;FA;;;BA)";
    }
}
