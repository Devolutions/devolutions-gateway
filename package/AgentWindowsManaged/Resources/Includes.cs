using System;
namespace DevolutionsAgent.Resources
{
    internal static class Includes
    {
        internal static string VENDOR_NAME = "Devolutions";

        internal static string PRODUCT_NAME = "Devolutions Agent";

        internal static string SHORT_NAME = "Agent";

        internal static string SERVICE_NAME = "DevolutionsAgent";

        internal static string SERVICE_DISPLAY_NAME = "Devolutions Agent Service";

        internal static string SERVICE_DESCRIPTION = "Devolutions Agent Service";

        internal static string EXECUTABLE_NAME = "DevolutionsAgent.exe";

        internal static string EMAIL_SUPPORT = "support@devolutions.net";

        internal static string FORUM_SUPPORT = "forum.devolutions.net";

        internal static Guid UPGRADE_CODE = new("82318D3C-811F-4D5D-9A82-B7C31B076755");

        internal static string INFO_URL = "https://server.devolutions.net";

        /// <summary>
        /// SDDL string representing desired %programdata%\devolutions\agent ACL
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
