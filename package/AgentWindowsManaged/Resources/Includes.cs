using System;
using WixSharp;
namespace DevolutionsAgent.Resources
{
    internal static class Includes
    {
        internal static readonly string VENDOR_NAME = "Devolutions";

        internal static readonly string PRODUCT_NAME = "Devolutions Agent";

        internal static readonly string SHORT_NAME = "Agent";

        internal static readonly string SERVICE_NAME = "DevolutionsAgent";

        internal static readonly string SERVICE_DISPLAY_NAME = "Devolutions Agent Service";

        internal static readonly string SERVICE_DESCRIPTION = "Devolutions Agent Service";

        internal static readonly string EXECUTABLE_NAME = "DevolutionsAgent.exe";

        internal static readonly string POLICY_CONSENT_EXECUTABLE_NAME =
            DevolutionsAgentPolicyConsent.PolicyConsentContract.ExecutableName;

        internal static readonly string POLICY_CONSENT_PRODUCT_NAME =
            DevolutionsAgentPolicyConsent.PolicyConsentContract.ProductName;

        internal static readonly string POLICY_CONSENT_PROTOCOL_VERSION =
            DevolutionsAgentPolicyConsent.PolicyConsentContract.ProtocolVersion;

        internal static readonly string POLICY_CONSENT_CURRENT_UI_SIGNER_SPKI_SHA256 =
            DevolutionsAgentPolicyConsent.PolicyConsentContract.CurrentUiSignerSpkiSha256;

        internal static readonly string POLICY_CONSENT_TRANSITION_UI_SIGNER_SPKI_SHA256 =
            DevolutionsAgentPolicyConsent.PolicyConsentContract.TransitionUiSignerSpkiSha256;

        internal static readonly string DESKTOP_DIRECTORY_NAME = "desktop";

        internal static readonly string DESKTOP_EXECUTABLE_NAME = "DevolutionsDesktopAgent.exe";

        internal static readonly string EMAIL_SUPPORT = "support@devolutions.net";

        internal static readonly string FORUM_SUPPORT = "forum.devolutions.net";

        internal static readonly string SHELL_EXT_BINARY_NAME = "DevolutionsPedmShellExt.dll";

        internal static readonly Guid SHELL_EXT_CSLID = new("0BA604FD-4A5A-4ABB-92B1-09AC5C3BF356");

        internal static readonly Guid UPGRADE_CODE = new("82318d3c-811f-4d5d-9a82-b7c31b076755");

        internal static readonly string INFO_URL = "https://server.devolutions.net";

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
        ///    BUILTIN\Administrators Allow  FullControl
        ///    BUILTIN\Users Allow ReadAndExecute, Synchronize
        /// </remarks>
        internal static readonly string PROGRAM_DATA_SDDL = "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;0x1201bf;;;LS)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

        /// <summary>
        /// SDDL string representing desired %programdata%\devolutions\agent\pedm ACL
        /// Easiest way to generate an SDDL is to configure the required access, and then query the path with PowerShell: `Get-Acl | Format-List`
        /// </summary>
        /// <remarks>
        /// Owner  : NT AUTHORITY\SYSTEM
        /// Group  : NT AUTHORITY\SYSTEM
        /// Access :
        ///    NT AUTHORITY\SYSTEM Allow  FullControl
        /// </remarks>
        internal static readonly string PROGRAM_DATA_PEDM_SDDL = "O:SYG:SYD:(A;OICI;FA;;;SY)";

        /// <summary>
        /// Protected ACL for the dedicated package-broker policy directory.
        /// </summary>
        /// <remarks>
        /// This directory must not inherit the LOCAL SERVICE and Users grants required by
        /// unrelated Agent features under %ProgramData%\Devolutions\Agent.
        /// </remarks>
        internal static readonly string PROGRAM_DATA_PACKAGE_BROKER_SDDL =
            "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

        internal static readonly string PROGRAM_DATA_PACKAGE_BROKER_FILE_SDDL =
            "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";
    }
}
