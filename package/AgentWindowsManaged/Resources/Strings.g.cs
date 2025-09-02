using WixSharp;

namespace DevolutionsAgent.Resources
{
	public static class Strings
	{
		public static string I18n(this MsiRuntime runtime, string res)
		{
			return $"[{res}]".LocalizeWith(runtime.Localize);
		}
		/// <summary>
		/// 1033
		/// </summary>
		public const string Language = "Language";		
		/// <summary>
		/// Devolutions
		/// </summary>
		public const string VendorName = "VendorName";		
		/// <summary>
		/// Devolutions Inc.
		/// </summary>
		public const string VendorFullName = "VendorFullName";		
		/// <summary>
		/// System-wide service for extending Devolutions Gateway functionality.
		/// </summary>
		public const string ProductDescription = "ProductDescription";		
		/// <summary>
		/// Devolutions Agent
		/// </summary>
		public const string FeatureAgentName = "FeatureAgentName";		
		/// <summary>
		/// Installs the Devolutions Agent service
		/// </summary>
		public const string FeatureAgentDescription = "FeatureAgentDescription";		
		/// <summary>
		/// Devolutions Gateway Updater
		/// </summary>
		public const string FeatureAgentUpdaterName = "FeatureAgentUpdaterName";		
		/// <summary>
		/// Enables the Devolutions Gateway updater
		/// </summary>
		public const string FeatureAgentUpdaterDescription = "FeatureAgentUpdaterDescription";		
		/// <summary>
		/// Devolutions PEDM
		/// </summary>
		public const string FeaturePedmName = "FeaturePedmName";		
		/// <summary>
		/// Enables PEDM features and installs the shell extension
		/// </summary>
		public const string FeaturePedmDescription = "FeaturePedmDescription";		
		/// <summary>
		/// RDP Extension
		/// </summary>
		public const string FeatureSessionName = "FeatureSessionName";		
		/// <summary>
		/// Installs the RDP Extension
		/// </summary>
		public const string FeatureSessionDescription = "FeatureSessionDescription";		
		/// <summary>
		/// There is a problem with the entered data. Please correct the issue and try again.
		/// </summary>
		public const string ThereIsAProblemWithTheEnteredData = "ThereIsAProblemWithTheEnteredData";		
		/// <summary>
		/// This product requires at least Windows 8 / Windows Server 2012 R2
		/// </summary>
		public const string OS2Old = "OS2Old";		
		/// <summary>
		/// A newer version of this product is already installed.
		/// </summary>
		public const string NewerInstalled = "NewerInstalled";		
		/// <summary>
		/// You need to install the 64-bit version of this product on 64-bit Windows.
		/// </summary>
		public const string x64VersionRequired = "x64VersionRequired";		
		/// <summary>
		/// You need to install the 32-bit version of this product on 32-bit Windows.
		/// </summary>
		public const string x86VersionRequired = "x86VersionRequired";		
		/// <summary>
		/// The product requires Microsoft .NET Framework 4.8. Would you like to download it now?
		/// </summary>
		public const string Dotnet48IsRequired = "Dotnet48IsRequired";		
		/// <summary>
		/// View
		/// </summary>
		public const string ViewButton = "ViewButton";		
		/// <summary>
		/// Search
		/// </summary>
		public const string SearchButton = "SearchButton";		
		/// <summary>
		/// View Log
		/// </summary>
		public const string ViewLogButton = "ViewLogButton";		
		/// <summary>
		/// Install Location
		/// </summary>
		public const string Group_InstallLocation = "Group_InstallLocation";		
		/// <summary>
		/// Directory
		/// </summary>
		public const string Property_Directory = "Property_Directory";		
		/// <summary>
		/// Please wait for UAC prompt to appear.If it appears minimized then active it from the taskbar.
		/// </summary>
		public const string UACPromptLabel = "UACPromptLabel";		
		/// <summary>
		/// Experimental
		/// </summary>
		public const string ExperimentalLabel = "ExperimentalLabel";		
		/// <summary>
		/// All Files
		/// </summary>
		public const string Filter_AllFiles = "Filter_AllFiles";		
		/// <summary>
		/// [ProductName] Setup
		/// </summary>
		public const string AgentDlg_Title = "AgentDlg_Title";		
		/// <summary>
		/// Change destination folder
		/// </summary>
		public const string BrowseDlgTitle = "BrowseDlgTitle";		
		/// <summary>
		/// Browse to the destination folder
		/// </summary>
		public const string BrowseDlgDescription = "BrowseDlgDescription";		
		/// <summary>
		/// Destination Folder
		/// </summary>
		public const string InstallDirDlgTitle = "InstallDirDlgTitle";		
		/// <summary>
		/// Click Next to install to the default folder or click Change to choose another.
		/// </summary>
		public const string InstallDirDlgDescription = "InstallDirDlgDescription";		
		/// <summary>
		/// Installing [ProductName]
		/// </summary>
		public const string ProgressDlgTitleInstalling = "ProgressDlgTitleInstalling";		
		/// <summary>
		/// Changing [ProductName]
		/// </summary>
		public const string ProgressDlgTitleChanging = "ProgressDlgTitleChanging";		
		/// <summary>
		/// Repairing [ProductName]
		/// </summary>
		public const string ProgressDlgTitleRepairing = "ProgressDlgTitleRepairing";		
		/// <summary>
		/// Removing [ProductName]
		/// </summary>
		public const string ProgressDlgTitleRemoving = "ProgressDlgTitleRemoving";		
		/// <summary>
		/// Updating [ProductName]
		/// </summary>
		public const string ProgressDlgTitleUpdating = "ProgressDlgTitleUpdating";		
		/// <summary>
		/// Ready to install [ProductName]
		/// </summary>
		public const string VerifyReadyDlgInstallTitle = "VerifyReadyDlgInstallTitle";		
		/// <summary>
		/// Ready to change [ProductName]
		/// </summary>
		public const string VerifyReadyDlgChangeTitle = "VerifyReadyDlgChangeTitle";		
		/// <summary>
		/// Ready to repair [ProductName]
		/// </summary>
		public const string VerifyReadyDlgRepairTitle = "VerifyReadyDlgRepairTitle";		
		/// <summary>
		/// Ready to remove [ProductName]
		/// </summary>
		public const string VerifyReadyDlgRemoveTitle = "VerifyReadyDlgRemoveTitle";		
		/// <summary>
		/// Ready to update [ProductName]
		/// </summary>
		public const string VerifyReadyDlgUpdateTitle = "VerifyReadyDlgUpdateTitle";		
		/// <summary>
		/// Welcome to the [ProductName] 20[ProductVersion] Setup Wizard
		/// </summary>
		public const string WelcomeDlgTitle = "WelcomeDlgTitle";		
	}
}
