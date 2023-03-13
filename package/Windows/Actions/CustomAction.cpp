#include "stdafx.h"
#include "shlwapi.h"

enum Errors
{
	NoError = 0,
	CommandExecPublicKeyFailure = 29989,
	CommandExecCertificateFailure = 29990,
	CommandExecListenersFailure = 29991,
	CommandExecAccessUriFailure = 29992,
	CommandExecFailure = 29993,
	ServiceQueryFailure = 29994,
	InvalidCertificate = 29995,
	FileNotFound = 29996,
	InvalidFilename = 29997,
	InvalidScheme = 29998,
	InvalidPort = 29999,
	InvalidHost = 30000
};

constexpr auto DG_SERVICE_NAME = L"DevolutionsGateway";

DWORD __stdcall Win32FromHResult(HRESULT hr)
{
	if ((hr & 0xFFFF0000) == MAKE_HRESULT(SEVERITY_ERROR, FACILITY_WIN32, 0))
	{
		return HRESULT_CODE(hr);
	}

	if (hr == S_OK)
	{
		return ERROR_SUCCESS;
	}

	// Not a Win32 HRESULT so return a generic error code.
	return ERROR_CAN_NOT_COMPLETE;
}

BOOL FormatWin32ErrorMessage(DWORD dwErrorCode, LPWSTR pBuffer, DWORD cchBufferLength)
{
	if (cchBufferLength == 0)
	{
		return FALSE;
	}

	DWORD cchMsg = FormatMessageW(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 
		nullptr, 
		dwErrorCode, 
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
		pBuffer, 
		cchBufferLength, 
		nullptr);

	return (cchMsg > 0);
}

/// <summary>
/// Write a message to the installer log
/// </summary>
void __stdcall Log(MSIHANDLE hInstall, LPCWSTR message)
{
	PMSIHANDLE hRecord = MsiCreateRecord(1);
	MsiRecordSetStringW(hRecord, 0, L"DevolutionsGateway.Installer.Actions: [1]");
	MsiRecordSetStringW(hRecord, 1, message);
	MsiProcessMessage(hInstall, INSTALLMESSAGE_INFO, hRecord);
}

/// <summary>
/// Write a message to the installer log including the error code |le|
/// </summary>
void __stdcall LogGLE(MSIHANDLE hInstall, LPCWSTR message, DWORD lastError)
{
	static LPCWSTR format = L"%ls (%lu)";
	WCHAR* formatMessage = nullptr;
	size_t formatMessageLen = 0;

	formatMessageLen = _snwprintf(nullptr, 0, format, message, lastError);
	formatMessage = new WCHAR[formatMessageLen + 1];
	_snwprintf(formatMessage, formatMessageLen, format, message, lastError);
	formatMessage[formatMessageLen] = L'\0';

	Log(hInstall, formatMessage);

	delete[] formatMessage;
}

/// <summary>
/// Write a message to the installer log, including the result of GetLastError
/// </summary>
void __stdcall LogGLE(MSIHANDLE hInstall, LPCWSTR message)
{
	LogGLE(hInstall, message, GetLastError());
}

/// <summary>
/// Looks up the localized error message for |error| from the Error table
/// </summary>
/// <remarks>
/// Note this will not work from within a deferred custom action
/// </remarks>
HRESULT __stdcall GetLocalizedErrorMessage(MSIHANDLE hInstall, int error, LPWSTR* pErrMsg, PDWORD pdwErrMsgLen)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	WCHAR szQuery[255] = { 0 };
	PMSIHANDLE hDatabase;
	PMSIHANDLE hView = NULL;
	PMSIHANDLE hRecord = NULL;
	DWORD dwErrMsgLen = 0;
	LPWSTR errMsg = nullptr;

	swprintf_s(szQuery, _countof(szQuery), L"SELECT `Message` FROM `Error` WHERE `Error` = %d", error);

	hDatabase = MsiGetActiveDatabase(hInstall);
	ExitOnNull(hDatabase, hr, E_OUTOFMEMORY, "MsiGetActiveDatabase");

	hr = MsiDatabaseOpenViewW(hDatabase, szQuery, &hView);
	ExitOnFailure(hr, "MsiDatabaseOpenView");

	er = MsiViewExecute(hView, hRecord);
	ExitOnWin32Error(er, hr, "MsiViewExecute");

	er = MsiViewFetch(hView, &hRecord);
	ExitOnWin32Error(er, hr, "MsiViewExecute");

	// MsiRecordGetString offsets begin at 1 (obviously written by a VB developer)
	er = MsiRecordGetStringW(hRecord, 1, L"", &dwErrMsgLen);

	if (er == ERROR_MORE_DATA)
	{
		++dwErrMsgLen;

		errMsg = (LPWSTR) calloc(dwErrMsgLen, sizeof(WCHAR));
		ExitOnNull(errMsg, hr, E_OUTOFMEMORY, "calloc");

		er = MsiRecordGetStringW(hRecord, 1, errMsg, &dwErrMsgLen);
		ExitOnWin32Error(er, hr, "MsiRecordGetString");
	}
	else
	{
		ExitOnWin32Error(er, hr, "MsiRecordGetString");
	}

LExit:
	if (SUCCEEDED(hr))
	{
		*pErrMsg = errMsg;
		*pdwErrMsgLen = dwErrMsgLen;
	}
	else
	{
		free(errMsg);
	}

	return hr;
}

/// <summary>
/// Lookup the localized error message for the code |error| and copy it to the P.ERROR property
/// </summary>
HRESULT __stdcall HandleValidationError(MSIHANDLE hInstall, int error)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	DWORD dwErrorMessageLen = 0;
	LPWSTR errMessage = nullptr;

	// Write the error to the log file
	PMSIHANDLE hLogRecord = MsiCreateRecord(1);
	MsiRecordSetInteger(hLogRecord, 1, error);
	MsiProcessMessage(hInstall, INSTALLMESSAGE_INFO, hLogRecord);
	//

	hr = GetLocalizedErrorMessage(hInstall, error, &errMessage, &dwErrorMessageLen);
	ExitOnFailure(hr, "GetLocalizedErrorMessage");

	er = MsiSetPropertyW(hInstall, L"P.ERROR", errMessage);
	ExitOnWin32Error(er, hr, "MsiSetProperty");

LExit:
	free(errMessage);

	return hr;
}

BOOL __stdcall IsValidPort(LPWSTR port, int* value)
{
	BOOL result = FALSE;

	for (int i = 0; i < lstrlenW(port); i++)
	{
		if (!iswdigit(port[i]))
		{
			goto LExit;
		}
	}

	int portValue = _wtoi(port);

	if (portValue < 1 || portValue > 65535)
	{
		goto LExit;
	}

	if (value != nullptr)
	{
		*value = portValue;
	}

	result = TRUE;

LExit:
	return result;
}

BOOL __stdcall IsValidPort(LPWSTR port)
{
	return IsValidPort(port, nullptr);
}

BOOL __stdcall IsValidOption(LPWSTR option, const WCHAR** validOptions, int len)
{
	BOOL result = FALSE;

	for (int i = 0; i < len; i++)
	{
		if (StrCmpIW(option, validOptions[i]) == 0)
		{
			result = TRUE;
			break;
		}
	}

	return result;
}

UINT __stdcall FormatHttpUrl(LPCWSTR scheme, int port, WCHAR* buffer, size_t bufferLen)
{
	static LPCWSTR urlFormat = L"%ls://*%ls";
	static LPCWSTR portFormat = L":%d";
	int suffixLen = 0;
	WCHAR* suffix = nullptr;

	if ((StrCmpIW(scheme, L"http") == 0 && port != 80) ||
	    (StrCmpIW(scheme, L"https") == 0 && port != 443))
	{
		suffixLen = _snwprintf(suffix, 0, portFormat, port);
		suffix = new WCHAR[suffixLen + 1];
		_snwprintf(suffix, suffixLen, portFormat, port);
		suffix[suffixLen] = L'\0';
	}

	return _snwprintf(buffer, bufferLen, urlFormat, scheme, suffix ? suffix : L"");
}

HRESULT __stdcall GetPowerShellVersion(USHORT* pMajor, USHORT* pMinor, USHORT* pRevision, USHORT* pPatch)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	HKEY hKey = nullptr;
	DWORD dwType;
	DWORD dwInstall = 0;
	DWORD cbData;
	USHORT major, minor, revision, patch;

	char szVersion[512] = { 0 };

	er = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\PowerShell\\3", 0, KEY_READ, &hKey);
	ExitOnWin32Error(er, hr, "RegOpenKeyEx");

	cbData = sizeof(DWORD);

	er = RegQueryValueExW(hKey, L"Install", nullptr, &dwType, (LPBYTE) &dwInstall, &cbData);
	ExitOnWin32Error(er, hr, "RegQueryValueEx");

	if (dwInstall != 1)
	{
		hr = REGDB_E_INVALIDVALUE;
		ExitOnFailure(hr, "RegQueryValueEx");
	}

	RegCloseKey(hKey);
	hKey = nullptr;

	er = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\PowerShell\\3\\PowerShellEngine", 0, KEY_READ, &hKey);
	ExitOnWin32Error(er, hr, "RegOpenKeyEx");

	cbData = sizeof(szVersion);

	er = RegQueryValueExA(hKey, "PowerShellVersion", nullptr, &dwType, (LPBYTE) szVersion, &cbData);
	ExitOnWin32Error(er, hr, "RegQueryValueEx");

	if (sscanf(szVersion, "%hu.%hu.%hu.%hu", &major, &minor, &revision, &patch) != 4)
	{
		hr = REGDB_E_INVALIDVALUE;
	}
	else
	{
		if (pMajor)
			*pMajor = major;
		
		if (pMinor)
			*pMinor = minor;

		if (pRevision)
			*pRevision = revision;

		if (pPatch)
			*pPatch = patch;
	}

LExit:
	if (hKey)
		RegCloseKey(hKey);

	return hr;
}

UINT __stdcall CheckPowerShellVersion(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	USHORT major, minor, rev, patch;

	hr = WcaInitialize(hInstall, "CheckPowerShellVersion");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = WcaSetIntProperty(L"P.HASPWSH", 1);
	ExitOnFailure(hr, "WcaSetIntProperty");

	hr = GetPowerShellVersion(&major, &minor, &rev, &patch);
	ExitOnFailure(hr, "GetPowerShellVersion");

	if (major >= 5 && minor >= 1)
	{
		hr = WcaSetIntProperty(L"P.HASPWSH", 0);
		ExitOnFailure(hr, "WcaSetIntProperty");
	}

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

BOOL __stdcall FileExists(LPCWSTR filePath)
{
	WIN32_FIND_DATA fdExistingFileData = { 0 };
	HANDLE hFile = INVALID_HANDLE_VALUE;

	hFile = FindFirstFileW(filePath, &fdExistingFileData);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	FindClose(hFile);

	return TRUE;
}

/// <summary>
/// Creates a temporary file with inheritable write access. Returns |nullptr| on failure,
/// otherwise a |HANDLE| that must be closed
/// </summary>
HANDLE __stdcall CreateSharedTempFile(LPWSTR* pFilePath)
{
	HRESULT hr = S_OK;
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
	WCHAR szTempFileName[MAX_PATH];
	WCHAR lpTempPathBuffer[MAX_PATH];
	DWORD dwRetVal = 0;
	HANDLE hTempFile = nullptr;
	int filePathLen = 0;

	dwRetVal = GetTempPathW(MAX_PATH, lpTempPathBuffer);

	if (dwRetVal < 1 || dwRetVal > MAX_PATH)
	{
		ExitWithLastError(hr, "GetTempPath");
	}

	if (GetTempFileNameW(lpTempPathBuffer, L"DGW", 0, szTempFileName) == 0)
	{
		ExitWithLastError(hr, "GetTempFileName");
	}

	hTempFile = CreateFileW(szTempFileName, GENERIC_WRITE, FILE_SHARE_WRITE, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hTempFile == INVALID_HANDLE_VALUE)
	{
		hTempFile = nullptr;
		ExitWithLastError(hr, "CreateFile");
	}

	filePathLen = lstrlenW(szTempFileName);
	*pFilePath = (LPWSTR) calloc((size_t) filePathLen + 1, sizeof(WCHAR));
	ExitOnNull(*pFilePath, hr, E_OUTOFMEMORY, "calloc");

	CopyMemory(*pFilePath, szTempFileName, filePathLen * sizeof(WCHAR));

LExit:
	if (FAILED(hr))
	{
		ReleaseHandle(hTempFile);
		free(*pFilePath);
		*pFilePath = nullptr;
	}

	return hTempFile;
}

HRESULT __stdcall ExecuteCommand(MSIHANDLE hInstall, LPCWSTR command, LPDWORD dwExitCode, LPWSTR* pOutputPath)
{
	HRESULT hr = S_OK;
	int lpCommandLen = 0;
	WCHAR* lpCommand = nullptr;
	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
	DWORD exitCode = 1;
	HANDLE hTempFile = nullptr;
	
	// CreateProcessW can modify the contents of the lpCommand parameter
	lpCommandLen = lstrlenW(command);
	lpCommand = (LPWSTR) calloc((size_t)lpCommandLen, sizeof(WCHAR));
	ExitOnNull(lpCommand, hr, E_OUTOFMEMORY, "calloc");
	CopyMemory(lpCommand, command, lpCommandLen * sizeof(WCHAR));

	si.cb = sizeof(STARTUPINFOW);

	// Create a temp file and redirect output
	hTempFile = CreateSharedTempFile(pOutputPath);

	if (hTempFile != nullptr)
	{
		si.dwFlags = STARTF_USESTDHANDLES;
		si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
		si.hStdOutput = hTempFile;
		si.hStdError = hTempFile;
	}

	if (!CreateProcessW(nullptr, lpCommand, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
	{
		ExitWithLastError(hr, "CreateProcess");
	}

	// Give the process reasonable time to finish, don't hang the installer
	if (WaitForSingleObject(pi.hProcess, 30 * 1000) == WAIT_TIMEOUT)
	{
		Log(hInstall, L"Timeout waiting for subprocess");

		if (!TerminateProcess(pi.hProcess, exitCode))
		{
			ExitWithLastError(hr, "TerminateProcess failed");
		}
	}

	if (!GetExitCodeProcess(pi.hProcess, &exitCode))
	{
		ExitWithLastError(hr, "GetExitCodeProcess failed");
	}

	if (exitCode != 0)
	{
		Log(hInstall, L"Subprocess returned non-zero exit code.");
	}

LExit:
	if (hr == S_OK)
	{
		*dwExitCode = exitCode;
	}

	free(lpCommand);
	lpCommand = nullptr;

	ReleaseHandle(hTempFile);
	ReleaseHandle(pi.hProcess);
	ReleaseHandle(pi.hThread);

	return hr;
}

HRESULT __stdcall BrowseForFile(MSIHANDLE hInstall, LPCWSTR propertyName, LPCWSTR fileFilter)
{
	HRESULT hr = S_OK;
	HANDLE hExistingFile;
	WIN32_FIND_DATA fdExistingFileData = { 0 };
	OPENFILENAMEW ofn = { 0 };
	LPWSTR szSourceFileName = nullptr;
	WCHAR szFoundFileName[MAX_PATH] = { 0 };

	hr = WcaGetProperty(propertyName, &szSourceFileName);
	ExitOnFailure(hr, "WcaGetProperty");

	hExistingFile = FindFirstFileW(szSourceFileName, &fdExistingFileData);

	if (hExistingFile != INVALID_HANDLE_VALUE)
	{
		if (StringCchCopyW(szFoundFileName, sizeof(szFoundFileName), szSourceFileName) != S_OK)
		{
			Log(hInstall, L"StringCchCopyW possible truncation");
		}

		FindClose(hExistingFile);
	}

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = GetActiveWindow(); // can also use NULL, although the dialog won't be modal in that case
	ofn.lpstrFile = szFoundFileName;
	ofn.nMaxFile = sizeof(szFoundFileName);
	ofn.lpstrInitialDir = nullptr;
	ofn.lpstrFilter = fileFilter;
	ofn.nFilterIndex = 1;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (GetOpenFileNameW(&ofn))
	{
		hr = WcaSetProperty(propertyName, ofn.lpstrFile);
		ExitOnFailure(hr, "WcaSetProperty");
	}

LExit:
	ReleaseStr(szSourceFileName);

	return hr;
}

UINT __stdcall BrowseForCertificate(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	LPCWSTR propertyName = L"P.CERT_FILE";
	LPWSTR szSourceFileName = nullptr;
	static const WCHAR* PFX_EXTS[] = { (L"pfx"), (L"p12") };

	hr = WcaInitialize(hInstall, "BrowseForCertificate");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = BrowseForFile(
		hInstall, 
		propertyName, 
		L"PFX Files (*.pfx, *.p12)\0*.pfx;*.p12\0Certificate Files (*.pem, *.crt, *.cer)\0*.pem;*.crt;*.cer\0All Files\0*.*\0\0"
	);
	ExitOnFailure(hr, "BrowseForFile");

	hr = WcaGetProperty(propertyName, &szSourceFileName);
	ExitOnFailure(hr, "WcaGetProperty");

	// We expect the file to have an extension, because of the filter
	WCHAR* pExt = PathFindExtensionW(szSourceFileName);
	pExt++;

	hr = WcaSetIntProperty(L"P.CERT_NEED_PASS", 1);
	ExitOnFailure(hr, "WcaSetIntProperty");

	if (IsValidOption(pExt, PFX_EXTS, ARRAYSIZE(PFX_EXTS)))
	{
		// Tell the .msi we need a password
		hr = WcaSetIntProperty(L"P.CERT_NEED_PASS", 0);
		ExitOnFailure(hr, "WcaSetIntProperty");
	}

LExit:
	ReleaseStr(szSourceFileName);

	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall BrowseForPrivateKey(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;

	hr = WcaInitialize(hInstall, "BrowseForPrivateKey");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = BrowseForFile(hInstall, L"P.CERT_PK_FILE", L"Private Key Files (*.key)\0*.key\0All Files\0*.*\0\0");
	ExitOnFailure(hr, "BrowseForFile");

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall BrowseForPublicKey(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;

	hr = WcaInitialize(hInstall, "BrowseForPublicKey");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = BrowseForFile(
		hInstall, 
		L"P.PUBLIC_KEY_FILE", 
		L"Public Key Files (*.pem)\0*.pem\0Private Key Files (*.key)\0*.key\0All Files\0*.*\0\0"
	);
	ExitOnFailure(hr, "BrowseForFile");

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

HRESULT __stdcall OpenServiceManagerX(MSIHANDLE hInstall, DWORD dwDesiredAccess, SC_HANDLE* lpHandle)
{
	HRESULT hr = S_OK;
	SC_HANDLE hSCM = nullptr;

	hSCM = OpenSCManagerW(nullptr, nullptr, dwDesiredAccess);
	ExitOnNullWithLastError(hSCM, hr, "OpenSCManager");

LExit:
	*lpHandle = hSCM;

	return hr;
}

HRESULT __stdcall OpenServiceX(MSIHANDLE hInstall, SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess, SC_HANDLE* lpHandle)
{
	HRESULT hr = S_OK;
	SC_HANDLE hService = nullptr;

	hService = OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);
	ExitOnNullWithLastError(hService, hr, "OpenService");

LExit:
	*lpHandle = hService;

	return hr;
}

UINT __stdcall SetGatewayStartupType(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	int serviceStart = SERVICE_DEMAND_START;
	SC_HANDLE hSCM = nullptr;
	SC_HANDLE hService = nullptr;
	DWORD dwValBuf = 0;
	LPWSTR szValBuf = nullptr;

	hr = WcaInitialize(hInstall, "SetGatewayStartupType");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = WcaGetProperty(L"CustomActionData", &szValBuf);
	ExitOnFailure(hr, "WcaGetProperty");

	serviceStart = _wtoi(szValBuf);

	ReleaseStr(szValBuf);

	hr = OpenServiceManagerX(hInstall, SC_MANAGER_ALL_ACCESS, &hSCM);
	ExitOnFailure(hr, "OpenServiceManager");

	hr = OpenServiceX(hInstall, hSCM, DG_SERVICE_NAME, SERVICE_CHANGE_CONFIG, &hService);
	ExitOnFailure(hr, "OpenService");

	if (!ChangeServiceConfigW(hService, SERVICE_NO_CHANGE, serviceStart, SERVICE_NO_CHANGE,
		nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr))
	{
		ExitWithLastError(hr, "ChangeServiceConfig");
	}

LExit:
	if (hService != nullptr)
	{
		CloseServiceHandle(hService);
	}

	if (hSCM != nullptr)
	{
		CloseServiceHandle(hSCM);
	}

	ReleaseStr(szValBuf);

	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

HRESULT __stdcall GetGatewayStartupType(MSIHANDLE hInstall, DWORD* pStartupType)
{
	HRESULT hr = S_OK;
	SC_HANDLE hSCM = nullptr;
	SC_HANDLE hService = nullptr;
	LPQUERY_SERVICE_CONFIG lpsc = nullptr;
	DWORD dwBytesNeeded;
	DWORD cbBufSize = 0;
	DWORD dwError;

	hr = OpenServiceManagerX(hInstall, SC_MANAGER_CONNECT, &hSCM);
	ExitOnFailure(hr, "OpenServiceManager");

	hr = OpenServiceX(hInstall, hSCM, DG_SERVICE_NAME, SERVICE_QUERY_CONFIG, &hService);
	ExitOnFailure(hr, "OpenService");

	if (!QueryServiceConfigW(hService, nullptr, 0, &dwBytesNeeded))
	{
		dwError = GetLastError();

		if (dwError == ERROR_INSUFFICIENT_BUFFER)
		{
			cbBufSize = dwBytesNeeded;
			lpsc = (LPQUERY_SERVICE_CONFIG) LocalAlloc(LMEM_FIXED, cbBufSize);
			ExitOnNull(lpsc, hr, E_OUTOFMEMORY, "LocalAlloc");
		}
		else
		{
			ExitOnLastError(hr, "QueryServiceConfig");
		}
	}

	if (!QueryServiceConfigW(hService, lpsc, cbBufSize, &dwBytesNeeded))
	{
		ExitOnLastError(hr, "QueryServiceConfig");
	}

	ExitOnNull(lpsc, hr, E_OUTOFMEMORY, "QueryServiceConfig");

	*pStartupType = lpsc->dwStartType;

LExit:
	if (lpsc != nullptr)
	{
		LocalFree(lpsc);
	}

	if (hService != nullptr)
	{
		CloseServiceHandle(hService);
	}

	if (hSCM != nullptr)
	{
		CloseServiceHandle(hSCM);
	}

	return hr;
}

UINT __stdcall QueryGatewayStartupType(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	DWORD dwStartType = 0;

	hr = WcaInitialize(hInstall, "QueryGatewayStartupType");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	Log(hInstall, L"Looking for existing Devolutions Gateway service");

	hr = GetGatewayStartupType(hInstall, &dwStartType);
	ExitOnFailure(hr, "GetGatewayStartupType");

	hr = WcaSetIntProperty(L"P.SERVICE_START", dwStartType == SERVICE_DISABLED ? SERVICE_DEMAND_START : dwStartType);
	ExitOnFailure(hr, "WcaSetIntProperty");

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall StartGatewayIfNeeded(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	DWORD dwStartType = 0;
	SC_HANDLE hSCM = nullptr;
	SC_HANDLE hService = nullptr;

	hr = WcaInitialize(hInstall, "StartGatewayIfNeeded");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = GetGatewayStartupType(hInstall, &dwStartType);

	if (SUCCEEDED(hr) && dwStartType == SERVICE_AUTO_START)
	{
		if (dwStartType == SERVICE_AUTO_START)
		{
			Log(hInstall, L"Trying to start the Devolutions Gateway service");

			hr = OpenServiceManagerX(hInstall, SC_MANAGER_CONNECT, &hSCM);
			ExitOnFailure(hr, "OpenServiceManager");

			hr = OpenServiceX(hInstall, hSCM, DG_SERVICE_NAME, SERVICE_START, &hService);
			ExitOnFailure(hr, "OpenService");

			if (StartServiceW(hService, 0, nullptr))
			{
				Log(hInstall, L"Successfully asked the Devolutions Gateway service to start");
			}
			else
			{
				DWORD dwError = GetLastError();

				if (dwError != ERROR_SERVICE_ALREADY_RUNNING)
				{
					ExitOnLastError(hr, "StartService");
				}

				Log(hInstall, L"Devolutions Gateway service is already running");
			}
		}
		else
		{
			Log(hInstall, L"Devolutions Gateway service is not SERVICE_AUTO_START, nothing to do");
		}
	}

LExit:
	if (hService != nullptr)
	{
		CloseServiceHandle(hService);
	}

	if (hSCM != nullptr)
	{
		CloseServiceHandle(hSCM);
	}

	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall ValidateAccessUri(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	LPWSTR szAccessUriScheme = nullptr;
	LPWSTR szAccessUriHost = nullptr;
	LPWSTR szAccessUriPort = nullptr;
	static LPCWSTR uriFormat = L"%ls://%ls:%ls";
	int uriLen = 0;
	WCHAR* uri = nullptr;
	DWORD dwHostLen = INTERNET_MAX_HOST_NAME_LENGTH;
	WCHAR wszHost[INTERNET_MAX_HOST_NAME_LENGTH] = { 0 };
	static LPCWSTR psCommandFormat = L"Set-DGatewayHostname %ls";
	int psCommandLen = 0;
	WCHAR* psCommand = nullptr;

	hr = WcaInitialize(hInstall, "ValidateAccessUri");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = WcaSetProperty(L"P.ERROR", L"");
	ExitOnFailure(hr, "WcaSetProperty");

	hr = WcaGetProperty(L"P.ACCESSURI_SCHEME", &szAccessUriScheme);
	ExitOnFailure(hr, "WcaGetProperty");

	if (!szAccessUriScheme || lstrlen(szAccessUriScheme) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidScheme);
		goto LExit;
	}

	static const WCHAR* VALID_SCHEMES[] = { (L"http"), (L"https") };

	if (!IsValidOption(szAccessUriScheme, VALID_SCHEMES, ARRAYSIZE(VALID_SCHEMES)))
	{
		HandleValidationError(hInstall, Errors::InvalidScheme);
		goto LExit;
	}

	hr = WcaGetProperty(L"P.ACCESSURI_HOST", &szAccessUriHost);
	ExitOnFailure(hr, "WcaGetProperty");

	if (!szAccessUriHost || lstrlen(szAccessUriHost) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidHost);
		goto LExit;
	}

	hr = WcaGetProperty(L"P.ACCESSURI_PORT", &szAccessUriPort);
	ExitOnFailure(hr, "WcaGetProperty");

	if (!szAccessUriPort || lstrlen(szAccessUriPort) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidPort);
		goto LExit;
	}

	if (!IsValidPort(szAccessUriPort))
	{
		HandleValidationError(hInstall, Errors::InvalidPort);
		goto LExit;
	}

	if (lstrcmpi(szAccessUriScheme, L"http") == 0)
	{
		hr = WcaSetProperty(L"P.HTTPURI_SCHEME", L"http");
		ExitOnFailure(hr, "WcaSetProperty");
	}

	uriLen = _snwprintf(nullptr, 0, uriFormat, szAccessUriScheme, szAccessUriHost, szAccessUriPort);
	uri = new WCHAR[uriLen + 1];
	_snwprintf(uri, uriLen, uriFormat, szAccessUriScheme, szAccessUriHost, szAccessUriPort);
	uri[uriLen] = L'\0';

	hr = UrlGetPartW(uri, wszHost, &dwHostLen, URL_PART_HOSTNAME, 0);

	delete[] uri;

	if (FAILED(hr))
	{
		HandleValidationError(hInstall, Errors::InvalidHost);
		goto LExit;
	}

	psCommandLen = _snwprintf(nullptr, 0, psCommandFormat, wszHost);
	psCommand = new WCHAR[psCommandLen + 1];
	_snwprintf(psCommand, psCommandLen, psCommandFormat, wszHost);
	psCommand[psCommandLen] = L'\0';

	hr = WcaSetProperty(L"P.ACCESSURI_CMD", psCommand);
	delete[] psCommand;
	ExitOnFailure(hr, "WcaSetProperty");

LExit:
	ReleaseStr(szAccessUriScheme);
	ReleaseStr(szAccessUriHost);
	ReleaseStr(szAccessUriPort);

	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall ValidateListeners(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	LPWSTR szHttpUriScheme = nullptr;
	LPWSTR szHttpUriPort = nullptr;
	LPWSTR szTcpUriPort = nullptr;
	LPWSTR szAccessUriScheme = nullptr;
	int httpUriPort = 0;
	int accessUriPort = 0;
	int externalUrlLen = 0;
	WCHAR* externalUrl = nullptr;
	int internalUrlLen = 0;
	WCHAR* internalUrl = nullptr;
	static LPCWSTR psCommandFormat = L"$httpListener = New-DGatewayListener \"%ls\" \"%ls\"; $tcpListener = New-DGatewayListener \"tcp://*:%ls\" \"tcp://*:%ls\"; $listeners = $httpListener, $tcpListener; Set-DGatewayListeners $listeners";
	int psCommandLen = 0;
	WCHAR* psCommand = nullptr;

	hr = WcaInitialize(hInstall, "ValidateListeners");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = WcaSetProperty(L"P.ERROR", L"");
	ExitOnFailure(hr, "WcaSetProperty");

	hr = WcaGetProperty(L"P.HTTPURI_SCHEME", &szHttpUriScheme);
	ExitOnFailure(hr, "WcaGetProperty");

	if (!szHttpUriScheme || lstrlen(szHttpUriScheme) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidScheme);
		goto LExit;
	}

	static const WCHAR* VALID_SCHEMES[] = { (L"http"), (L"https") };

	if (!IsValidOption(szHttpUriScheme, VALID_SCHEMES, ARRAYSIZE(VALID_SCHEMES)))
	{
		HandleValidationError(hInstall, Errors::InvalidScheme);
		goto LExit;
	}

	hr = WcaGetProperty(L"P.HTTPURI_PORT", &szHttpUriPort);
	ExitOnFailure(hr, "WcaGetProperty");

	if (!szHttpUriPort || lstrlen(szHttpUriPort) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidPort);
		goto LExit;
	}

	if (!IsValidPort(szHttpUriPort, &httpUriPort))
	{
		HandleValidationError(hInstall, Errors::InvalidPort);
		goto LExit;
	}

	hr = WcaGetProperty(L"P.TCPURI_PORT", &szTcpUriPort);
	ExitOnFailure(hr, "WcaGetProperty");

	if (!szTcpUriPort || lstrlen(szTcpUriPort) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidPort);
		goto LExit;
	}

	if (!IsValidPort(szTcpUriPort))
	{
		HandleValidationError(hInstall, Errors::InvalidPort);
		goto LExit;
	}

	// Build the internal HTTP listener URL
	internalUrlLen = FormatHttpUrl(szHttpUriScheme, httpUriPort, internalUrl, internalUrlLen);
	internalUrl = new WCHAR[internalUrlLen + 1];
	FormatHttpUrl(szHttpUriScheme, httpUriPort, internalUrl, internalUrlLen + 1);
	internalUrl[internalUrlLen] = L'\0';

	// Build the external HTTP listener URL
	WcaGetProperty(L"P.ACCESSURI_SCHEME", &szAccessUriScheme); /* Known valid, checked in previous step */
	WcaGetIntProperty(L"P.ACCESSURI_PORT", &accessUriPort);    /* Known valid, checked in previous step */

	externalUrlLen = FormatHttpUrl(szAccessUriScheme, accessUriPort, externalUrl, externalUrlLen);
	externalUrl = new WCHAR[externalUrlLen + 1];
	FormatHttpUrl(szAccessUriScheme, accessUriPort, externalUrl, externalUrlLen + 1);
	externalUrl[externalUrlLen] = L'\0';

	// Format the command
	psCommandLen = _snwprintf(nullptr, 0, psCommandFormat, internalUrl, externalUrl, szTcpUriPort, szTcpUriPort);
	psCommand = new WCHAR[psCommandLen + 1];
	_snwprintf(psCommand, psCommandLen, psCommandFormat, internalUrl, externalUrl, szTcpUriPort, szTcpUriPort);
	psCommand[psCommandLen] = L'\0';

	delete[] internalUrl;
	delete[] externalUrl;

	hr = WcaSetProperty(L"P.LISTENER_CMD", psCommand);
	delete[] psCommand;
	ExitOnFailure(hr, "WcaSetProperty");

LExit:
	ReleaseStr(szHttpUriScheme);
	ReleaseStr(szHttpUriPort);
	ReleaseStr(szTcpUriPort);
	ReleaseStr(szAccessUriScheme);

	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall ValidateCertificate(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	LPWSTR szCertFile = nullptr;
	LPWSTR szCertPass = nullptr;
	LPWSTR szPkFile = nullptr;
	int psCommandLen = 0;
	WCHAR* psCommand = nullptr;

	hr = WcaInitialize(hInstall, "ValidateCertificate");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = WcaSetProperty(L"P.ERROR", L"");
	ExitOnFailure(hr, "WcaSetProperty");

	hr = WcaGetProperty(L"P.CERT_FILE", &szCertFile);
	ExitOnFailure(hr, "WcaGetProperty");

	if (!szCertFile || lstrlen(szCertFile) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidFilename);
		goto LExit;
	}

	hr = WcaGetProperty(L"P.CERT_PASS", &szCertPass);
	ExitOnFailure(hr, "WcaGetProperty");

	if (szCertPass && lstrlen(szCertPass) > 0)
	{
		LPWSTR szValBuf = new WCHAR[lstrlenW(szCertPass) + 1];

		for (int i = 0; i < lstrlenW(szCertPass); i++)
		{
			szValBuf[i] = L'*';
		}

		szValBuf[lstrlenW(szCertPass)] = L'\0';

		hr = WcaSetProperty(L"P.CERT_PASS_MASKED", szValBuf);

		delete[] szValBuf;

		ExitOnFailure(hr, "WcaSetProperty");
	}

	hr = WcaGetProperty(L"P.CERT_PK_FILE", &szPkFile);
	ExitOnFailure(hr, "WcaGetProperty");

	if ((!szCertPass || lstrlen(szCertPass) < 1) && (!szPkFile || lstrlen(szPkFile) < 1))
	{
		HandleValidationError(hInstall, Errors::InvalidCertificate);
		goto LExit;
	}

	int needPass = 0;
	hr = WcaGetIntProperty(L"P.CERT_NEED_PASS", &needPass);
	ExitOnFailure(hr, "WcaGetIntProperty");

	if (needPass == 0)
	{
		static LPCWSTR psCommandFormat = L"Import-DGatewayCertificate -CertificateFile '%ls' -Password '%ls'";
		psCommandLen = _snwprintf(nullptr, 0, psCommandFormat, szCertFile, szCertPass);
		psCommand = new WCHAR[psCommandLen + 1];
		_snwprintf(psCommand, psCommandLen, psCommandFormat, szCertFile, szCertPass);
	}
	else
	{
		static LPCWSTR psCommandFormat = L"Import-DGatewayCertificate -CertificateFile '%ls' -PrivateKeyFile '%ls'";
		psCommandLen = _snwprintf(nullptr, 0, psCommandFormat, szCertFile, szPkFile);
		psCommand = new WCHAR[psCommandLen + 1];
		_snwprintf(psCommand, psCommandLen, psCommandFormat, szCertFile, szPkFile);
	}

	psCommand[psCommandLen] = L'\0';

	hr = WcaSetProperty(L"P.CERT_CMD", psCommand);
	delete[] psCommand;
	ExitOnFailure(hr, "WcaSetProperty");

LExit:
	ReleaseStr(szCertFile);
	ReleaseStr(szCertPass);
	ReleaseStr(szPkFile);

	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall ValidatePublicKey(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	LPWSTR szPkFile = nullptr;
	static LPCWSTR psCommandFormat = L"Import-DGatewayProvisionerKey -PublicKeyFile \"%ls\"";
	int psCommandLen = 0;
	WCHAR* psCommand = nullptr;

	hr = WcaInitialize(hInstall, "ValidatePublicKey");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = WcaSetProperty(L"P.ERROR", L"");
	ExitOnFailure(hr, "WcaSetProperty");

	hr = WcaGetProperty(L"P.PUBLIC_KEY_FILE", &szPkFile);
	ExitOnFailure(hr, "WcaGetProperty");

	if (!szPkFile || lstrlen(szPkFile) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidFilename);
		goto LExit;
	}

	if (!FileExists(szPkFile))
	{
		HandleValidationError(hInstall, Errors::FileNotFound);
		goto LExit;
	}

	hr = WcaSetProperty(L"P.PUBLIC_KEY_CONFIG_VALID", L"0");
	ExitOnFailure(hr, "WcaSetProperty");

	psCommandLen = _snwprintf(nullptr, 0, psCommandFormat, szPkFile);
	psCommand = new WCHAR[psCommandLen + 1];
	_snwprintf(psCommand, psCommandLen, psCommandFormat, szPkFile);
	psCommand[psCommandLen] = L'\0';

	hr = WcaSetProperty(L"P.PK_CMD", psCommand);
	delete[] psCommand;
	ExitOnFailure(hr, "WcaSetProperty");

LExit:
	ReleaseStr(szPkFile);

	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

HRESULT __stdcall Configure(MSIHANDLE hInstall, LPCWSTR propCommand, int errorCode)
{
	HRESULT hr = S_OK;
	DWORD dwExitCode = 0;
	LPWSTR szPowerShellCmd = nullptr;
	LPWSTR szOutputPath = nullptr;
	LPWSTR szErrMsg = nullptr;
	DWORD dwErrMsgLen = 0;
	LPWSTR szFormattedErrMsg = nullptr;

	hr = WcaGetProperty(propCommand, &szPowerShellCmd);
	ExitOnFailure(hr, "WcaGetProperty");

	hr = ExecuteCommand(hInstall, szPowerShellCmd, &dwExitCode, &szOutputPath);
	ExitOnFailure(hr, "Failed to execute PowerShell command.");

LExit:
	if (SUCCEEDED(hr) && dwExitCode != 0)
	{
		LPCWSTR defaultErrMsg = L"N/A";

		if (szOutputPath == nullptr)
		{
			szOutputPath = (LPWSTR) calloc((size_t) lstrlenW(defaultErrMsg) + 1, sizeof(WCHAR));
			ExitOnNull(szOutputPath, hr, E_OUTOFMEMORY, "calloc");
			CopyMemory(szOutputPath, defaultErrMsg, lstrlenW(defaultErrMsg) * sizeof(WCHAR));
		}

		PMSIHANDLE hRecord = MsiCreateRecord(2);
		MsiRecordSetInteger(hRecord, 1, errorCode);
		MsiRecordSetStringW(hRecord, 2, szOutputPath);
		MsiProcessMessage(hInstall, INSTALLMESSAGE(INSTALLMESSAGE_ERROR + MB_OK), hRecord);
	}
	else if (FAILED(hr))
	{
		DWORD dwErr = Win32FromHResult(hr);
		LPWSTR szErrMsg = new WCHAR[256]();
		FormatWin32ErrorMessage(dwErr, szErrMsg, 256);

		PMSIHANDLE hRecord = MsiCreateRecord(2);
		MsiRecordSetInteger(hRecord, 1, CommandExecFailure);
		MsiRecordSetStringW(hRecord, 2, szErrMsg);
		MsiProcessMessage(hInstall, INSTALLMESSAGE(INSTALLMESSAGE_ERROR + MB_OK), hRecord);

		delete[] szErrMsg;
	}

	ReleaseStr(szPowerShellCmd);

	if (szOutputPath != nullptr)
	{
		MoveFileExW(szOutputPath, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
	}

	free(szOutputPath);

	if (dwExitCode != 0)
	{
		hr = E_FAIL;
	}

	return hr;
}

UINT __stdcall ConfigureAccessUri(MSIHANDLE hInstall)
{
	UINT er = ERROR_SUCCESS;
	HRESULT hr = S_OK;

	hr = WcaInitialize(hInstall, "ConfigureAccessUri");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = Configure(hInstall, L"CustomActionData", CommandExecAccessUriFailure);

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall ConfigureListeners(MSIHANDLE hInstall)
{
	UINT er = ERROR_SUCCESS;
	HRESULT hr = S_OK;

	hr = WcaInitialize(hInstall, "ConfigureListeners");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = Configure(hInstall, L"CustomActionData", CommandExecListenersFailure);

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall ConfigureCert(MSIHANDLE hInstall)
{
	UINT er = ERROR_SUCCESS;
	HRESULT hr = S_OK;

	hr = WcaInitialize(hInstall, "ConfigureCert");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = Configure(hInstall, L"CustomActionData", CommandExecCertificateFailure);

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall ConfigurePublicKey(MSIHANDLE hInstall)
{
	UINT er = ERROR_SUCCESS;
	HRESULT hr = S_OK;

	hr = WcaInitialize(hInstall, "ConfigurePublicKey");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = Configure(hInstall, L"CustomActionData", CommandExecPublicKeyFailure);

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall RollbackConfig(MSIHANDLE hInstall)
{
	UINT er = ERROR_SUCCESS;
	HRESULT hr = S_OK;
	WCHAR szProgramDataPath[MAX_PATH] = { 0 };
	WCHAR szFilePath[MAX_PATH] = { 0 };
	static const WCHAR* FILES[] = { (L"gateway.json"), (L"server.crt"), (L"server.key"), (L"provisioner.pem")};

	hr = WcaInitialize(hInstall, "RollbackConfig");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, szProgramDataPath);
	ExitOnFailure(hr, "SHGetFolderPath");

	hr = PathCchAppend(szProgramDataPath, MAX_PATH, L"Devolutions");
	ExitOnFailure(hr, "PathCchAppend");

	hr = PathCchAppend(szProgramDataPath, MAX_PATH, L"Gateway");
	ExitOnFailure(hr, "PathCchAppend");

	for (int i = 0; i < ARRAYSIZE(FILES); i++)
	{
		ZeroMemory(szFilePath, MAX_PATH * sizeof(WCHAR));
		CopyMemory(szFilePath, szProgramDataPath, lstrlenW(szProgramDataPath) * sizeof(WCHAR));

		hr = PathCchAppend(szFilePath, MAX_PATH, FILES[i]);

		if (!SUCCEEDED(hr))
		{
			Log(hInstall, L"PathCchAppend failed");
			continue;
		}

		if (!DeleteFileW(szFilePath) && GetLastError() != ERROR_FILE_NOT_FOUND)
		{
			LogGLE(hInstall, L"DeleteFile");
		}
	}

	hr = S_OK;

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

// DllMain - Initialize and cleanup WiX custom action utils.
extern "C" BOOL WINAPI DllMain(
	__in HINSTANCE hInst,
	__in ULONG ulReason,
	__in LPVOID
	)
{
	switch(ulReason)
	{
	case DLL_PROCESS_ATTACH:
		WcaGlobalInitialize(hInst);
		break;

	case DLL_PROCESS_DETACH:
		WcaGlobalFinalize();
		break;
	}

	return TRUE;
}
