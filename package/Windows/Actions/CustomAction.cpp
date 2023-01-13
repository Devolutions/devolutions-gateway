#include "stdafx.h"
#include "shlwapi.h"

enum Errors
{
	NoError = 0,
	ServiceQueryFailure = 29994,
	InvalidCertificate = 29995,
	FileNotFound = 29996,
	InvalidFilename = 29997,
	InvalidScheme = 29998,
	InvalidPort = 29999,
	InvalidHost = 30000
};

constexpr auto DG_SERVICE_NAME = L"DevolutionsGateway";

/// <summary>
/// Write a message to the installer log
/// </summary>
UINT __stdcall Log(MSIHANDLE hInstall, LPCWSTR message)
{
	PMSIHANDLE hRecord = MsiCreateRecord(1);
	MsiRecordSetStringW(hRecord, 0, L"DevolutionsGateway.Installer.Actions: [1]");
	MsiRecordSetStringW(hRecord, 1, message);
	MsiProcessMessage(hInstall, INSTALLMESSAGE_INFO, hRecord);
	return ERROR_SUCCESS; 
}

/// <summary>
/// Write a message to the installer log including the error code |le|
/// </summary>
UINT __stdcall LogGLE(MSIHANDLE hInstall, LPCWSTR message, int le)
{
	WCHAR formatMessage[260] = { 0 };

	if (swprintf_s(formatMessage, 260, L"%ls (%lu)", message, GetLastError()) == -1)
	{
		Log(hInstall, L"Failed to format GLE");
		return Log(hInstall, message);
	}
	else
	{
		return Log(hInstall, formatMessage);
	}
}

/// <summary>
/// Write a message to the installer log, including the result of GetLastError
/// </summary>
UINT __stdcall LogGLE(MSIHANDLE hInstall, LPCWSTR message)
{
	int le = GetLastError();

	return LogGLE(hInstall, message, le);
}

void __stdcall ShowErrorMessage(MSIHANDLE hInstall, int error)
{
	PMSIHANDLE hRecord = MsiCreateRecord(1);
	MsiRecordSetInteger(hRecord, 1, error);
	MsiProcessMessage(hInstall, INSTALLMESSAGE_WARNING, hRecord);
}

/// <summary>
/// Lookup the localized error message for the code |error| and copy it to the P.ERROR property
/// </summary>
UINT __stdcall HandleValidationError(MSIHANDLE hInstall, int error)
{
	UINT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	PMSIHANDLE hDatabase;
	PMSIHANDLE hView = NULL;
	PMSIHANDLE hRecord = NULL;
	WCHAR szQuery[255] = { 0 };
	DWORD dwErrorMessageLen = 0;
	LPWSTR errMessage = NULL;

	// Write the error to the log file
	PMSIHANDLE hLogRecord = MsiCreateRecord(1);
	MsiRecordSetInteger(hLogRecord, 1, error);
	MsiProcessMessage(hInstall, INSTALLMESSAGE_INFO, hLogRecord);

	swprintf_s(szQuery, _countof(szQuery), L"SELECT `Message` FROM `Error` WHERE `Error` = %d", error);

	hDatabase = MsiGetActiveDatabase(hInstall);
	hr = MsiDatabaseOpenViewW(hDatabase, szQuery, &hView);
	ExitOnFailure(hr, "MsiDatabaseOpenView");

	hr = MsiViewExecute(hView, hRecord);
	ExitOnFailure(hr, "MsiViewExecute");

	hr = MsiViewFetch(hView, &hRecord);
	ExitOnFailure(hr, "MsiViewExecute");

	// MsiRecordGetString offsets begin at 1 (obviously written by a VB developer)
	hr = MsiRecordGetString(hRecord, 1, L"", &dwErrorMessageLen);

	if (hr == ERROR_MORE_DATA)
	{
		++dwErrorMessageLen;

		errMessage = new WCHAR[dwErrorMessageLen];
		MsiRecordGetString(hRecord, 1, errMessage, &dwErrorMessageLen);

		MsiSetPropertyW(hInstall, L"P.ERROR", errMessage);

		delete[] errMessage;
	}

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return er;
}

UINT __stdcall IsValidPort(LPWSTR port, int* value)
{
	UINT status = -1;

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

	if (value != NULL)
	{
		*value = portValue;
	}

	status = ERROR_SUCCESS;

LExit:
	return status;
}

UINT __stdcall IsValidPort(LPWSTR port)
{
	return IsValidPort(port, NULL);
}

UINT __stdcall IsValidOption(LPWSTR option, const WCHAR** validOptions, int len)
{
	UINT status = -1;

	for (int i = 0; i < len; i++)
	{
		if (StrCmpIW(option, validOptions[i]) == 0)
		{
			status = ERROR_SUCCESS;
			break;
		}
	}

	return status;
}

UINT __stdcall FormatHttpUrl(LPCWSTR scheme, int port, WCHAR* buffer, size_t bufferLen)
{
	static LPCWSTR urlFormat = L"%ls://*%ls";
	static LPCWSTR portFormat = L":%d";
	int suffixLen = 0;
	WCHAR* suffix = NULL;

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

UINT __stdcall GetPowerShellVersion(USHORT* pMajor, USHORT* pMinor, USHORT* pRevision, USHORT* pPatch)
{
	UINT status = -1;
	HKEY hKey = nullptr;
	DWORD dwType;
	DWORD dwInstall = 0;
	DWORD cbData;
	USHORT major, minor, revision, patch;

	char szVersion[512] = { 0 };

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\PowerShell\\3", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
		goto exit;

	cbData = sizeof(DWORD);

	if (RegQueryValueExA(hKey, "Install", nullptr, &dwType, (LPBYTE)&dwInstall, &cbData) != ERROR_SUCCESS)
		goto exit;

	if (dwInstall != 1)
		goto exit;

	RegCloseKey(hKey);
	hKey = nullptr;

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\PowerShell\\3\\PowerShellEngine", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
		goto exit;

	cbData = sizeof(szVersion);

	if (RegQueryValueExA(hKey, "PowerShellVersion", nullptr, &dwType, (LPBYTE)szVersion, &cbData) != ERROR_SUCCESS)
		goto exit;

	if (sscanf(szVersion, "%hu.%hu.%hu.%hu", &major, &minor, &revision, &patch) == 4)
	{
		if (pMajor)
			*pMajor = major;
		
		if (pMinor)
			*pMinor = minor;

		if (pRevision)
			*pRevision = revision;

		if (pPatch)
			*pPatch = patch;

		status = 1;
	}

exit:
	if (hKey)
		RegCloseKey(hKey);

	return status;
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
	ExitOnFailure(hr, "The expected property was not found.");

	if (GetPowerShellVersion(&major, &minor, &rev, &patch) != 1)
	{
		goto LExit;
	}

	if (major >= 5 && minor >= 1)
	{
		hr = WcaSetIntProperty(L"P.HASPWSH", 0);
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

UINT __stdcall BrowseForFile(MSIHANDLE hInstall, LPCWSTR propertyName, LPCWSTR fileFilter)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	HANDLE hExistingFile;
	WIN32_FIND_DATA fdExistingFileData = { 0 };
	OPENFILENAMEW ofn = { 0 };
	LPWSTR szSourceFileName = NULL;
	WCHAR szFoundFileName[MAX_PATH] = { 0 };

	hr = WcaGetProperty(propertyName, &szSourceFileName);
	ExitOnFailure(hr, "The expected property was not found.");

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
	ofn.lpstrInitialDir = NULL;
	ofn.lpstrFilter = fileFilter;
	ofn.nFilterIndex = 1;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (GetOpenFileNameW(&ofn))
	{
		hr = WcaSetProperty(propertyName, ofn.lpstrFile);
		ExitOnFailure(hr, "The expected property was not found.");
	}

LExit:
	ReleaseStr(szSourceFileName);
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return er;
}

UINT __stdcall BrowseForCertificate(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	LPCWSTR propertyName = L"P.CERT_FILE";
	LPWSTR szSourceFileName = NULL;
	static const WCHAR* PFX_EXTS[] = { (L"pfx"), (L"p12") };

	hr = WcaInitialize(hInstall, "BrowseForCertificate");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	er = BrowseForFile(
		hInstall, 
		propertyName, 
		L"PFX Files (*.pfx, *.p12)\0*.pfx;*.p12\0Certificate Files (*.pem, *.crt)\0*.pem;*.crt\0All Files\0*.*\0\0"
	);

	if (er != ERROR_SUCCESS)
	{
		hr = HRESULT_FROM_WIN32(er);
		goto LExit;
	}

	hr = WcaGetProperty(propertyName, &szSourceFileName);
	ExitOnFailure(hr, "The expected property was not found.");

	// We expect the file to have an extension, because of the filter
	WCHAR* pExt = PathFindExtensionW(szSourceFileName);
	pExt++;

	hr = WcaSetIntProperty(L"P.CERT_NEED_PASS", 1);
	ExitOnFailure(hr, "The expected property was not found.");

	if (IsValidOption(pExt, PFX_EXTS, ARRAYSIZE(PFX_EXTS)) == ERROR_SUCCESS)
	{
		// Tell the .msi we need a password
		hr = WcaSetIntProperty(L"P.CERT_NEED_PASS", 0);
	}

LExit:
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

	er = BrowseForFile(hInstall, L"P.CERT_PK_FILE", L"Private Key Files (*.key)\0*.key\0All Files\0*.*\0\0");

	if (er != ERROR_SUCCESS)
	{
		hr = HRESULT_FROM_WIN32(er);
		goto LExit;
	}

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

	er = BrowseForFile(
		hInstall, 
		L"P.PUBLIC_KEY_FILE", 
		L"Public Key Files (*.pem)\0*.pem\0Private Key Files (*.key)\0*.key\0All Files\0*.*\0\0"
	);

	if (er != ERROR_SUCCESS)
	{
		hr = HRESULT_FROM_WIN32(er);
		goto LExit;
	}

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

HRESULT __stdcall OpenServiceManagerX(MSIHANDLE hInstall, DWORD dwDesiredAccess, SC_HANDLE* lpHandle)
{
	HRESULT hr = S_OK;
	SC_HANDLE hSCM = NULL;

	hSCM = OpenSCManagerW(NULL, NULL, dwDesiredAccess);

	if (hSCM == NULL)
	{
		DWORD dwError = GetLastError();
		LogGLE(hInstall, L"OpenSCManager failed", dwError);
		hr = HRESULT_FROM_WIN32(dwError);
	}

	*lpHandle = hSCM;

	return hr;
}

HRESULT __stdcall OpenServiceX(MSIHANDLE hInstall, SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess, SC_HANDLE* lpHandle)
{
	HRESULT hr = S_OK;
	SC_HANDLE hService = NULL;

	hService = OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);

	if (hService == NULL)
	{
		DWORD dwError = GetLastError();
		LogGLE(hInstall, L"OpenService failed", dwError);
		hr = HRESULT_FROM_WIN32(dwError);
	}

	*lpHandle = hService;

	return hr;
}

UINT __stdcall SetGatewayStartupType(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	int serviceStart = SERVICE_DEMAND_START;
	SC_HANDLE hSCM = NULL;
	SC_HANDLE hService = NULL;
	DWORD dwValBuf = 0;
	LPWSTR szValBuf = NULL;

	hr = WcaInitialize(hInstall, "SetGatewayStartupType");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	er = MsiGetPropertyW(hInstall, L"CustomActionData", L"", &dwValBuf);

	if (er == ERROR_MORE_DATA)
	{
		++dwValBuf; // Null-terminator
		szValBuf = new WCHAR[dwValBuf];
		er = MsiGetPropertyW(hInstall, L"CustomActionData", szValBuf, &dwValBuf);

		if (er == ERROR_SUCCESS)
		{
			serviceStart = _wtoi(szValBuf);
		}

		delete[] szValBuf;

		if (er != ERROR_SUCCESS)
		{
			hr = HRESULT_FROM_WIN32(er);
			Log(hInstall, L"SetGatewayStartupType failed to retrieve CustomActionData");

			goto LExit;
		}
	}
	else
	{
		hr = HRESULT_FROM_WIN32(er);
		Log(hInstall, L"SetGatewayStartupType failed to retrieve CustomActionData");

		goto LExit;
	}

	if (OpenServiceManagerX(hInstall, SC_MANAGER_ALL_ACCESS, &hSCM) != S_OK)
	{
		goto LExit;
	}

	if (OpenServiceX(hInstall, hSCM, DG_SERVICE_NAME, SERVICE_CHANGE_CONFIG, &hService) != S_OK)
	{
		goto LExit;
	}

	if (!ChangeServiceConfigW(hService, SERVICE_NO_CHANGE, serviceStart, SERVICE_NO_CHANGE,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL))
	{
		DWORD dwError = GetLastError();
		LogGLE(hInstall, L"ChangeServiceConfig failed", dwError);
		hr = HRESULT_FROM_WIN32(dwError);

		goto LExit;
	}

LExit:
	if (hService != NULL)
	{
		CloseServiceHandle(hService);
	}

	if (hSCM != NULL)
	{
		CloseServiceHandle(hSCM);
	}

	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

HRESULT __stdcall GetGatewayStartupType(MSIHANDLE hInstall, DWORD* pStartupType)
{
	HRESULT hr = E_FAIL;
	SC_HANDLE hSCM = NULL;
	SC_HANDLE hService = NULL;
	LPQUERY_SERVICE_CONFIG lpsc = { 0 };
	DWORD dwBytesNeeded;
	DWORD cbBufSize = 0;
	DWORD dwError;

	if (OpenServiceManagerX(hInstall, SC_MANAGER_CONNECT, &hSCM) != S_OK)
	{
		goto LExit;
	}

	if (OpenServiceX(hInstall, hSCM, DG_SERVICE_NAME, SERVICE_QUERY_CONFIG, &hService) != S_OK)
	{
		goto LExit;
	}

	if (!QueryServiceConfigW(hService, NULL, 0, &dwBytesNeeded))
	{
		dwError = GetLastError();

		if (dwError == ERROR_INSUFFICIENT_BUFFER)
		{
			cbBufSize = dwBytesNeeded;
			lpsc = (LPQUERY_SERVICE_CONFIG) LocalAlloc(LMEM_FIXED, cbBufSize);

			if (lpsc == NULL)
			{
				Log(hInstall, L"LocalAlloc failure");

				goto LExit;
			}
		}
		else
		{
			LogGLE(hInstall, L"QueryServiceConfig failed", dwError);
			hr = HRESULT_FROM_WIN32(dwError);

			goto LExit;
		}
	}

	if (!QueryServiceConfigW(hService, lpsc, cbBufSize, &dwBytesNeeded))
	{
		dwError = GetLastError();
		LogGLE(hInstall, L"QueryServiceConfig failed", dwError);
		hr = HRESULT_FROM_WIN32(dwError);

		LocalFree(lpsc);

		goto LExit;
	}

	hr = S_OK;
	*pStartupType = lpsc->dwStartType;

	LocalFree(lpsc);

LExit:
	if (hService != NULL)
	{
		CloseServiceHandle(hService);
	}

	if (hSCM != NULL)
	{
		CloseServiceHandle(hSCM);
	}

	return hr;
}

UINT __stdcall QueryGatewayStartupType(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	DWORD dwStartType = 0;
	UINT er = ERROR_SUCCESS;

	hr = WcaInitialize(hInstall, "QueryGatewayStartupType");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	Log(hInstall, L"Looking for existing Devolutions Gateway service");

	hr = GetGatewayStartupType(hInstall, &dwStartType);

	if (hr == S_OK)
	{
		hr = WcaSetIntProperty(L"P.SERVICE_START", dwStartType == SERVICE_DISABLED ? SERVICE_DEMAND_START : dwStartType);
		ExitOnFailure(hr, "The expected property was not found.");
	}

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall StartGatewayIfNeeded(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	DWORD dwStartType = 0;
	SC_HANDLE hSCM = NULL;
	SC_HANDLE hService = NULL;
	UINT er = ERROR_SUCCESS;

	hr = WcaInitialize(hInstall, "StartGatewayIfNeeded");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = GetGatewayStartupType(hInstall, &dwStartType);

	if (hr == S_OK)
	{
		if (dwStartType == SERVICE_AUTO_START)
		{
			Log(hInstall, L"Trying to start the Devolutions Gateway service");

			if (OpenServiceManagerX(hInstall, SC_MANAGER_CONNECT, &hSCM) != S_OK)
			{
				goto LExit;
			}

			if (OpenServiceX(hInstall, hSCM, DG_SERVICE_NAME, SERVICE_START, &hService) != S_OK)
			{
				goto LExit;
			}

			if (StartServiceW(hService, 0, NULL))
			{
				Log(hInstall, L"Successfully asked the Devolutions Gateway service to start");
			}
			else
			{
				DWORD dwError = GetLastError();

				if (dwError == ERROR_SERVICE_ALREADY_RUNNING)
				{
					Log(hInstall, L"Devolutions Gateway service is already running");

					goto LExit;
				}

				LogGLE(hInstall, L"StartService failed", dwError);
				hr = HRESULT_FROM_WIN32(dwError);
			}
		}
		else
		{
			Log(hInstall, L"Devolutions Gateway service is not SERVICE_AUTO_START, nothing to do");
		}
	}

LExit:
	if (hService != NULL)
	{
		CloseServiceHandle(hService);
	}

	if (hSCM != NULL)
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
	LPWSTR szAccessUriScheme = NULL;
	LPWSTR szAccessUriHost = NULL;
	LPWSTR szAccessUriPort = NULL;
	static LPCWSTR uriFormat = L"%ls://%ls:%ls";
	int uriLen = 0;
	WCHAR* uri = NULL;
	DWORD dwHostLen = INTERNET_MAX_HOST_NAME_LENGTH;
	WCHAR wszHost[INTERNET_MAX_HOST_NAME_LENGTH] = { 0 };
	static LPCWSTR psCommandFormat = L"Set-DGatewayHostname %ls";
	int psCommandLen = 0;
	WCHAR* psCommand = NULL;

	hr = WcaInitialize(hInstall, "ValidateAccessUri");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = WcaSetProperty(L"P.ERROR", L"");
	ExitOnFailure(hr, "The expected property was not found.");

	hr = WcaGetProperty(L"P.ACCESSURI_SCHEME", &szAccessUriScheme);
	ExitOnFailure(hr, "The expected property was not found.");

	if (!szAccessUriScheme || lstrlen(szAccessUriScheme) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidScheme);
		goto LExit;
	}

	static const WCHAR* VALID_SCHEMES[] = { (L"http"), (L"https") };

	if (IsValidOption(szAccessUriScheme, VALID_SCHEMES, ARRAYSIZE(VALID_SCHEMES)) != ERROR_SUCCESS)
	{
		HandleValidationError(hInstall, Errors::InvalidScheme);
		goto LExit;
	}

	hr = WcaGetProperty(L"P.ACCESSURI_HOST", &szAccessUriHost);
	ExitOnFailure(hr, "The expected property was not found.");

	if (!szAccessUriHost || lstrlen(szAccessUriHost) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidHost);
		goto LExit;
	}

	hr = WcaGetProperty(L"P.ACCESSURI_PORT", &szAccessUriPort);
	ExitOnFailure(hr, "The expected property was not found.");

	if (!szAccessUriPort || lstrlen(szAccessUriPort) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidPort);
		goto LExit;
	}

	if (IsValidPort(szAccessUriPort) != ERROR_SUCCESS)
	{
		HandleValidationError(hInstall, Errors::InvalidPort);
		goto LExit;
	}

	if (lstrcmpi(szAccessUriScheme, L"http") == 0)
	{
		hr = WcaSetProperty(L"P.HTTPURI_SCHEME", L"http");
		ExitOnFailure(hr, "The expected property was not found.");
	}

	uriLen = _snwprintf(NULL, 0, uriFormat, szAccessUriScheme, szAccessUriHost, szAccessUriPort);
	uri = new WCHAR[uriLen + 1];
	_snwprintf(uri, uriLen, uriFormat, szAccessUriScheme, szAccessUriHost, szAccessUriPort);
	uri[uriLen] = L'\0';

	hr = UrlGetPartW(uri, wszHost, &dwHostLen, URL_PART_HOSTNAME, 0);

	delete[] uri;

	if (hr != S_OK)
	{
		HandleValidationError(hInstall, Errors::InvalidHost);
		goto LExit;
	}

	psCommandLen = _snwprintf(NULL, 0, psCommandFormat, wszHost);
	psCommand = new WCHAR[psCommandLen + 1];
	_snwprintf(psCommand, psCommandLen, psCommandFormat, wszHost);
	psCommand[psCommandLen] = L'\0';

	hr = WcaSetProperty(L"P.ACCESSURI_CMD", psCommand);
	delete[] psCommand;
	ExitOnFailure(hr, "The expected property was not found.");

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall ValidateListeners(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	LPWSTR szHttpUriScheme = NULL;
	LPWSTR szHttpUriPort = NULL;
	LPWSTR szTcpUriPort = NULL;
	LPWSTR szAccessUriScheme = NULL;
	int httpUriPort = 0;
	int accessUriPort = 0;
	int externalUrlLen = 0;
	WCHAR* externalUrl = NULL;
	int internalUrlLen = 0;
	WCHAR* internalUrl = NULL;
	static LPCWSTR psCommandFormat = L"$httpListener = New-DGatewayListener \"%ls\" \"%ls\"; $tcpListener = New-DGatewayListener \"tcp://*:%ls\" \"tcp://*:%ls\"; $listeners = $httpListener, $tcpListener; Set-DGatewayListeners $listeners";
	int psCommandLen = 0;
	WCHAR* psCommand = NULL;

	hr = WcaInitialize(hInstall, "ValidateListeners");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = WcaSetProperty(L"P.ERROR", L"");
	ExitOnFailure(hr, "The expected property was not found.");

	hr = WcaGetProperty(L"P.HTTPURI_SCHEME", &szHttpUriScheme);
	ExitOnFailure(hr, "The expected property was not found.");

	if (!szHttpUriScheme || lstrlen(szHttpUriScheme) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidScheme);
		goto LExit;
	}

	static const WCHAR* VALID_SCHEMES[] = { (L"http"), (L"https") };

	if (IsValidOption(szHttpUriScheme, VALID_SCHEMES, ARRAYSIZE(VALID_SCHEMES)) != ERROR_SUCCESS)
	{
		HandleValidationError(hInstall, Errors::InvalidScheme);
		goto LExit;
	}

	hr = WcaGetProperty(L"P.HTTPURI_PORT", &szHttpUriPort);
	ExitOnFailure(hr, "The expected property was not found.");

	if (!szHttpUriPort || lstrlen(szHttpUriPort) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidPort);
		goto LExit;
	}

	if (IsValidPort(szHttpUriPort, &httpUriPort) != ERROR_SUCCESS)
	{
		HandleValidationError(hInstall, Errors::InvalidPort);
		goto LExit;
	}

	hr = WcaGetProperty(L"P.TCPURI_PORT", &szTcpUriPort);
	ExitOnFailure(hr, "The expected property was not found.");

	if (!szTcpUriPort || lstrlen(szTcpUriPort) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidPort);
		goto LExit;
	}

	if (IsValidPort(szTcpUriPort) != ERROR_SUCCESS)
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
	psCommandLen = _snwprintf(NULL, 0, psCommandFormat, internalUrl, externalUrl, szTcpUriPort, szTcpUriPort);
	psCommand = new WCHAR[psCommandLen + 1];
	_snwprintf(psCommand, psCommandLen, psCommandFormat, internalUrl, externalUrl, szTcpUriPort, szTcpUriPort);
	psCommand[psCommandLen] = L'\0';

	delete[] internalUrl;
	delete[] externalUrl;

	hr = WcaSetProperty(L"P.LISTENER_CMD", psCommand);
	delete[] psCommand;
	ExitOnFailure(hr, "The expected property was not found.");

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall ValidateCertificate(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	LPWSTR szCertFile = NULL;
	LPWSTR szCertPass = NULL;
	LPWSTR szPkFile = NULL;
	int psCommandLen = 0;
	WCHAR* psCommand = NULL;

	hr = WcaInitialize(hInstall, "ValidateCertificate");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = WcaSetProperty(L"P.ERROR", L"");
	ExitOnFailure(hr, "The expected property was not found.");

	hr = WcaGetProperty(L"P.CERT_FILE", &szCertFile);
	ExitOnFailure(hr, "The expected property was not found.");

	if (!szCertFile || lstrlen(szCertFile) < 1)
	{
		HandleValidationError(hInstall, Errors::InvalidFilename);
		goto LExit;
	}

	hr = WcaGetProperty(L"P.CERT_PASS", &szCertPass);
	ExitOnFailure(hr, "The expected property was not found.");

	if (szCertPass && lstrlen(szCertPass) > 0)
	{
		LPWSTR szValBuf = new WCHAR[lstrlenW(szCertPass) + 1];

		for (int i = 0; i < lstrlenW(szCertPass); i++)
		{
			szValBuf[i] = L'●';
		}

		szValBuf[lstrlenW(szCertPass)] = L'\0';

		hr = WcaSetProperty(L"P.CERT_PASS_MASKED", szValBuf);

		delete[] szValBuf;
	}

	hr = WcaGetProperty(L"P.CERT_PK_FILE", &szPkFile);
	ExitOnFailure(hr, "The expected property was not found.");

	if ((!szCertPass || lstrlen(szCertPass) < 1) && (!szPkFile || lstrlen(szPkFile) < 1))
	{
		HandleValidationError(hInstall, Errors::InvalidCertificate);
		goto LExit;
	}

	int needPass = 0;
	hr = WcaGetIntProperty(L"P.CERT_NEED_PASS", &needPass);
	ExitOnFailure(hr, "The expected property was not found.");

	if (needPass == 0)
	{
		static LPCWSTR psCommandFormat = L"Import-DGatewayCertificate -CertificateFile '%ls' -Password '%ls'";
		psCommandLen = _snwprintf(NULL, 0, psCommandFormat, szCertFile, szCertPass);
		psCommand = new WCHAR[psCommandLen + 1];
		_snwprintf(psCommand, psCommandLen, psCommandFormat, szCertFile, szCertPass);
	}
	else
	{
		static LPCWSTR psCommandFormat = L"Import-DGatewayCertificate -CertificateFile '%ls' -PrivateKeyFile '%ls'";
		psCommandLen = _snwprintf(NULL, 0, psCommandFormat, szCertFile, szPkFile);
		psCommand = new WCHAR[psCommandLen + 1];
		_snwprintf(psCommand, psCommandLen, psCommandFormat, szCertFile, szPkFile);
	}

	psCommand[psCommandLen] = L'\0';

	hr = WcaSetProperty(L"P.CERT_CMD", psCommand);
	delete[] psCommand;
	ExitOnFailure(hr, "The expected property was not found.");

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

UINT __stdcall ValidatePublicKey(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	LPWSTR szPkFile = NULL;
	static LPCWSTR psCommandFormat = L"Import-DGatewayProvisionerKey -PublicKeyFile '%ls'";
	int psCommandLen = 0;
	WCHAR* psCommand = NULL;

	hr = WcaInitialize(hInstall, "ValidatePublicKey");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = WcaSetProperty(L"P.ERROR", L"");
	ExitOnFailure(hr, "The expected property was not found.");

	hr = WcaGetProperty(L"P.PUBLIC_KEY_FILE", &szPkFile);
	ExitOnFailure(hr, "The expected property was not found.");

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
	ExitOnFailure(hr, "The expected property was not found.");

	psCommandLen = _snwprintf(NULL, 0, psCommandFormat, szPkFile);
	psCommand = new WCHAR[psCommandLen + 1];
	_snwprintf(psCommand, psCommandLen, psCommandFormat, szPkFile);
	psCommand[psCommandLen] = L'\0';

	hr = WcaSetProperty(L"P.PK_CMD", psCommand);
	delete[] psCommand;
	ExitOnFailure(hr, "The expected property was not found.");

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
