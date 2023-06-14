
#include "ApiHooks.h"

#include "Logger.h"
#include "Utils.h"

#include <winhttp.h>

#include <detours.h>

#define JETIFY_DETOUR_ATTACH(_realFn, _hookFn) \
	if (_realFn) DetourAttach((PVOID*)(&_realFn), _hookFn);

#define JETIFY_DETOUR_DETACH(_realFn, _hookFn) \
	if (_realFn) DetourDetach((PVOID*)(&_realFn), _hookFn);

#define JETIFY_GETPROCADDRESS(_funcPtr, _funcType, _hModule, _funcName) \
	_funcPtr = ( _funcType ) GetProcAddress(_hModule, _funcName);

HINTERNET(WINAPI * Real_WinHttpOpen)(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags) = WinHttpOpen;

HINTERNET Hook_WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags)
{
    HINTERNET hInternet;
    char* pszAgentA = NULL;
    char* pszProxyA = NULL;
    WCHAR* _pszProxyW = NULL;
    char* pszProxyBypassA = NULL;
    WCHAR* _pszProxyBypassW = NULL;

    if (pszAgentW && !wcscmp(pszAgentW, L"Microsoft WinRM Client")) {
        char* pszProxyEnvA = Jetify_GetEnv("WINRM_PROXY");
        char* pszProxyBypassEnvA = Jetify_GetEnv("WINRM_PROXY_BYPASS");

        if (pszProxyEnvA) {
            dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
            Jetify_ConvertToUnicode(CP_UTF8, 0, pszProxyEnvA, -1, &_pszProxyW, 0);
            pszProxyW = _pszProxyW;

            if (pszProxyBypassEnvA) {
                Jetify_ConvertToUnicode(CP_UTF8, 0, pszProxyBypassEnvA, -1, &_pszProxyBypassW, 0);
                pszProxyBypassW = _pszProxyBypassW;
            }
        }

        free(pszProxyEnvA);
        free(pszProxyBypassEnvA);
    }

    if (pszAgentW)
        Jetify_ConvertFromUnicode(CP_UTF8, 0, pszAgentW, -1, &pszAgentA, 0, NULL, NULL);

    if (pszProxyW)
        Jetify_ConvertFromUnicode(CP_UTF8, 0, pszProxyW, -1, &pszProxyA, 0, NULL, NULL);

    if (pszProxyBypassW)
        Jetify_ConvertFromUnicode(CP_UTF8, 0, pszProxyBypassW, -1, &pszProxyBypassA, 0, NULL, NULL);

    Jetify_LogPrint(DEBUG, "WinHttpOpen(dwAccessType: %d, dwFlags: 0x%08X)", dwAccessType, dwFlags);
    Jetify_LogPrint(DEBUG, "pszAgent: \"%s\"", pszAgentA ? pszAgentA : "");
    Jetify_LogPrint(DEBUG, "pszProxy: \"%s\" pszProxyBypass: \"%s\"",
        pszProxyA ? pszProxyA : "", pszProxyBypassA ? pszProxyBypassA : "");

    hInternet = Real_WinHttpOpen(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags);

    if (pszAgentA)
        free(pszAgentA);

    if (pszProxyA)
        free(pszProxyA);

    if (_pszProxyW)
        free(_pszProxyW);

    if (pszProxyBypassA)
        free(pszProxyBypassA);

    if (_pszProxyBypassW)
        free(_pszProxyBypassW);

    return hInternet;
}

HINTERNET(WINAPI* Real_WinHttpConnect)(HINTERNET hSession, LPCWSTR pszServerNameW, INTERNET_PORT nServerPort, DWORD dwReserved) = WinHttpConnect;

HINTERNET Hook_WinHttpConnect(HINTERNET hSession, LPCWSTR pszServerNameW, INTERNET_PORT nServerPort, DWORD dwReserved)
{
    HINTERNET hInternet;
    char* pszServerNameA = NULL;

    if (pszServerNameW)
        Jetify_ConvertFromUnicode(CP_UTF8, 0, pszServerNameW, -1, &pszServerNameA, 0, NULL, NULL);

    Jetify_LogPrint(DEBUG, "WinHttpConnect(hSession: %p, pszServerName: %s nServerPort: %d)",
        hSession, pszServerNameA ? pszServerNameA : "", (int)nServerPort);
    
    hInternet = Real_WinHttpConnect(hSession, pszServerNameW, nServerPort, dwReserved);
    
    if (pszServerNameA)
        free(pszServerNameA);

    return hInternet;
}

BOOL(WINAPI* Real_WinHttpSetOption)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength) = WinHttpSetOption;

BOOL Hook_WinHttpSetOption(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength)
{
    BOOL success;
    
    Jetify_LogPrint(DEBUG, "WinHttpSetOption(hInternet: %p, dwOption: %d, dwBufferLength: %d)",
        hInternet, dwOption, dwBufferLength);
    
    success = Real_WinHttpSetOption(hInternet, dwOption, lpBuffer, dwBufferLength);
    
    return success;
}

HINTERNET(WINAPI* Real_WinHttpOpenRequest)(HINTERNET hConnect, LPCWSTR pszVerbW,
    LPCWSTR pszObjectNameW, LPCWSTR pszVersionW, LPCWSTR pszReferrerW,
    LPCWSTR* ppszAcceptTypesW, DWORD dwFlags) = WinHttpOpenRequest;

HINTERNET Hook_WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pszVerbW,
    LPCWSTR pszObjectNameW, LPCWSTR pszVersionW, LPCWSTR pszReferrerW,
    LPCWSTR* ppszAcceptTypesW, DWORD dwFlags)
{
    HINTERNET hRequest;

    Jetify_LogPrint(DEBUG, "WinHttpOpenRequest(hConnect: %p)",
        hConnect);

    hRequest = Real_WinHttpOpenRequest(hConnect, pszVerbW, pszObjectNameW, pszVersionW, pszReferrerW, ppszAcceptTypesW, dwFlags);

    return hRequest;
}

BOOL (WINAPI* Real_WinHttpSendRequest)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext) = WinHttpSendRequest;

BOOL Hook_WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext)
{
    BOOL success;

    Jetify_LogPrint(DEBUG, "WinHttpSendRequest(hRequest: %p)",
        hRequest);

    success = Real_WinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength,
        lpOptional, dwOptionalLength, dwTotalLength, dwContext);

    return success;
}

BOOL(WINAPI* Real_WinHttpCloseHandle)(HINTERNET hInternet) = WinHttpCloseHandle;

BOOL Hook_WinHttpCloseHandle(HINTERNET hInternet)
{
    BOOL success;
    Jetify_LogPrint(DEBUG, "WinHttpCloseHandle(hInternet: %p)", hInternet);
    success = Real_WinHttpCloseHandle(hInternet);
    return success;
}

static HMODULE g_hKernelBase = NULL;
static HMODULE g_hAdvapi32 = NULL;
static HMODULE g_hRegApi = NULL;

typedef LSTATUS(WINAPI* Func_RegOpenKeyExW)(
    HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);

typedef LSTATUS(WINAPI* Func_RegQueryValueExW)(
    HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE  lpData, LPDWORD lpcbData);

static Func_RegOpenKeyExW Real_RegOpenKeyExW = NULL;
static Func_RegQueryValueExW Real_RegQueryValueExW = NULL;

static HKEY g_hRegWSManClient = NULL;

LSTATUS Hook_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKeyW, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    LSTATUS lstatus = ERROR_SUCCESS;

#if 0
    char* lpSubKeyA = NULL;

    if (lpSubKeyW)
        Jetify_ConvertFromUnicode(CP_UTF8, 0, lpSubKeyW, -1, &lpSubKeyA, 0, NULL, NULL);

    Jetify_LogPrint(DEBUG, "RegOpenKeyExW(lpSubKey: %s)", lpSubKeyA);
#endif

    lstatus = Real_RegOpenKeyExW(hKey, lpSubKeyW, ulOptions, samDesired, phkResult);

    if ((hKey == HKEY_LOCAL_MACHINE) && lpSubKeyW)
    {
        if (!_wcsicmp(lpSubKeyW, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Client"))
        {
            g_hRegWSManClient = *phkResult;
        }
    }

    //free(lpSubKeyA);
    return lstatus;
}

LSTATUS Hook_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueNameW, LPDWORD lpReserved, LPDWORD lpType, LPBYTE  lpData, LPDWORD lpcbData)
{
    LSTATUS lstatus = ERROR_SUCCESS;

#if 0
    char* lpValueNameA = NULL;

    if (lpValueNameW)
        Jetify_ConvertFromUnicode(CP_UTF8, 0, lpValueNameW, -1, &lpValueNameA, 0, NULL, NULL);

    Jetify_LogPrint(DEBUG, "RegQueryValueExW(lpValueName: %s)", lpValueNameA);
#endif

    if ((hKey == g_hRegWSManClient) && lpValueNameW)
    {
        if (!_wcsicmp(lpValueNameW, L"TrustedHosts"))
        {
            if (lpType)
                *lpType = REG_DWORD;

            if (lpData && lpcbData && (*lpcbData == sizeof(DWORD)))
            {
                *((DWORD*)lpData) = 1;
                return lstatus;
            }
        }
        else if (!_wcsicmp(lpValueNameW, L"TrustedHostsList"))
        {
            if (lpType)
                *lpType = REG_SZ;

            if (lpData && lpcbData)
            {
                if (*lpcbData >= 4)
                {
                    WCHAR* lpDataW = (WCHAR*)lpData;
                    lpDataW[0] = L'*';
                    lpDataW[1] = 0;
                    *lpcbData = 4;
                    return lstatus;
                }
            }
            else
            {
                if (lpcbData)
                    *lpcbData = 4;
                return ERROR_MORE_DATA;
            }
        }
    }

    lstatus = Real_RegQueryValueExW(hKey, lpValueNameW, lpReserved, lpType, lpData, lpcbData);

    //free(lpValueNameA);
    return lstatus;
}

uint32_t Jetify_AttachHooks()
{
    LONG error;
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    JETIFY_DETOUR_ATTACH(Real_WinHttpOpen, Hook_WinHttpOpen);
    JETIFY_DETOUR_ATTACH(Real_WinHttpConnect, Hook_WinHttpConnect);
    JETIFY_DETOUR_ATTACH(Real_WinHttpSetOption, Hook_WinHttpSetOption);
    JETIFY_DETOUR_ATTACH(Real_WinHttpOpenRequest, Hook_WinHttpOpenRequest);
    JETIFY_DETOUR_ATTACH(Real_WinHttpCloseHandle, Hook_WinHttpCloseHandle);

    g_hKernelBase = GetModuleHandleA("KernelBase.dll");
    g_hAdvapi32 = GetModuleHandleA("advapi32.dll");

    if (g_hKernelBase)
    {
        Real_RegOpenKeyExW = (Func_RegOpenKeyExW)GetProcAddress(g_hKernelBase, "RegOpenKeyExW");
        Real_RegQueryValueExW = (Func_RegQueryValueExW)GetProcAddress(g_hKernelBase, "RegQueryValueExW");
    }

    if (g_hAdvapi32)
    {
        if (!Real_RegOpenKeyExW)
            Real_RegOpenKeyExW = (Func_RegOpenKeyExW)GetProcAddress(g_hAdvapi32, "RegOpenKeyExW");

        if (!Real_RegQueryValueExW)
            Real_RegQueryValueExW = (Func_RegQueryValueExW)GetProcAddress(g_hAdvapi32, "RegQueryValueExW");
    }


    if (Real_RegOpenKeyExW)
    {
        JETIFY_DETOUR_ATTACH(Real_RegOpenKeyExW, Hook_RegOpenKeyExW);
    }

    if (Real_RegQueryValueExW)
    {
        JETIFY_DETOUR_ATTACH(Real_RegQueryValueExW, Hook_RegQueryValueExW);
    }

    error = DetourTransactionCommit();
    return (uint32_t) error;
}

uint32_t Jetify_DetachHooks()
{
    LONG error;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    JETIFY_DETOUR_DETACH(Real_WinHttpOpen, Hook_WinHttpOpen);
    JETIFY_DETOUR_DETACH(Real_WinHttpConnect, Hook_WinHttpConnect);
    JETIFY_DETOUR_DETACH(Real_WinHttpSetOption, Hook_WinHttpSetOption);
    JETIFY_DETOUR_DETACH(Real_WinHttpOpenRequest, Hook_WinHttpOpenRequest);
    JETIFY_DETOUR_DETACH(Real_WinHttpCloseHandle, Hook_WinHttpCloseHandle);

    if (Real_RegOpenKeyExW)
    {
        JETIFY_DETOUR_DETACH(Real_RegOpenKeyExW, Hook_RegOpenKeyExW);
    }

    if (Real_RegQueryValueExW)
    {
        JETIFY_DETOUR_DETACH(Real_RegQueryValueExW, Hook_RegQueryValueExW);
    }
    
    error = DetourTransactionCommit();
    return (uint32_t)error;
}
