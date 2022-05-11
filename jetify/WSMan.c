
#include "WSMan.h"

#include <string.h>

#include "Logger.h"
#include "Utils.h"

typedef uint32_t(WSMANAPI* fnWSManInitialize)(uint32_t flags, WSMAN_API_HANDLE* apiHandle);

typedef uint32_t(WSMANAPI* fnWSManDeinitialize)(WSMAN_API_HANDLE apiHandle, uint32_t flags);

typedef uint32_t(WSMANAPI* fnWSManGetErrorMessage)(WSMAN_API_HANDLE apiHandle,
    uint32_t flags, const WCHAR* languageCode, uint32_t errorCode,
    uint32_t messageLength, WCHAR* message, uint32_t* messageLengthUsed);

typedef uint32_t(WSMANAPI* fnWSManCreateSession)(WSMAN_API_HANDLE apiHandle,
    const WCHAR* connection, uint32_t flags,
    WSMAN_AUTHENTICATION_CREDENTIALS* serverAuthenticationCredentials,
    WSMAN_PROXY_INFO* proxyInfo, WSMAN_SESSION_HANDLE* session);

typedef uint32_t(WSMANAPI* fnWSManCloseSession)(WSMAN_SESSION_HANDLE session, uint32_t flags);

typedef uint32_t(WSMANAPI* fnWSManSetSessionOption)(WSMAN_SESSION_HANDLE session,
    WSManSessionOption option, WSMAN_DATA* data);

typedef uint32_t(WSMANAPI* fnWSManGetSessionOptionAsDword)(WSMAN_SESSION_HANDLE session,
    WSManSessionOption option, uint32_t* value);

typedef uint32_t(WSMANAPI* fnWSManGetSessionOptionAsString)(WSMAN_SESSION_HANDLE session,
    WSManSessionOption option, uint32_t stringLength, WCHAR* string, uint32_t* stringLengthUsed);

typedef uint32_t (WSMANAPI * fnWSManCloseOperation)(WSMAN_OPERATION_HANDLE operationHandle, uint32_t flags);

typedef void (WSMANAPI* fnWSManSignalShell)(WSMAN_SHELL_HANDLE shell,
    WSMAN_COMMAND_HANDLE command, uint32_t flags, const WCHAR* code,
    WSMAN_SHELL_ASYNC* async, WSMAN_OPERATION_HANDLE* signalOperation);

typedef void (WSMANAPI* fnWSManReceiveShellOutput)(WSMAN_SHELL_HANDLE shell,
    WSMAN_COMMAND_HANDLE command, uint32_t flags,
    WSMAN_STREAM_ID_SET* desiredStreamSet, WSMAN_SHELL_ASYNC* async,
    WSMAN_OPERATION_HANDLE* receiveOperation);

typedef void (WSMANAPI* fnWSManSendShellInput)(WSMAN_SHELL_HANDLE shell,
    WSMAN_COMMAND_HANDLE command, uint32_t flags, const WCHAR* streamId,
    WSMAN_DATA* streamData, BOOL endOfStream, WSMAN_SHELL_ASYNC* async,
    WSMAN_OPERATION_HANDLE* sendOperation);

typedef void (WSMANAPI* fnWSManCloseCommand)(WSMAN_COMMAND_HANDLE commandHandle,
    uint32_t flags, WSMAN_SHELL_ASYNC* async);

typedef void (WSMANAPI* fnWSManCloseShell)(WSMAN_SHELL_HANDLE shellHandle,
    uint32_t flags, WSMAN_SHELL_ASYNC* async);

typedef void (WSMANAPI* fnWSManCreateShellEx)(WSMAN_SESSION_HANDLE session,
    uint32_t flags, const WCHAR* resourceUri, const WCHAR* shellId,
    WSMAN_SHELL_STARTUP_INFO* startupInfo,
    WSMAN_OPTION_SET* options, WSMAN_DATA* createXml,
    WSMAN_SHELL_ASYNC* async, WSMAN_SHELL_HANDLE* shell);

typedef void (WSMANAPI * fnWSManRunShellCommandEx)(WSMAN_SHELL_HANDLE shell,
    uint32_t flags, const WCHAR* commandId, const WCHAR* commandLine,
    WSMAN_COMMAND_ARG_SET* args, WSMAN_OPTION_SET* options,
    WSMAN_SHELL_ASYNC* async, WSMAN_COMMAND_HANDLE* command);

typedef void (WSMANAPI * fnWSManDisconnectShell)(WSMAN_SHELL_HANDLE shell, uint32_t flags,
    WSMAN_SHELL_DISCONNECT_INFO* disconnectInfo, WSMAN_SHELL_ASYNC* async);

typedef void (WSMANAPI * fnWSManReconnectShell)(WSMAN_SHELL_HANDLE shell,
    uint32_t flags, WSMAN_SHELL_ASYNC* async);

typedef void (WSMANAPI * fnWSManReconnectShellCommand)(WSMAN_COMMAND_HANDLE commandHandle,
    uint32_t flags, WSMAN_SHELL_ASYNC* async);

typedef void (WSMANAPI * fnWSManConnectShell)(WSMAN_SESSION_HANDLE session,
    uint32_t flags, const WCHAR* resourceUri, const WCHAR* shellID,
    WSMAN_OPTION_SET* options, WSMAN_DATA* connectXml,
    WSMAN_SHELL_ASYNC* async, WSMAN_SHELL_HANDLE* shell);

typedef void (WSMANAPI * fnWSManConnectShellCommand)(WSMAN_SHELL_HANDLE shell,
    uint32_t flags, const WCHAR* commandID,
    WSMAN_OPTION_SET* options, WSMAN_DATA* connectXml,
    WSMAN_SHELL_ASYNC* async, WSMAN_COMMAND_HANDLE* command);

typedef struct
{
    HMODULE hModule;
    fnWSManInitialize WSManInitialize;
    fnWSManDeinitialize WSManDeinitialize;
    fnWSManGetErrorMessage WSManGetErrorMessage;
    fnWSManCreateSession WSManCreateSession;
    fnWSManCloseSession WSManCloseSession;
    fnWSManSetSessionOption WSManSetSessionOption;
    fnWSManGetSessionOptionAsDword WSManGetSessionOptionAsDword;
    fnWSManGetSessionOptionAsString WSManGetSessionOptionAsString;
    fnWSManCloseOperation WSManCloseOperation;
    fnWSManSignalShell WSManSignalShell;
    fnWSManReceiveShellOutput WSManReceiveShellOutput;
    fnWSManSendShellInput WSManSendShellInput;
    fnWSManCloseCommand WSManCloseCommand;
    fnWSManCloseShell WSManCloseShell;
    fnWSManCreateShellEx WSManCreateShellEx;
    fnWSManRunShellCommandEx WSManRunShellCommandEx;
    fnWSManDisconnectShell WSManDisconnectShell;
    fnWSManReconnectShell WSManReconnectShell;
    fnWSManReconnectShellCommand WSManReconnectShellCommand;
    fnWSManConnectShell WSManConnectShell;
    fnWSManConnectShellCommand WSManConnectShellCommand;
} WSManDll;

static WSManDll g_WSManDll = { 0 };

#ifndef _WIN32
#include <dlfcn.h>

static HMODULE LoadLibraryA(const char* filename)
{
	return (HMODULE) dlopen(filename, RTLD_LOCAL | RTLD_LAZY);
}

static void* GetProcAddress(HMODULE hModule, const char* procName)
{
	return dlsym(hModule, procName);
}

static BOOL FreeLibrary(HMODULE hModule)
{
	return (dlclose(hModule) == 0) ? TRUE : FALSE;
}
#endif

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

bool WSManDll_ShouldInit()
{
    char libraryFilePath[JETIFY_MAX_PATH] = { 0 };
    GetModuleFileNameA((HINSTANCE)&__ImageBase, libraryFilePath, JETIFY_MAX_PATH);

    Jetify_LogPrint(DEBUG, "WSMan_ShouldInit: %s", libraryFilePath);

    const char* filename = Jetify_FileBase(libraryFilePath);

    if (!filename)
        return false;

    if (Jetify_StringIEquals(filename, "WsmSvc.dll")) {
        return true;
    }

    return false;
}

bool WSManDll_Init()
{
    HMODULE hModule;
    char filename[1024];
    WSManDll* dll = &g_WSManDll;

    memset(dll, 0, sizeof(WSManDll));

    if (!WSManDll_ShouldInit()) {
        return true;
    }

#ifdef _WIN32
    ExpandEnvironmentStringsA("%SystemRoot%\\System32\\WsmSvc.dll", filename, sizeof(filename));
#endif

    hModule = LoadLibraryA(filename);

    if (!hModule)
        return false;

    dll->hModule = hModule;
    dll->WSManInitialize = (fnWSManInitialize)GetProcAddress(hModule, "WSManInitialize");
    dll->WSManDeinitialize = (fnWSManDeinitialize)GetProcAddress(hModule, "WSManDeinitialize");
    dll->WSManGetErrorMessage = (fnWSManGetErrorMessage)GetProcAddress(hModule, "WSManGetErrorMessage");
    dll->WSManCreateSession = (fnWSManCreateSession)GetProcAddress(hModule, "WSManCreateSession");
    dll->WSManCloseSession = (fnWSManCloseSession)GetProcAddress(hModule, "WSManCloseSession");
    dll->WSManSetSessionOption = (fnWSManSetSessionOption)GetProcAddress(hModule, "WSManSetSessionOption");
    dll->WSManGetSessionOptionAsDword = (fnWSManGetSessionOptionAsDword)GetProcAddress(hModule, "WSManGetSessionOptionAsDword");
    dll->WSManGetSessionOptionAsString = (fnWSManGetSessionOptionAsString)GetProcAddress(hModule, "WSManGetSessionOptionAsString");
    dll->WSManCloseOperation = (fnWSManCloseOperation)GetProcAddress(hModule, "WSManCloseOperation");
    dll->WSManSignalShell = (fnWSManSignalShell)GetProcAddress(hModule, "WSManSignalShell");
    dll->WSManReceiveShellOutput = (fnWSManReceiveShellOutput)GetProcAddress(hModule, "WSManReceiveShellOutput");
    dll->WSManSendShellInput = (fnWSManSendShellInput)GetProcAddress(hModule, "WSManSendShellInput");
    dll->WSManCloseCommand = (fnWSManCloseCommand)GetProcAddress(hModule, "WSManCloseCommand");
    dll->WSManCloseShell = (fnWSManCloseShell)GetProcAddress(hModule, "WSManCloseShell");
    dll->WSManCreateShellEx = (fnWSManCreateShellEx)GetProcAddress(hModule, "WSManCreateShellEx");
    dll->WSManRunShellCommandEx = (fnWSManRunShellCommandEx)GetProcAddress(hModule, "WSManRunShellCommandEx");
    dll->WSManDisconnectShell = (fnWSManDisconnectShell)GetProcAddress(hModule, "WSManDisconnectShell");
    dll->WSManReconnectShell = (fnWSManReconnectShell)GetProcAddress(hModule, "WSManReconnectShell");
    dll->WSManReconnectShellCommand = (fnWSManReconnectShellCommand)GetProcAddress(hModule, "WSManReconnectShellCommand");
    dll->WSManConnectShell = (fnWSManConnectShell)GetProcAddress(hModule, "WSManConnectShell");
    dll->WSManConnectShellCommand = (fnWSManConnectShellCommand)GetProcAddress(hModule, "WSManConnectShellCommand");

    return true;
}

void WSManDll_Uninit()
{
    WSManDll* dll = &g_WSManDll;

    if (dll->hModule) {
        FreeLibrary(dll->hModule);
        dll->hModule = NULL;
    }

    memset(dll, 0, sizeof(WSManDll));
}

uint32_t WSManInitialize(uint32_t flags, WSMAN_API_HANDLE* apiHandle)
{
    uint32_t status;
    status = g_WSManDll.WSManInitialize(flags, apiHandle);
    Jetify_LogPrint(DEBUG, "WSManInitialize");
    return status;
}

uint32_t WSManDeinitialize(WSMAN_API_HANDLE apiHandle, uint32_t flags)
{
    uint32_t status;
    status = g_WSManDll.WSManDeinitialize(apiHandle, flags);
    Jetify_LogPrint(DEBUG, "WSManDeinitialize");
    return status;
}

uint32_t WSManGetErrorMessage(WSMAN_API_HANDLE apiHandle,
    uint32_t flags, const WCHAR* languageCode, uint32_t errorCode,
    uint32_t messageLength, WCHAR* message, uint32_t* messageLengthUsed)
{
    uint32_t status;
    status = g_WSManDll.WSManGetErrorMessage(apiHandle, flags, languageCode, errorCode, messageLength, message, messageLengthUsed);
    return status;
}

uint32_t WSManCreateSession(WSMAN_API_HANDLE apiHandle,
    const WCHAR* connection, uint32_t flags,
    WSMAN_AUTHENTICATION_CREDENTIALS* serverAuthenticationCredentials,
    WSMAN_PROXY_INFO* proxyInfo, WSMAN_SESSION_HANDLE* session)
{
    uint32_t status;
    status = g_WSManDll.WSManCreateSession(apiHandle, connection, flags, serverAuthenticationCredentials, proxyInfo, session);
    Jetify_LogPrint(DEBUG, "WSManCreateSession");
    return status;
}

uint32_t WSManCloseSession(WSMAN_SESSION_HANDLE session, uint32_t flags)
{
    uint32_t status;
    status = g_WSManDll.WSManCloseSession(session, flags);
    Jetify_LogPrint(DEBUG, "WSManCloseSession");
    return status;
}

uint32_t WSManSetSessionOption(WSMAN_SESSION_HANDLE session,
    WSManSessionOption option, WSMAN_DATA* data)
{
    uint32_t status;
    status = g_WSManDll.WSManSetSessionOption(session, option, data);
    Jetify_LogPrint(DEBUG, "WSManSetSessionOption");
    return status;
}

uint32_t WSManGetSessionOptionAsDword(WSMAN_SESSION_HANDLE session,
    WSManSessionOption option, uint32_t* value)
{
    uint32_t status;
    status = g_WSManDll.WSManGetSessionOptionAsDword(session, option, value);
    Jetify_LogPrint(DEBUG, "WSManGetSessionOptionAsDword");
    return status;
}

uint32_t WSManGetSessionOptionAsString(WSMAN_SESSION_HANDLE session,
    WSManSessionOption option, uint32_t stringLength, WCHAR* string, uint32_t* stringLengthUsed)
{
    uint32_t status;
    status = g_WSManDll.WSManGetSessionOptionAsString(session, option, stringLength, string, stringLengthUsed);
    Jetify_LogPrint(DEBUG, "WSManGetSessionOptionAsString");
    return status;
}

uint32_t WSManCloseOperation(WSMAN_OPERATION_HANDLE operationHandle, uint32_t flags)
{
    uint32_t status;
    status = g_WSManDll.WSManCloseOperation(operationHandle, flags);
    Jetify_LogPrint(DEBUG, "WSManCloseOperation");
    return status;
}

void WSManSignalShell(WSMAN_SHELL_HANDLE shell,
    WSMAN_COMMAND_HANDLE command, uint32_t flags, const WCHAR* code,
    WSMAN_SHELL_ASYNC* async, WSMAN_OPERATION_HANDLE* signalOperation)
{
    g_WSManDll.WSManSignalShell(shell, command, flags, code, async, signalOperation);
    Jetify_LogPrint(DEBUG, "WSManSignalShell");
}

void WSManReceiveShellOutput(WSMAN_SHELL_HANDLE shell,
    WSMAN_COMMAND_HANDLE command, uint32_t flags,
    WSMAN_STREAM_ID_SET* desiredStreamSet, WSMAN_SHELL_ASYNC* async,
    WSMAN_OPERATION_HANDLE* receiveOperation)
{
    g_WSManDll.WSManReceiveShellOutput(shell, command, flags, desiredStreamSet, async, receiveOperation);
    Jetify_LogPrint(DEBUG, "WSManReceiveShellOutput");
}

void WSManSendShellInput(WSMAN_SHELL_HANDLE shell,
    WSMAN_COMMAND_HANDLE command, uint32_t flags, const WCHAR* streamId,
    WSMAN_DATA* streamData, BOOL endOfStream, WSMAN_SHELL_ASYNC* async,
    WSMAN_OPERATION_HANDLE* sendOperation)
{
    g_WSManDll.WSManSendShellInput(shell, command, flags, streamId, streamData, endOfStream, async, sendOperation);
    Jetify_LogPrint(DEBUG, "WSManSendShellInput");
}

void WSManCloseCommand(WSMAN_COMMAND_HANDLE commandHandle,
    uint32_t flags, WSMAN_SHELL_ASYNC* async)
{
    g_WSManDll.WSManCloseCommand(commandHandle, flags, async);
    Jetify_LogPrint(DEBUG, "WSManCloseCommand");
}

void WSManCloseShell(WSMAN_SHELL_HANDLE shellHandle,
    uint32_t flags, WSMAN_SHELL_ASYNC* async)
{
    g_WSManDll.WSManCloseShell(shellHandle, flags, async);
    Jetify_LogPrint(DEBUG, "WSManCloseShell");
}

void WSManCreateShellEx(WSMAN_SESSION_HANDLE session,
    uint32_t flags, const WCHAR* resourceUri, const WCHAR* shellId,
    WSMAN_SHELL_STARTUP_INFO* startupInfo,
    WSMAN_OPTION_SET* options, WSMAN_DATA* createXml,
    WSMAN_SHELL_ASYNC* async, WSMAN_SHELL_HANDLE* shell)
{
    g_WSManDll.WSManCreateShellEx(session, flags, resourceUri, shellId, startupInfo, options, createXml, async, shell);
    Jetify_LogPrint(DEBUG, "WSManCreateShellEx");
}

void WSManRunShellCommandEx(WSMAN_SHELL_HANDLE shell,
    uint32_t flags, const WCHAR* commandId, const WCHAR* commandLine,
    WSMAN_COMMAND_ARG_SET* args, WSMAN_OPTION_SET* options,
    WSMAN_SHELL_ASYNC* async, WSMAN_COMMAND_HANDLE* command)
{
    g_WSManDll.WSManRunShellCommandEx(shell, flags, commandId, commandLine, args, options, async, command);
    Jetify_LogPrint(DEBUG, "WSManRunShellCommandEx");
}

void WSManDisconnectShell(WSMAN_SHELL_HANDLE shell, uint32_t flags,
    WSMAN_SHELL_DISCONNECT_INFO* disconnectInfo, WSMAN_SHELL_ASYNC* async)
{
    g_WSManDll.WSManDisconnectShell(shell, flags, disconnectInfo, async);
    Jetify_LogPrint(DEBUG, "WSManDisconnectShell");
}

void WSManReconnectShell(WSMAN_SHELL_HANDLE shell,
    uint32_t flags, WSMAN_SHELL_ASYNC* async)
{
    g_WSManDll.WSManReconnectShell(shell, flags, async);
    Jetify_LogPrint(DEBUG, "WSManReconnectShell");
}

void WSManReconnectShellCommand(WSMAN_COMMAND_HANDLE commandHandle,
    uint32_t flags, WSMAN_SHELL_ASYNC* async)
{
    g_WSManDll.WSManReconnectShellCommand(commandHandle, flags, async);
    Jetify_LogPrint(DEBUG, "WSManReconnectShellCommand");
}

void WSManConnectShell(WSMAN_SESSION_HANDLE session,
    uint32_t flags, const WCHAR* resourceUri, const WCHAR* shellId,
    WSMAN_OPTION_SET* options, WSMAN_DATA* connectXml,
    WSMAN_SHELL_ASYNC* async, WSMAN_SHELL_HANDLE* shell)
{
    g_WSManDll.WSManConnectShell(session, flags, resourceUri, shellId, options, connectXml, async, shell);
    Jetify_LogPrint(DEBUG, "WSManConnectShell");
}

void WSManConnectShellCommand(WSMAN_SHELL_HANDLE shell,
    uint32_t flags, const WCHAR* commandId,
    WSMAN_OPTION_SET* options, WSMAN_DATA* connectXml,
    WSMAN_SHELL_ASYNC* async, WSMAN_COMMAND_HANDLE* command)
{
    g_WSManDll.WSManConnectShellCommand(shell, flags, commandId, options, connectXml, async, command);
    Jetify_LogPrint(DEBUG, "WSManConnectShellCommand");
}
