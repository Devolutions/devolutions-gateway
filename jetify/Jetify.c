
#include "Jetify.h"

#include "Logger.h"
#include "ApiHooks.h"

#include "WSMan.h"

bool Jetify_Init()
{
    Jetify_LogOpen();

#ifdef _WIN32
    Jetify_AttachHooks();
#endif

    WSManDll_Init();

    return true;
}

void Jetify_Uninit()
{
    WSManDll_Uninit();

#ifdef _WIN32
    Jetify_DetachHooks();
#endif

    Jetify_LogClose();
}

#ifdef _WIN32
#include <detours.h>

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID reserved)
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            Jetify_Init();
            break;

        case DLL_PROCESS_DETACH:
            Jetify_Uninit();
            break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;
    }

    return TRUE;
}
#endif
