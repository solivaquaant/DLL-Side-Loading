
#include "pch.h"
#include <windows.h>

extern "C" __declspec(dllexport) PVOID curl_easy_init()
{
    return NULL;
}
extern "C" __declspec(dllexport) PVOID curl_easy_setopt()
{
    return NULL;
}
extern "C" __declspec(dllexport) PVOID curl_easy_cleanup()
{
    return NULL;
}
extern "C" __declspec(dllexport) PVOID curl_easy_perform()
{
    return NULL;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Group-CK13", "Simple DLL 02", MB_OK | MB_ICONEXCLAMATION);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}