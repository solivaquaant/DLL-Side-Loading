#include "pch.h"
#include <windows.h>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

#pragma comment(linker, "/export:curl_easy_cleanup=gup.curl_easy_cleanup,@1")
#pragma comment(linker, "/export:curl_easy_init=gup.curl_easy_init,@6")
#pragma comment(linker, "/export:curl_easy_perform=gup.curl_easy_perform,@12")
#pragma comment(linker, "/export:curl_easy_setopt=gup.curl_easy_setopt,@16")


DWORD WINAPI DoMagic(LPVOID lpParameter)
{
    MessageBoxA(NULL, "Group-CK13", "Simple DLL 03", MB_OK | MB_ICONEXCLAMATION);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
)
{
    HANDLE threadHandle;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        threadHandle = CreateThread(NULL, 0, DoMagic, NULL, 0, NULL);
        CloseHandle(threadHandle);
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
