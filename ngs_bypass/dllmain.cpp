// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "utilities.h"
#include "hooks.h"
#include <locale>
#include <codecvt>

modInfo *ntdllInfo = new modInfo;
modInfo *kernel32Info = new modInfo;
modInfo *blackCipherInfo = new modInfo;
modInfo *tmpNtdllInfo = new modInfo;

void mainFuncs()
{
    AllocConsole();
    FILE* fl;
    freopen_s(&fl, "CONOUT$", "w", stdout);
    //modInfo maple;
    //maple = copyModule("maplestory.exe");
    //modInfo blackcall = copyModule("BlackCall64.aes");
    std::wstring NtdllTmpName = findNtdllTmpName();
    std::wstring kernel32TmpName = findKernelTmpName();
    *blackCipherInfo = copyModule("BlackCipher64.aes");
    *ntdllInfo = copyModule("ntdll.dll");
    *kernel32Info = copyModule("kernel32.dll");
    *tmpNtdllInfo = copyModule(ws2s(NtdllTmpName));



    x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "ZwMapViewOfSection"), (DWORD64)ZwMapViewOfSection_Hook);
    //x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "ZwOpenProcess"), (DWORD64)ZwOpenProcess_Hook);
    x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwOpenProcess"), (DWORD64)ZwOpenProcess_Hook);

    //x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "NtReadFile"), (DWORD64)NtReadFile_hook);
    x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "NtReadVirtualMemory"), (DWORD64)NtReadVirtualMemory_Hook);
    //modInfo ntdllTmpInf = copyModule(ws2s(NtdllTmpName));
    //changeImageBase(ntdllTmpInf);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        mainFuncs();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
