#include "pch.h"
#include "BlackCipher.h"

modInfo* ntdllInfo = new modInfo;
modInfo* kernel32Info = new modInfo;
modInfo* blackCipherInfo = new modInfo;
modInfo* tmpNtdllInfo = new modInfo;

std::wstring NtdllTmpName = findNtdllTmpName();
std::wstring kernel32TmpName = findKernelTmpName();

namespace BlackCipher
{
    void DumpModules()
    {
        dumpModuleToFile("ntdll.dll");
        dumpModuleToFile(ws2s(NtdllTmpName));
        dumpModuleToFile("BlackCipher64.aes");
    }

    void ActivateDetours()
    {
        x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "ZwMapViewOfSection"), (DWORD64)ZwMapViewOfSection_Hook);
        x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwOpenProcess"), (DWORD64)ZwOpenProcess_Hook);
        x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "NtReadVirtualMemory"), (DWORD64)NtReadVirtualMemory_Hook);

        //x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "ZwMapViewOfSection"), (DWORD64)ZwMapViewOfSection_Hook);
       //x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "ZwOpenProcess"), (DWORD64)ZwOpenProcess_Hook);
        //x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "NtReadFile"), (DWORD64)NtReadFile_hook);
    }

        void BlackCipherMain()
        {
        AllocConsole();
        FILE* fl;
        freopen_s(&fl, "CONOUT$", "w", stdout);

        *ntdllInfo = copyModule("ntdll.dll");
        *tmpNtdllInfo = copyModule(ws2s(NtdllTmpName));
        *blackCipherInfo = copyModule("BlackCipher64.aes");

        BlackCipher::DumpModules();
        BlackCipher::ActivateDetours();
        getExternBaseAddr("MapleStory.exe");
    }


}

//HANDLE tmp = OpenFileMappingW(
//    FILE_MAP_ALL_ACCESS,
//    true,
//    L"ntdll.dll_tmp");
//LPCTSTR pBuf;
//pBuf = (LPTSTR)MapViewOfFile(tmp, // handle to map object
//    FILE_MAP_ALL_ACCESS,  // read/write permission
//    0,
//    0,
//    1333337);