#include "pch.h"
#include "BlackCipher.h"

modInfoNew* BC_MapleInfos = new modInfoNew;
modInfoNew* BC_MapleNtdllTmpInfos = new modInfoNew;

modInfo *ntdllInfo = new modInfo;
modInfo *tmpNtdllInfo = new modInfo;

std::wstring NtdllTmpName = findNtdllTmpName();

namespace BlackCipher
{
    void DumpModules()
    {
        dumpModuleToFile("ntdll.dll");
        dumpModuleToFile("BlackCipher64.aes");
    }

    void getMapleInfos()
    {
        DWORD BCPid = getProcID(L"MapleStory.exe");
        if (BCPid)
        {
            *BC_MapleNtdllTmpInfos = getExternNtdlTmpInfos(BCPid);
            *BC_MapleInfos = getExternBaseAddr("maplestory.exe", BCPid);
        }
        else
            std::cout << "Couldnt get Maples PID" << std::endl;
    }

    void ActivateDetours()
    {
        x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "ZwMapViewOfSection"), (DWORD64)ZwMapViewOfSection_Hook);
        x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "ZwOpenProcess"), (DWORD64)ZwOpenProcess_Hook);
        x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "NtReadVirtualMemory"), (DWORD64)NtReadVirtualMemory_BC_Hook);
        //x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwOpenProcess"), (DWORD64)ZwOpenProcess_Hook);
    }

        void BlackCipherMain()
        {
        AllocConsole();
        FILE* fl;
        freopen_s(&fl, "CONOUT$", "w", stdout);
        std::cout << "Inside BlackCipher" << std::endl;

        *ntdllInfo = copyModule("ntdll.dll");
        *tmpNtdllInfo = copyModule(ws2s(NtdllTmpName));

        BlackCipher::DumpModules();
        BlackCipher::getMapleInfos();
        BlackCipher::ActivateDetours();

    }


}
