#include "pch.h"
#include "MapleStory.h"

modInfoNew *Maple_BCNtdllInfos = new modInfoNew;
modInfoNew *Maple_BCBlackCipherInfos = new modInfoNew;
modInfoNew *Maple_BCNtdllTmpInfos = new modInfoNew;

modInfo* Maple_MapleCpy = new modInfo;
modInfo* Maple_MsNtdllTmpCpy = new modInfo;

namespace MapleStory
{

    void DumpModules()
    {
        dumpModuleToFile("maplestory.exe");
    }

    void ActivateDetours()
    {
        x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "ZwMapViewOfSection"), (DWORD64)ZwMapViewOfSection_Hook);
        x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "NtReadVirtualMemory"), (DWORD64)NtReadVirtualMemory_MS_Hook);
    }

    void getBcInfos()
    {
        DWORD BCPid = getProcID(L"BlackCipher64.aes");
        if (BCPid)
        {
            *Maple_BCNtdllTmpInfos = getExternNtdlTmpInfos(BCPid);
            *Maple_BCNtdllInfos = getExternBaseAddr("ntdll.dll", BCPid);
            *Maple_BCBlackCipherInfos = getExternBaseAddr("BlackCipher64.aes", BCPid);
        }
        else
            std::cout << "Couldnt get BlackCipher64 PID" << std::endl;
    }

    void MapleStoryMain()
    {
        AllocConsole();
        FILE* fl;
        freopen_s(&fl, "CONOUT$", "w", stdout);
        std::cout << "Inside Maplestory" << std::endl;

        *Maple_MapleCpy = copyModule("maplestory.exe");
        *Maple_MsNtdllTmpCpy = copyModule(ws2s(NtdllTmpName));

        MapleStory::DumpModules();
        MapleStory::getBcInfos();
        MapleStory::ActivateDetours();
        
    }


}




//x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "ZwMapViewOfSection"), (DWORD64)ZwMapViewOfSection_Hook);
//x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "ZwOpenProcess"), (DWORD64)ZwOpenProcess_Hook);
 //x64_detour((DWORD64*)GetProcAddress(GetModuleHandleW(NtdllTmpName.c_str()), "NtReadFile"), (DWORD64)NtReadFile_hook);