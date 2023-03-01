// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "BlackCipher.h"
#include "MapleStory.h"
#include <string>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        AllocConsole();
        FILE* fl;
        freopen_s(&fl, "CONOUT$", "w", stdout);

        char moduleFileName[MAX_PATH];
        GetModuleFileNameA(GetModuleHandle(NULL), moduleFileName, MAX_PATH);
        std::string procName = moduleFileName;

        //std::cout << procName << std::endl;
        if (procName.find("maplestory.exe") != std::string::npos)
            MapleStory::MapleStoryMain();
        else if (procName.find("BlackCipher64.aes") != std::string::npos)
            BlackCipher::BlackCipherMain();
        else
            std::cout << "not injected into MapleStory.exe or BlackCipher64.aes" << std::endl;
        
        //getExternBaseAddr("BlackCipher64.aes", procId);

    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
