// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "BlackCipher.h"
#include <string>

void MapleStoryMain()
{

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        char moduleFileName[MAX_PATH];
        GetModuleFileNameA(GetModuleHandle(NULL), moduleFileName, MAX_PATH);
        std::string procName = moduleFileName;

        if (procName.find("MapleStory.exe") != std::string::npos)
            MapleStoryMain();
        else if (procName.find("BlackCipher64.aes") != std::string::npos)
            BlackCipher::BlackCipherMain();
        else
            std::cout << "not injected into MapleStory.exe or BlackCipher64.aes" << std::endl;

    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
