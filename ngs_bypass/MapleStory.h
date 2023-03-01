#pragma once
#include "hooks.h"
#include "utilities.h"

extern std::wstring NtdllTmpName;
namespace MapleStory
{

    void DumpModules();
    void ActivateDetours();
    void getBcInfos();
    void MapleStoryMain();
}