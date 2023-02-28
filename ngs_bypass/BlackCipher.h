#pragma once
#include "utilities.h"
#include "hooks.h"
#include <locale>
#include <codecvt>
#include <DbgHelp.h>
#include <tchar.h>
#include <iostream>
#include <fstream>

namespace BlackCipher
{

	void DumpModules();
	void ActivateDetours();
	void BlackCipherMain();
}