#include "pch.h"
#include "utilities.h"


modInfo copyModule(std::string name)
{
	modInfo ret;
	ret.name = name;
	ret.base = (unsigned char*)GetModuleHandleA(name.c_str());
	
	if (!ret.base)
		return ret;
	IMAGE_NT_HEADERS* ntHeader = PIMAGE_NT_HEADERS(ret.base + PIMAGE_DOS_HEADER(ret.base)->e_lfanew);
	ret.size = ntHeader->OptionalHeader.SizeOfImage;
	ret.baseCpy = (unsigned char*)malloc(ret.size);
	if (!ret.baseCpy)
		return ret;
	memcpy(ret.baseCpy, ret.base, ret.size);

	std::cout << ret.name << ":" << std::endl;
	std::cout << "Base: " << std::hex << (DWORD64)ret.base << std::endl;
	std::cout << "Cpy: " << std::hex << (DWORD64)ret.baseCpy << std::endl;
	std::cout << "Size: " << std::hex << (DWORD64)ret.size << std::endl;
	return ret;
}

bool changeImageBase(modInfo& obj)
{
	PEB* peb = (PEB*)__readgsqword(0x60);
	LDR_DATA_TABLE_ENTRY *cur = (LDR_DATA_TABLE_ENTRY*)peb->Ldr->InLoadOrderModuleList.Flink;


	//LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(head.Flink, LDR_DATA_TABLE_ENTRY, );
	while (cur && cur->DllBase != NULL)
	{
		DWORD oldProtect;
		VirtualProtect(cur, sizeof(LDR_DATA_TABLE_ENTRY), PAGE_EXECUTE_READWRITE, &oldProtect);
		if (cur->DllBase == obj.base)
		{
			cur->DllBase = obj.baseCpy;
			return true;
		}
		VirtualProtect(cur, sizeof(LDR_DATA_TABLE_ENTRY), oldProtect, &oldProtect);
		cur = (LDR_DATA_TABLE_ENTRY*)cur->InLoadOrderLinks.Flink;
	}
	return false;
}

std::wstring findNtdllTmpName()
{
	{
		PEB* peb = (PEB*)__readgsqword(0x60);
		LDR_DATA_TABLE_ENTRY* cur = (LDR_DATA_TABLE_ENTRY*)peb->Ldr->InLoadOrderModuleList.Flink;


		//LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(head.Flink, LDR_DATA_TABLE_ENTRY, );
		while (cur && cur->DllBase != NULL)
		{
			std::wstring cmp = cur->BaseDllName.Buffer;

			if (cmp.find(L"tmp") != std::string::npos && cur->SizeOfImage == 0x1f8000)
			{
				std::wcout << cmp << std::endl;
				return cur->BaseDllName.Buffer;
			}
			cur = (LDR_DATA_TABLE_ENTRY*)cur->InLoadOrderLinks.Flink;
		}
		return L"";
	}
}

std::wstring findKernelTmpName()
{
	{
		PEB* peb = (PEB*)__readgsqword(0x60);
		LDR_DATA_TABLE_ENTRY* cur = (LDR_DATA_TABLE_ENTRY*)peb->Ldr->InLoadOrderModuleList.Flink;


		//LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(head.Flink, LDR_DATA_TABLE_ENTRY, );
		while (cur && cur->DllBase != NULL)
		{
			std::wstring cmp = cur->BaseDllName.Buffer;

			if (cmp.find(L"tmp") != std::string::npos && cur->SizeOfImage == 0x2d2000)
			{
				std::wcout << cmp << std::endl;
				return cur->BaseDllName.Buffer;
			}
			cur = (LDR_DATA_TABLE_ENTRY*)cur->InLoadOrderLinks.Flink;
		}
		return L"";
	}
}

HANDLE getTmpHandle(std::wstring name)
{
//C:\Users\Brain\AppData\Local\Temp\BC4CD7.tmp
	name = L"C:/Users/Brain/AppData/Local/Temp/" + name;
	HANDLE hndl;
	do {
		hndl = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		std::cout << "HANDLE : " << hndl << std::endl;
	} while (hndl == INVALID_HANDLE_VALUE);
	return (hndl);
}

std::wstring s2ws(const std::string& str)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(str);
}

std::string ws2s(const std::wstring& wstr)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(wstr);
}