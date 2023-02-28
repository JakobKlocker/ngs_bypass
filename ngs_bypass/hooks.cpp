#include "pch.h"
#include "hooks.h"
#include <iostream>
#include <array> 
#include "ntdll.h"
#include <psapi.h>
#include "utilities.h"

typedef NTSTATUS(NTAPI* p_NtReadVirtualMemory)
(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);

p_NtReadVirtualMemory g_NtReadVirtualMemory = nullptr;

NTSTATUS NtReadVirtualMemory_Hook(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PULONG NumberOfBytesReaded)
{
    g_NtReadVirtualMemory = (p_NtReadVirtualMemory)((DWORD64)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtReadVirtualMemory"));
    char buf[256];
    GetModuleFileNameExA(ProcessHandle, NULL, buf, 256);
    std::string procName = buf;
    if (procName.find("MapleStory.exe") != std::string::npos)
    {
        std::cout << "Checking Maplestory address at " << BaseAddress << std::endl;
    }
    if ((DWORD64)ProcessHandle == 0xFFFFFFFFFFFFFFFF)
    {
        std::cout << "Reading Addr inside BC: " << (DWORD64)BaseAddress << std::endl;
        if ((DWORD64)BaseAddress >= (DWORD64)ntdllInfo->base && (DWORD64)BaseAddress <= (DWORD64)ntdllInfo->base + (DWORD64)ntdllInfo->size)
        {
            std::cout << "Redirected to ntdll Copy at :" << std::hex << (DWORD64)BaseAddress - (DWORD64)ntdllInfo->base + (DWORD64)ntdllInfo->baseCpy << std::endl;
            return(g_NtReadVirtualMemory(ProcessHandle, (PVOID)((DWORD64)BaseAddress - (DWORD64)ntdllInfo->base + (DWORD64)ntdllInfo->baseCpy), Buffer, NumberOfBytesToRead, NumberOfBytesReaded));
        }
        if ((DWORD64)BaseAddress >= (DWORD64)tmpNtdllInfo->base && (DWORD64)BaseAddress <= (DWORD64)tmpNtdllInfo->base + (DWORD64)tmpNtdllInfo->size)
        {
            std::cout << "Redirected to tmpNtdlll Copy at :" << std::hex << (DWORD64)BaseAddress - (DWORD64)tmpNtdllInfo->base + (DWORD64)tmpNtdllInfo->baseCpy << std::endl;
            return(g_NtReadVirtualMemory(ProcessHandle, (PVOID)((DWORD64)BaseAddress - (DWORD64)tmpNtdllInfo->base + (DWORD64)tmpNtdllInfo->baseCpy), Buffer, NumberOfBytesToRead, NumberOfBytesReaded));
        }
    }
    return(g_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded));
}


typedef NTSTATUS(NTAPI* p_MapViewOfFile)(    HANDLE hFileMappingObject,     DWORD  dwDesiredAccess,     
    DWORD  dwFileOffsetHigh,     DWORD  dwFileOffsetLow,     SIZE_T dwNumberOfBytesToMap);

p_MapViewOfFile g_MapViewOfFile = nullptr;

NTSTATUS MapViewOfFile_Hook(
    HANDLE hFileMappingObject,
    DWORD  dwDesiredAccess,
    DWORD  dwFileOffsetHigh,
    DWORD  dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap)
{
    g_MapViewOfFile = (p_MapViewOfFile)((DWORD64)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "MapViewOfFile"));
    char buf[256];
    GetModuleFileNameExA(hFileMappingObject, NULL, buf, 256);
    std::cout << buf << std::endl;
    return (g_MapViewOfFile(hFileMappingObject,
        dwDesiredAccess,
        dwFileOffsetHigh,
        dwFileOffsetLow,
        dwNumberOfBytesToMap));
}

typedef NTSTATUS(NTAPI* p_ZwMapViewOfSection)(
HANDLE          SectionHandle,
HANDLE          ProcessHandle,
PVOID* BaseAddress,
ULONG_PTR       ZeroBits,
SIZE_T          CommitSize,
PLARGE_INTEGER  SectionOffset,
PSIZE_T         ViewSize,
SECTION_INHERIT InheritDisposition,
ULONG           AllocationType,
ULONG           Win32Protect);

p_ZwMapViewOfSection g_ZwMapViewOfSection = nullptr;

NTSTATUS ZwMapViewOfSection_Hook(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect
)
{
    g_ZwMapViewOfSection = (p_ZwMapViewOfSection)((DWORD64)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwMapViewOfSection"));
    char buf[256];
    buf[0] = '\0';
    GetModuleFileNameExA(ProcessHandle, NULL, buf, 256);
    //std::cout << "ZWMapView" << buf << " " << (DWORD64)BaseAddress << std::endl;
    //NTSTATUS status = (g_ZwMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect));
    //std::cout << *BaseAddress << std::endl;
    return (STATUS_SECTION_PROTECTION);
    //return (g_ZwMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect));
}

typedef NTSTATUS (NTAPI *p_NtReadFile)(
         HANDLE           FileHandle,
      HANDLE           Event,
     PIO_APC_ROUTINE  ApcRoutine,
     PVOID            ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        PVOID            Buffer,
         ULONG            Length,
     PLARGE_INTEGER   ByteOffset,
     PULONG           Key
);

NTSTATUS NtReadFile_hook(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
)
{
    char buf[256];
    GetModuleFileNameExA(FileHandle, NULL, buf, 256);
    std::cout << buf << std::endl;
    return(0x1);
}


typedef NTSTATUS (NTAPI* p_ZwOpenProcess)(
              PHANDLE            ProcessHandle,
               ACCESS_MASK        DesiredAccess,
               POBJECT_ATTRIBUTES ObjectAttributes,
      PCLIENT_ID         ClientId
);

p_ZwOpenProcess g_ZwOpenProcess = nullptr;

NTSTATUS ZwOpenProcess_Hook(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
)
{
    char buf[256];
    buf[0] = '\0';
    g_ZwOpenProcess = (p_ZwOpenProcess)((DWORD64)GetProcAddress(GetModuleHandle(s2ws(tmpNtdllInfo->name).c_str()), "ZwOpenProcess"));
    HANDLE tmp;
    g_ZwOpenProcess(&tmp, DesiredAccess, ObjectAttributes, ClientId);
    GetProcessImageFileNameA(tmp, buf, 256);
    std::string name = buf;
    std::cout << "OpenProcess: " << name << std::endl;
    if (name.find("cheat") != std::string::npos || name.find("Proc") != std::string::npos)
    {
        std::cout << "hid from OpenProcess" << std::endl;
        return(STATUS_ACCESS_DENIED);
    }
    return(g_ZwOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId));
 };




void    x64_detour(DWORD64* target, DWORD64 hook)
{
    std::array<BYTE, 12> jmp_hook{ {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rax, 00000 << replaced with our function bytes
        0xFF, 0xE0                                                      // jmp rax
        } };
	std::cout << "Detoured at " << target << std::endl;
    *reinterpret_cast<DWORD64*>(jmp_hook.data() + 2) = hook;
    DWORD oldProt = 0;
    VirtualProtectEx(GetCurrentProcess(), (LPVOID)target, jmp_hook.size(), PAGE_EXECUTE_READWRITE, &oldProt);
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)target, jmp_hook.data(), jmp_hook.size(), NULL);
    VirtualProtectEx(GetCurrentProcess(), (LPVOID)target, jmp_hook.size(), oldProt, &oldProt);
}
