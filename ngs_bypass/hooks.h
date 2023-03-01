#pragma once
#include <windows.h>
#include <iostream>
#include <array> 
#include "ntdll.h"
#include "utilities.h"

extern modInfo *ntdllInfo;
extern modInfo *kernel32Info;
extern modInfo *blackCipherInfo;
extern modInfo* tmpNtdllInfo;

extern modInfoNew* Maple_BCNtdllInfos;
extern modInfoNew* Maple_BCBlackCipherInfos;
extern modInfoNew* Maple_BCNtdllTmpInfos;

extern modInfoNew* BC_MapleInfos;
extern modInfoNew* BC_MapleNtdllTmpInfos;

extern modInfo* Maple_MapleCpy;
extern modInfo* Maple_MsNtdllTmpCpy;

NTSTATUS NtReadVirtualMemory_BC_Hook(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PULONG NumberOfBytesReaded);

NTSTATUS NtReadVirtualMemory_MS_Hook(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PULONG NumberOfBytesReaded);

NTSTATUS MapViewOfFile_Hook(
    HANDLE hFileMappingObject,
    DWORD  dwDesiredAccess,
    DWORD  dwFileOffsetHigh,
    DWORD  dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap);

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
);

NTSTATUS ZwOpenProcess_Hook(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

void    x64_detour(DWORD64* target, DWORD64 hook);


