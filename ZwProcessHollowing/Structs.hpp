#pragma once
#include <Windows.h>


typedef struct _PEB* PPEB;
typedef LONG KPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

unsigned char aesKey[32] = {
        0x53, 0x28, 0x40, 0x6e, 0x2f, 0x64, 0x63, 0x5d, 0x2d, 0x61, 0x77, 0x40, 0x76, 0x71, 0x77, 0x28,
        0x74, 0x61, 0x7d, 0x66, 0x61, 0x73, 0x3b, 0x5d, 0x66, 0x6d, 0x3c, 0x3f, 0x7b, 0x66, 0x72, 0x36
};