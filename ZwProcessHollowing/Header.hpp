#pragma once

PROCESS_BASIC_INFORMATION* GetProcessBasicInformation(HANDLE Process);
NTSTATUS UnmapView(HANDLE process, LPVOID ImageBase);
NTSTATUS AllocateMemory(HANDLE process, LPVOID ImageBaseAddr, SIZE_T sourceImageSize);
NTSTATUS WriteProcMemory(HANDLE process, PVOID sourceAddress, PVOID buffer, SIZE_T size);
NTSTATUS ReadProcMemory(HANDLE process, PVOID sourceAddress, PVOID buffer, SIZE_T size);
NTSTATUS ProtectMemory(HANDLE process, PVOID address, SIZE_T size);