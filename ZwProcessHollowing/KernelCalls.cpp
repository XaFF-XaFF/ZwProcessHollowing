#define _AMD64_
#include <ntifs.h>
#include <ntddk.h>
#include <stdio.h>
#include <minwindef.h>

#include "Header.hpp"
#include "API.hpp"

PROCESS_BASIC_INFORMATION* GetProcessBasicInformation(HANDLE Process)
{
	PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();

	DWORD returnLenght;
	ZwQueryInformationProcess(Process, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLenght);

	return pbi;
}

NTSTATUS UnmapView(HANDLE hProcess, LPVOID ImageAddress)
{
	NTSTATUS status = ZwUnmapViewOfSection(hProcess, ImageAddress);
	return status;
}

NTSTATUS AllocateMemory(HANDLE process, LPVOID ImageBaseAddr, SIZE_T sourceImageSize)
{
	NTSTATUS status = ZwAllocateVirtualMemory(process, &ImageBaseAddr, 0, &sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	return status;
}

NTSTATUS WriteProcMemory(HANDLE process, PVOID sourceAddress, PVOID buffer, SIZE_T size)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG retn;
	status = NtWriteVirtualMemory(process, sourceAddress, buffer, size, NULL);

	return status;
}

NTSTATUS ReadProcMemory(HANDLE process, PVOID sourceAddress, PVOID buffer, SIZE_T size)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG retn;
	status = NtReadVirtualMemory(process, sourceAddress, buffer, size, NULL);

	return status;
}