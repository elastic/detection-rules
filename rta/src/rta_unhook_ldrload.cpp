#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>


typedef NTSTATUS(NTAPI* pLdrLoadDll) (
	PWCHAR PathToFile,
	ULONG Flags,
	PUNICODE_STRING ModuleFileName,
	PHANDLE ModuleHandle
	);

typedef VOID(NTAPI* pRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

HMODULE NtLoad(LPCWSTR lpFileName) {
	UNICODE_STRING ustrModule;
	HANDLE hModule = NULL;

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");

	RtlInitUnicodeString(&ustrModule, lpFileName);

	pLdrLoadDll myLdrLoadDll = (pLdrLoadDll)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll");
	if (!myLdrLoadDll) {
		return NULL;
	}

	NTSTATUS status = myLdrLoadDll(NULL, 0, &ustrModule, &hModule);
	return (HMODULE)hModule;
}

int main()
{
	HANDLE process = GetCurrentProcess();
	MODULEINFO mi = {};
	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	STARTUPINFOW initInfo = { 0 };
	initInfo.cb = sizeof(initInfo);
	PROCESS_INFORMATION procInfo = { 0 };

	
	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
	HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	// unhook current proces ntdll .txt section
	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			DWORD oldProtection = 0;
			bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
			isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	// load ws2_32.dll from unhooked ntdll to trigger "Potential NTDLL Memory Unhooking"
	HANDLE ws32 = LoadLibraryA("C:\\Windows\\system32\\ws2_32.dll");
	printf("[+] - ws2_32.dll loaded at 0x%p\n", ws32);

	// create notepad.exe from unhooked ntdll to trigger "Process Creation from Modified NTDLL"
	CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, (LPSTARTUPINFOA)&initInfo, &procInfo);
	printf("[+] - notepad.exe created from unhooked ntdll\n");

	// load psapi.dll via LdrLoadDll to trigger "Suspicious Image Load via LdrLoadDLL"
	HMODULE psapi = NtLoad(L"psapi.dll");
	printf("[+] - psapi.dll loaded at 0x%p via LdrLoadDll\n", psapi);

	printf("[+] - RTA Done!\n", psapi);

	// close handles
	CloseHandle(process);
	CloseHandle(ntdllFile);
	CloseHandle(ntdllMapping);
	CloseHandle(ws32);
	CloseHandle(psapi);
	FreeLibrary(ntdllModule);

	return 0;
}
