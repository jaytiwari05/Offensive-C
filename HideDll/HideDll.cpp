
// Defining before windows.h to prevent min() macros
#define NOMINMAX
#include <phnt_windows.h>
#include <phnt.h>
#include <windows.h>
#include <Psapi.h>
#include <iostream>
//#include <winternl.h>
#include <utility>

#pragma comment(lib, "ntdll")

// Simple function that Enumerate DLL From a Process Handle
BOOL EnumDllsWithAPI(HANDLE hProcess)
{
	HMODULE h[1024];
	DWORD needed;
	if (!EnumProcessModules(hProcess, h, sizeof(h), &needed))
	{
		return false;
	}

	WCHAR name[256];
	for (int i = 0; i < std::min(needed / sizeof(HMODULE), _countof(h)); i++)
	{
		GetModuleBaseName(hProcess, h[i], name, _countof(name));
		printf("0x%p: %ws \n", h[i], name);
	}
	return true;
}

// Another way to Enumerate DLL using PEB walking
BOOL EnumDllsWithPeb(HANDLE hProcess)
{
	auto peb = NtCurrentTeb()->ProcessEnvironmentBlock;
	auto head = &peb->Ldr->InMemoryOrderModuleList;
	for ( LIST_ENTRY* next = head->Flink; next != head; next = next->Flink )
	{
		LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		printf("0x%p: %wZ \n", entry->DllBase, &entry->FullDllName);
	}

	return true;
}

// Code that Hide the DLL form the PEB
BOOL HideDll(PCWSTR dllname)
{
	// Building a UniCode String
	UNICODE_STRING uname;
	RtlInitUnicodeString(&uname, dllname);

	// Getting the PEB
	auto peb = NtCurrentTeb()->ProcessEnvironmentBlock;
	auto head = &peb->Ldr->InMemoryOrderModuleList;

	// Loop for walking the List
	for (LIST_ENTRY* next = head->Flink; next != head; next = next->Flink)
	{
		// matching the DLL name and modifing the reference address to the dll
		LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (RtlEqualUnicodeString(&entry->BaseDllName, &uname, TRUE))
		{
			auto prev = next->Blink;
			prev->Flink = next->Flink;
			next->Flink->Blink = prev;
			return true;
		}
	}

	return false;
}

int main()
{
	printf("-----------GetModuleBaseName----------- \n");
	EnumDllsWithAPI(GetCurrentProcess());
	printf("-----------PEB----------- \n");
	EnumDllsWithPeb(GetCurrentProcess());
	printf("[+] Hiding the kernelbase DLL ... \n");
	HideDll(L"kernelbase.dll");
	printf("[+] Succesfully hide the kernelbase DLL \n");
	printf("-----------After Hiding : GetModuleBaseName----------- \n");
	EnumDllsWithAPI(GetCurrentProcess());
	printf("-----------After Hiding : PEB----------- \n");
	EnumDllsWithPeb(GetCurrentProcess());

	return 0;
}
