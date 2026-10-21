#include <windows.h>
#include <stdio.h>

#define HASH_KEY_2 19

static __inline DWORD modror19(DWORD d) { return _rotr(d, HASH_KEY_2); }

DWORD RORhash(char* c) {
    DWORD h = 0;
    do { h = modror19(h); h += *c; } while (*++c);
    return h;
}

int main() {
    printf("VirtualProtect     = 0x%08X\n", RORhash("VirtualProtect"));
    printf("VirtualAlloc       = 0x%08X\n", RORhash("VirtualAlloc"));
    printf("LoadLibraryA       = 0x%08X\n", RORhash("LoadLibraryA"));
    printf("GetProcAddress     = 0x%08X\n", RORhash("GetProcAddress"));
    printf("NtFlushInstructionCache = 0x%08X\n", RORhash("NtFlushInstructionCache"));
    printf("\nExpected from loader.h:\n");
    printf("LOADLIBRARYA_HASH          = 0x3B8FF745\n");
    printf("GETPROCADDRESS_HASH        = 0x10D9D886\n");
    printf("VIRTUALALLOC_HASH          = 0x6AA1CCE4\n");
    printf("VIRTUALPROTECT_HASH        = 0x99EAAA33  <- is this right?\n");
    printf("NTFLUSHINSTRUCTIONCACHE_HASH = 0x57C5286B\n");
    return 0;
}
