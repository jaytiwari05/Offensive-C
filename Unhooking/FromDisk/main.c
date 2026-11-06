#include <windows.h>
#include <stdio.h>
#include "read.h"
#include "map.h"
#include "unhook.h"

// function pointer types - same signature for both methods
typedef BOOL (*FnLoad)(OUT PVOID*, OUT PDWORD);
typedef VOID (*FnFree)(IN PVOID);

// dispatch table - one row per method
typedef struct _NTDLL_PROVIDER {
    char*   Name;       // for printing
    FnLoad  Load;       // ReadNtdllFromDisk or MapNtdllFromDisk
    FnFree  Free;       // HeapFree wrapper or UnmapViewOfFile wrapper
    BOOL    bMapped;    // tells UnhookNtdll which offset to use
} NTDLL_PROVIDER;

NTDLL_PROVIDER Providers[] = {
    { "ReadFile",      ReadNtdllFromDisk, FreeReadNtdll, FALSE },
    { "MapViewOfFile", MapNtdllFromDisk,  FreeMapNtdll,  TRUE  },
};


int main(int argc, char* argv[]) {

    // default to map method, pass "read" as arg to use read method
    int idx = 1;
    if (argc > 1 && strcmp(argv[1], "read") == 0)
        idx = 0;

    NTDLL_PROVIDER* p = &Providers[idx];
    PVOID   pNtdll = NULL;
    DWORD   dwSize = 0;

    printf("[*] Method: %s\n", p->Name);

    // load a clean copy of ntdll
    if (!p->Load(&pNtdll, &dwSize)) {
        printf("[-] Failed to load ntdll\n");
        return -1;
    }
    printf("[+] Clean ntdll at 0x%p (%d bytes)\n", pNtdll, dwSize);

    // replace hooked .text with the clean copy
    if (!UnhookNtdll(pNtdll, p->bMapped)) {
        printf("[-] Unhooking failed\n");
        p->Free(pNtdll);
        return -1;
    }

    printf("[+] Press Enter to Unhook ... \n");
    getchar();
    // cleanup
    p->Free(pNtdll);
    printf("[+] ntdll unhooked successfully\n");

    getchar();

    return 0;
}
