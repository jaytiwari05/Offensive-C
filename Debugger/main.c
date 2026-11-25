#include <windows.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI* NTALLOCATEVIRTUALMEMORY)(HANDLE    ProcessHandle, PVOID *BaseAddress,ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG     Protect);

int main()
{
    NTALLOCATEVIRTUALMEMORY pNtAllocateVirtualMemory = (NTALLOCATEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");

    printf("The Address of NtAllocateVirtualMemory  0x%p \n", pNtAllocateVirtualMemory);
    system("pause");

    return 0;
}