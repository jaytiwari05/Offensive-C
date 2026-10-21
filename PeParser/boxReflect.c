#include <windows.h>
#include <stdio.h>
#include "loader.h" // To load the DLL in

struct MY_VAR_PTR
{
    LPVOID myDllBase;
};

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            struct MY_VAR_PTR *myVarPtr = (struct MY_VAR_PTR*)lpReserved;
            VirtualFree(myVarPtr->myDllBase, 0, MEM_RELEASE);
            MessageBoxA(NULL, "Box Refelected", "Test", MB_OK);
            printf("[+] Returning this output \n");
            fflush(stdout); // need to do this to capture printf statements
            break;
        }
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}