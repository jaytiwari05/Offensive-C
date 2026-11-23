#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "spoofer.h"

int main()
{
    srand((unsigned int) time(0));

    HMODULE hUser32 = LoadLibraryA("User32.dll");
    UINT64 pMsgBox = (UINT64)GetProcAddress(hUser32, "MessageBoxA");

    for (int i = 0; i < 5; i++)
    {
        SpoofCallStack(pMsgBox, 4, (UINT64)NULL, (UINT64)"Spoofed", (UINT64)"Call Stack Spoofer", (UINT64)MB_YESNO);
    }

    printf("Clean Exit \n");
}