#include <windows.h>
#include <stdio.h>

typedef BOOL (WINAPI* myGetComputerNameA)
(
    LPSTR lpBuffer,
    LPDWORD nSize
);

typedef BOOL (WINAPI* myGetUserNameA)
(
    LPSTR lpBuffer,
    LPDWORD pcbBuffer
);

int main()
{
    // Printing the Current ComputerName
    HMODULE hkernel32 = LoadLibraryW(L"kernel32.dll");
    myGetComputerNameA getComputerName = (myGetComputerNameA)GetProcAddress(hkernel32, "GetComputerNameA");
    if (getComputerName != NULL)
    {
        printf("GetComputerNameA: 0x%p \n", getComputerName);
        CHAR hostName[260];
        DWORD hostNameLength = 260;
        if (getComputerName(hostName, &hostNameLength))
        {
            printf("hostname: %s \n", hostName);
        }
    }

    // Printing the Current Username
    HMODULE hadvapi32 = LoadLibraryW(L"advapi32.dll");
    myGetUserNameA getUserName = (myGetUserNameA)GetProcAddress(hadvapi32, "GetUserNameA");
    if (getUserName != NULL)
    {
        printf("GetUserNameA: 0x%p \n", getUserName);
        CHAR userName[256];
        DWORD userNameLength = 256;
        if (getUserName(userName, &userNameLength))
        {
            printf("UserName: %s \n", userName);
        }
    }

    return 0;
}