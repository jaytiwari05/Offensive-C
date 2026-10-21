#include <windows.h>
#include <stdio.h>


// To get the current user Privs
VOID get_privileges()
{
    HANDLE hToken = NULL;
    TOKEN_ELEVATION token_elevation;
    PTOKEN_PRIVILEGES ptoken_privileges = NULL;
    DWORD cbSize = sizeof(TOKEN_ELEVATION);
    DWORD tpSize, length;

    CHAR name[256];

    // Opening Current Process 
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        // Getting the the current process token information
        GetTokenInformation(hToken, TokenPrivileges, ptoken_privileges, 0, &tpSize);

        ptoken_privileges = (PTOKEN_PRIVILEGES)calloc(tpSize+1, sizeof(TOKEN_PRIVILEGES));

        // Printing the Tokens/Priv which we have
        if (ptoken_privileges)
        {
            if (GetTokenInformation(hToken, TokenPrivileges, ptoken_privileges, tpSize, &tpSize))
            {
                for (int i=0; i<ptoken_privileges->PrivilegeCount; i++)
                {
                    length = 256;
                    LookupPrivilegeNameA(NULL, &ptoken_privileges->Privileges[i].Luid, name, &length);
                    if (ptoken_privileges->Privileges[i].Attributes == 3)
                    {
                        printf("[+] %-50s Enabled (Default)\n", name);
                    }
                    else if (ptoken_privileges->Privileges[i].Attributes == 2)
                    {
                        printf("[+] %-50s Enabled (Adjusted)\n", name);
                    }
                    else if (ptoken_privileges->Privileges[i].Attributes == 0)
                    {
                        printf("[+] %-50s Disabled\n", name);
                    }
                }
            }
        }

        // Checking if the Current User token is elevated
        if (GetTokenInformation(hToken, TokenElevation, &token_elevation, sizeof(token_elevation), &cbSize))
        {
            if(token_elevation.TokenIsElevated)
            {
                printf("[+] Elevated\n");
            }
            else
            {
                printf("[-] Restricted\n");
            }
        }
        CloseHandle(hToken);
    }
    else
    {
        printf("Err: %lu\n", GetLastError);
    }
    free(ptoken_privileges);
}

// Enabling SeDebugPrivilege - need admin privs
BOOL set_debug_token()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES token_privileges;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        if (LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &token_privileges.Privileges[0].Luid))
        {
            token_privileges.PrivilegeCount = 1;
            token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if(AdjustTokenPrivileges(hToken, 0, &token_privileges, sizeof(token_privileges), NULL, NULL))
            {
                CloseHandle(hToken);
                return TRUE;
            }
        }
        CloseHandle(hToken);
    }
    return FALSE;
}

// Checking for SeDebugPrivilege
BOOL check_debug_privs()
{
    LUID luid;
    PRIVILEGE_SET privs;
    BOOL bResult;
    HANDLE hToken;
    if( !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) )
    {
        return FALSE;
    }
    if ( !LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }
    privs.PrivilegeCount = 1;
    privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privs.Privilege[0].Luid = luid;
    privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    PrivilegeCheck(hToken, &privs, &bResult);
    CloseHandle(hToken);
    return bResult;
}

int main()
{
    get_privileges();
    if( set_debug_token() )
    {
        if( check_debug_privs() )
        {
            printf("-------------- Privileges modified --------------\n");
            get_privileges();
        }
        else
        {
            printf("Err %lu \n", GetLastError());
        }
    }
    else
    {
        printf("Err %lu \n", GetLastError());
    }

    return 0;
}