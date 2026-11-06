#include <windows.h>
#include <stdio.h>

BOOL ReadNtdllFromDisk( OUT PVOID* ppNtdllBuf, OUT PDWORD pdwFileSize )
{
    WCHAR cPath[MAX_PATH] = { 0 };
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PVOID pBuffer = NULL;
    DWORD dwSize = 0;
    DWORD dwBytesRead = 0;
    BOOL bResult = FALSE;

    // Build "C:\Windows\System32\ntdll.dll"
    GetSystemDirectoryW(cPath, MAX_PATH);
    lstrcatW(cPath, L"\\ntdll.dll");


    // Open the file read-only
    hFile = CreateFileW(cPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[!] CreateFileW Failed: %d \n", GetLastError());
        goto _Cleanup;
    }

    // get file size for allocation
    dwSize = GetFileSize(hFile, NULL);

    // allocate buffer to hold the raw file bytes
    pBuffer = HeapAlloc(GetProcessHeap(), 0, dwSize);
    if (!pBuffer) {
        printf("[!] HeapAlloc Failed\n");
        goto _Cleanup;
    }

    // read entire file into buffer
    if (!ReadFile(hFile, pBuffer, dwSize, &dwBytesRead, NULL) || dwBytesRead != dwSize) {
        printf("[!] ReadFile Failed: %d\n", GetLastError());
        goto _Cleanup;
    }

    // sucess - hand buffer and size to caller
    *ppNtdllBuf = pBuffer;
    *pdwFileSize = dwSize;
    bResult = TRUE;

_Cleanup:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    // Free buffer only on failure caller own it on sucess
    if (!bResult && pBuffer)
        HeapFree(GetProcessHeap(), 0, pBuffer);
    return bResult;
}

VOID FreeReadNtdll(IN PVOID pBuf)
{
    if(pBuf)
    {
        HeapFree(GetProcessHeap(), 0, pBuf);
    }
}
