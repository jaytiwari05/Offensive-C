#include <windows.h>
#include <stdio.h>

BOOL MapNtdllFromDisk(OUT PVOID* ppNtdllBuf, OUT PDWORD pdwFileSize)
{
    WCHAR cPath[MAX_PATH] = { 0 };
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapping = NULL;
    PVOID pBase = NULL;
    BOOL bResult = FALSE;

    // Build path to ntdll
    GetSystemDirectoryW(cPath, MAX_PATH);
    lstrcatW(cPath, L"\\ntdll.dll");

    // Open the file
    hFile = CreateFileW(cPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[!] CreateFileW Failed: %d \n", GetLastError());
        goto _Cleanup;
    }

    // store size for caller (useful for PE parsing later)
    *pdwFileSize = GetFileSize(hFile, NULL);

    // Create Mapping with SEC_IMAGE_NO_EXECUTE, OS Maps it as a PE Image
    hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);   
    if (!hMapping)
    {
        printf("[!] CreateFileMappingW Failed: %d \n", GetLastError());
        goto _Cleanup;
    }

    // Map Entire file into memory Sections are already at VirtualAddress offsets
    pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase)
    {
        printf("[!] MapViewOfFile Failed: %d \n", GetLastError());
        goto _Cleanup;
    }

    // sucess
    *ppNtdllBuf = pBase;
    bResult = TRUE;


_Cleanup:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    // Handle can be closed the mapping stays alive until UnMapViewOfFile
    if (hMapping)
        CloseHandle(hMapping);
    return bResult;
}

VOID FreeMapNtdll( IN PVOID pBuf)
{
    if (pBuf)
    {
        UnmapViewOfFile(pBuf);
    }
}
