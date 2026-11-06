#pragma once
#include <windows.h>

// prototype - map ntdll as PE image from disk
BOOL MapNtdllFromDisk(OUT PVOID* ppNtdllBuf, OUT PDWORD pdwFileSize);
// cleanup wrapper for map method
VOID FreeMapNtdll(IN PVOID pBuf);
