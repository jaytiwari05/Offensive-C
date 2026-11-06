#pragma once
#include <windows.h>

// prototype - read raw ntdll bytes from disk
BOOL ReadNtdllFromDisk(OUT PVOID* ppNtdllBuf, OUT PDWORD pdwFileSize);
// cleanup wrapper for read method
VOID FreeReadNtdll(IN PVOID pBuf);
