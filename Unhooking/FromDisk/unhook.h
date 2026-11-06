#pragma once
#include <windows.h>

// get ntdll base from PEB - no API calls, avoids hooked GetModuleHandle
PVOID FetchLocalNtdllBase();
// replace hooked .text with clean copy - bIsMapped controls offset calculation
BOOL  UnhookNtdll(IN PVOID pCleanNtdll, IN BOOL bIsMapped);
