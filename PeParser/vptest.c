#include <windows.h>
#include <stdio.h>
int main() {
    LPVOID mem = VirtualAlloc(NULL, 4096, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    printf("Allocated at: %p\n", mem);

    DWORD old = 0;
    // try to promote PAGE_READWRITE -> PAGE_EXECUTE_READ
    BOOL result = VirtualProtect(mem, 4096, PAGE_EXECUTE_READ, &old);
    printf("VirtualProtect(RW->XR): %s, err=%lu\n", result ? "SUCCESS" : "FAILED", GetLastError());

    VirtualFree(mem, 0, MEM_RELEASE);

    // now try allocating directly with execute permission
    LPVOID mem2 = VirtualAlloc(NULL, 4096, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("VirtualAlloc(RWX) result: %p, err=%lu\n", mem2, GetLastError());
    if (mem2) VirtualFree(mem2, 0, MEM_RELEASE);
    return 0;
}
