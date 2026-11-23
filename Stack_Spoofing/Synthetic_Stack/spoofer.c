#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <stdarg.h>
#include "spoofer.h"

// GetFrameSize Read PE unwind metadata to calculate -> How many bytes a function subtracts from RSP
// Simply we get the arry of the RUNTIME_FUNCTION struct

static UINT64 GetFrameSize(UINT64 hModule, UINT64 pFuncAddr)
{
    // Step 1 : Navigate PE Headers to the Exception Directory
    PIMAGE_NT_HEADERS64 pNtHdr = (PIMAGE_NT_HEADERS64)(hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);

    PIMAGE_DATA_DIRECTORY pExceptDir = &pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    PRUNTIME_FUNCTION pFuncs = (PRUNTIME_FUNCTION)(hModule + pExceptDir->VirtualAddress);

    DWORD dwCount = pExceptDir->Size / sizeof(RUNTIME_FUNCTION);

    // Step 2 : Find the RUNTIME_FUNCTION for our target
    // Coverts absolute address to RVA, Because RUNTIME_FUNCTION stores RVAs
    DWORD dwFuncRva = (DWORD)(pFuncAddr - hModule);

    PRUNTIME_FUNCTION pEntry = NULL;
    for ( DWORD i = 0; i < dwCount; i++ )
    {
        if (dwFuncRva >= pFuncs[i].BeginAddress && dwFuncRva < pFuncs[i].EndAddress)
        {
            pEntry = &pFuncs[i];
            break;
        }
    }
    if ( !pEntry ) return 0;

    // Step 3 : Walk the UNWIND_CODE array
    // RUNTIME_FUNCTION points to an UNWIND_INFO struct, its UnwindCode[] array describe each prologue operation then we sum up al stack-adjusting operations to get the total fram size

    PUNWIND_INFO pInfo = (PUNWIND_INFO)(hModule + pEntry->UnwindData);
    PUNWIND_CODE pCodes = pInfo->UnwindCode;
    UINT64 dwStackSize = 0;

    for ( UCHAR i = 0; i < pInfo->CountOfUnwindCodes; i++ )
    {
        switch ( pCodes[i].UnwindOp )
        {
            // Function is pushed a registor (+8 bytes)
            case UWOP_PUSH_NONVOL:
                // push <reg> takes 8 bytes
                dwStackSize += 8;
                break;

            // small sub rsp, N ( +N bytes)
            case UWOP_ALLOC_SMALL:
                // sub rsp, (OpInfo + 1)*8
                dwStackSize += ((UINT64)pCodes[i].OpInfo + 1)*8;
                break;

            // big sub rsp, N (size stored in the next 1-2 slots)
            case UWOP_ALLOC_LARGE:
               if (pCodes[i].OpInfo == 0)
               {
                    // Next slot's FrameOffset * 8
                    dwStackSize += (UINT64)pCodes[i + 1].FrameOffset * 8;
                    i += 1; // skip the extra slot we just read
               } else {
                    // Next two slots form a 32-bit byte count
                    dwStackSize += *(ULONG*)(&pCodes[i + 1]);
                    i += 2; // skip the two extra slots
               }
               break;
            
            // CPU exception frame ( +40 or +48 )
            case UWOP_PUSH_MACHFRAME:
               dwStackSize += (pCodes[i].OpInfo == 0) ? 40 : 48;
               break;

            // Both work is to save registor to stack with skippping slots
            case UWOP_SAVE_NONVOL:
               i += 1; // skip 1 extra slot ( 16-bit offset )
               break;

            case UWOP_SAVE_NONVOL_FAR:
               i += 2; // skip 2 extra sloits ( 32-bit offset )
               break;

            default:
               break;
        }
    }
    return dwStackSize;
}

static UINT64 FindGadget(UINT64 hModule)
{
    // Step 1: Navigate PE to the .text section (execution code)
    PIMAGE_NT_HEADERS64 pNtHdr = (PIMAGE_NT_HEADERS64)(hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);

    PIMAGE_SECTION_HEADER pSection =IMAGE_FIRST_SECTION(pNtHdr);
    DWORD dwTextSize = 0;
    UINT64 pTextBase = 0;

    for (WORD i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(pSection[i].Name, ".text", 5) == 0)
        {
            dwTextSize = pSection[i].Misc.VirtualSize;
            pTextBase = hModule + pSection[i].VirtualAddress;
            break;
        }
    }

    if (!pTextBase) 
    {
        printf("Couldn't Found a jmp rbx Gadget \n");
        return 0;
    }

    // Step 2 : Scan for FF 23 (jmp [rbx]) and collect all matches
    UINT64 gadgets[64];
    DWORD dwGadgetCount = 0;

    for (DWORD i = 0; i < dwTextSize - 1; i++)
    {
        BYTE* p = (BYTE*)(pTextBase + i);
        if (p[0] == 0xFF && p[1] == 0x23)
        {
            gadgets[dwGadgetCount++] = (UINT64)p;
            if (dwGadgetCount >= 64) break;
        }
    }
    if (dwGadgetCount == 0) return 0;

    // Step 3: Pick a random one (srand was called in main)
    return gadgets[rand() % dwGadgetCount];
}


void* SpoofCallStack(UINT64 pTargetFunc, DWORD dwNumArgs, ...)
{
    // Step 1: Get module handles for ntdll and kernel32
    UINT64 hNtdll = (UINT64)GetModuleHandleA("ntdll.dll");
    UINT64 hKernel32 = (UINT64)GetModuleHandleA("kernel32.dll");

    // Step 2: Get address of the two thread-start functions
    UINT64 pRuts = (UINT64)GetProcAddress((HMODULE)hNtdll, "RtlUserThreadStart");
    UINT64 pBtit = (UINT64)GetProcAddress((HMODULE)hKernel32, "BaseThreadInitThunk");

    // Step 3: Find a jmp [rbx] gadget in kernel32
    UINT64 pGadget = FindGadget(hKernel32);

    // Step 4: Fill the SPOOF_CTX struct
    SPOOF_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));

    ctx.rutsRetAddr = pRuts + 0x21;
    ctx.rutsFrameSize = GetFrameSize(hNtdll, pRuts);

    ctx.btitRetAddr = pBtit + 0x14;
    ctx.btitFrameSize = GetFrameSize(hKernel32, pBtit);

    ctx.gadgetAddr = pGadget;
    ctx.gadgetFrameSize = GetFrameSize(hKernel32, pGadget);

    ctx.targetFunc = pTargetFunc;
    ctx.argCount = (dwNumArgs < 4) ? 4 : dwNumArgs;

    // Step 5: Pack the variadic args into the inline array
    va_list args;
    va_start(args, dwNumArgs);
    for (DWORD i = 0; i < dwNumArgs; i++)
    {
        ctx.args[i] = va_arg(args, UINT64);
    }
    va_end(args);

    // Step 6: Call the ASM, It bulids fake frames and JMPs to target
    return Spoof(&ctx);
}



