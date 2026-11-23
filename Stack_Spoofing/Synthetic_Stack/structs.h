#pragma once
#include <windows.h>

typedef unsigned char UBYTE;

typedef enum _UNWIND_OP_CODES
{
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE = 1,
    UWOP_ALLOC_SMALL = 2,
    UWOP_SET_FPREG = 3,
    UWOP_SAVE_NONVOL = 4,
    UWOP_SAVE_NONVOL_FAR = 5,
    UWOP_PUSH_MACHFRAME = 10
} UNWIND_OP_CODES;

// Same 2 Bytes two views. ALLOC_LARGE reads the NEXT
// Slot's FrameOffset to get its size openrand
typedef union _UNWIND_CODE
{
    struct
    {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO
{
    UCHAR Version : 3;
    UCHAR Flags : 5;
    UCHAR SizeOfPrologue;
    UCHAR CountOfUnwindCodes;
    UCHAR FrameRegister : 4;
    UCHAR FrameRegisterOffset : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, *PUNWIND_INFO;

typedef struct _SPOOF_CTX
{
    UINT64 rutsRetAddr;  // +0 RtlUserThreadStart + 0x21
    UINT64 rutsFrameSize; // +8 fram size from unwind info

    UINT64 btitRetAddr; // +16 BaseThreadInitThunk + 0x14
    UINT64 btitFrameSize; // +24 frame size from unwind info

    UINT64 gadgetAddr; // +32 jmp [rbx] address in kernel32
    UINT64 gadgetFrameSize; // +40 gaget function's frame size

    UINT64 targetFunc; // +48 the API we're calling
    UINT64 argCount;   // +56 arg count (minimum 4)
    UINT64 restoreAddr; // +64 ASM writes restore label addr here

    UINT64 args[16]; // +72 inline arg array (no malloc)

} SPOOF_CTX, *PSPOOF_CTX;


