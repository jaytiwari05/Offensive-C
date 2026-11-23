#pragma once
#include <windows.h>
#include "structs.h"

// ASM entry point defined in spoof.asm
extern void* Spoof(PSPOOF_CTX ctx);

// C Entry Point Builds the struct and calls Spoof()
void* SpoofCallStack(UINT64 pTargetFunc, DWORD dwNumArgs, ...);
