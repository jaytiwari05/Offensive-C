#pragma once
#include <windows.h>

typedef ULONGLONG REGHANDLE;

typedef struct _EVENT_DESCRIPTOR {
    USHORT Id;
    UCHAR  Version;
    UCHAR  Channel;
    UCHAR  Level;
    UCHAR  Opcode;
    USHORT Task;
    ULONGLONG Keyword;
} EVENT_DESCRIPTOR;

typedef struct _EVENT_DATA_DESCRIPTOR {
    ULONGLONG Ptr;
    ULONG     Size;
    ULONG     Reserved;
} EVENT_DATA_DESCRIPTOR;

typedef ULONG (WINAPI* fnEtwEventWrite)(
    REGHANDLE              RegHandle,
    EVENT_DESCRIPTOR const *EventDescriptor,
    ULONG                  UserDataCount,
    EVENT_DATA_DESCRIPTOR  *UserData
);
