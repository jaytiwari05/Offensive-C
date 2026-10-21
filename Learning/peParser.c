#include <windows.h>
#include <stdio.h>
#include "boxreflect.h"
// #include "evasive_boxreflect.h"
// #include "boxreflect_cnth.h"


DWORD findExportDirectoryInfo(DWORD pointerToRawData, DWORD virtualAddressOffset) {
    printf("         [-] [0x%04x] [exportFlags] : 0x%02X%02X%02X%02X\n", pointerToRawData, boxreflect_dll[pointerToRawData+3],
        boxreflect_dll[pointerToRawData+2], boxreflect_dll[pointerToRawData+1], boxreflect_dll[pointerToRawData]);

    DWORD timeDateStampOffset = pointerToRawData + 0x4;
    printf("         [-] [0x%04x] [Time/DateStamp] : 0x%02X%02X%02X%02X\n", timeDateStampOffset, boxreflect_dll[timeDateStampOffset+3],
        boxreflect_dll[timeDateStampOffset+2], boxreflect_dll[timeDateStampOffset+1], boxreflect_dll[timeDateStampOffset]);

    DWORD majorVersionOffset = timeDateStampOffset + 0x4;
    printf("         [-] [0x%04x] [majorVersion] : 0x%02X%02X\n", majorVersionOffset, boxreflect_dll[majorVersionOffset+1],
        boxreflect_dll[majorVersionOffset]);

    DWORD minorVersionOffset = majorVersionOffset + 0x2;
    printf("         [-] [0x%04x] [minorVersion] : 0x%02X%02X\n", minorVersionOffset, boxreflect_dll[minorVersionOffset+1],
        boxreflect_dll[minorVersionOffset]);

    DWORD nameRVAOffset = minorVersionOffset + 0x2;
    printf("         [-] [0x%04x] [nameRVA] : 0x%02X%02X%02X%02X (RVA to PE name)\n", nameRVAOffset, boxreflect_dll[nameRVAOffset+3],
        boxreflect_dll[nameRVAOffset+2], boxreflect_dll[nameRVAOffset+1], boxreflect_dll[nameRVAOffset]);

    DWORD ordinalBaseOffset = nameRVAOffset + 0x4;
    printf("         [-] [0x%04x] [ordinalBase] : 0x%02X%02X%02X%02X\n", ordinalBaseOffset, boxreflect_dll[ordinalBaseOffset+3],
        boxreflect_dll[ordinalBaseOffset+2], boxreflect_dll[ordinalBaseOffset+1], boxreflect_dll[ordinalBaseOffset]);

    DWORD addressTableEntriesOffset = ordinalBaseOffset + 0x4;
    printf("         [-] [0x%04x] [addressTableEntries] : 0x%02X%02X%02X%02X (Count of functions in Export Address Table)\n", addressTableEntriesOffset, boxreflect_dll[addressTableEntriesOffset+3], 
        boxreflect_dll[addressTableEntriesOffset+2], boxreflect_dll[addressTableEntriesOffset+1], boxreflect_dll[addressTableEntriesOffset]);

    DWORD numberOfNamePointersOffset = addressTableEntriesOffset + 0x4;
    printf("         [-] [0x%04x] [numberOfNamePointers] : 0x%02X%02X%02X%02X (Count of entries in the name pointer table/ordinal table)\n", numberOfNamePointersOffset, boxreflect_dll[numberOfNamePointersOffset+3], 
        boxreflect_dll[numberOfNamePointersOffset+2], boxreflect_dll[numberOfNamePointersOffset+1], boxreflect_dll[numberOfNamePointersOffset]);

    DWORD exportAddressTableRVAOffset = numberOfNamePointersOffset + 0x4;
    printf("         [-] [0x%04x] [exportAddressTableRVA] : 0x%02X%02X%02X%02X (RVA of the Export Address Table)\n", exportAddressTableRVAOffset, boxreflect_dll[exportAddressTableRVAOffset+3], 
        boxreflect_dll[exportAddressTableRVAOffset+2], boxreflect_dll[exportAddressTableRVAOffset+1], boxreflect_dll[exportAddressTableRVAOffset]);

    DWORD namePointerRVAOffset = exportAddressTableRVAOffset + 0x4;
    printf("         [-] [0x%04x] [namePointerRVA] : 0x%02X%02X%02X%02X (RVA of the Export Name Pointer Table)\n", namePointerRVAOffset, boxreflect_dll[namePointerRVAOffset+3], boxreflect_dll[namePointerRVAOffset+2], 
        boxreflect_dll[namePointerRVAOffset+1], boxreflect_dll[namePointerRVAOffset]);

    DWORD ordinalTableRVAOffset = namePointerRVAOffset + 0x4;
    printf("         [-] [0x%04x] [ordinalTableRVA] : 0x%02X%02X%02X%02X (RVA of the Ordinal Table)\n", ordinalTableRVAOffset, boxreflect_dll[ordinalTableRVAOffset+3], boxreflect_dll[ordinalTableRVAOffset+2], 
        boxreflect_dll[ordinalTableRVAOffset+1], boxreflect_dll[ordinalTableRVAOffset]);



    DWORD exportNamePointerRVA = (boxreflect_dll[namePointerRVAOffset+3] << 24) | (boxreflect_dll[namePointerRVAOffset+2] << 16) | (boxreflect_dll[namePointerRVAOffset+1] << 8) | boxreflect_dll[namePointerRVAOffset];
    DWORD edataVirtualAddress = (boxreflect_dll[virtualAddressOffset+3] << 24) | (boxreflect_dll[virtualAddressOffset+2] << 16) | (boxreflect_dll[virtualAddressOffset+1] << 8) | boxreflect_dll[virtualAddressOffset];
    DWORD exportNamePointerFileOffset = ( exportNamePointerRVA - edataVirtualAddress ) + pointerToRawData;

    printf("         [-] [0x%04x] [exportNamePointerRVA] : 0x%02X%02X%02X%02X\n", exportNamePointerFileOffset, boxreflect_dll[exportNamePointerFileOffset+3], 
        boxreflect_dll[exportNamePointerFileOffset+2], boxreflect_dll[exportNamePointerFileOffset+1], boxreflect_dll[exportNamePointerFileOffset]);

    DWORD symbolNameRVA = (boxreflect_dll[exportNamePointerFileOffset+3] << 24) | (boxreflect_dll[exportNamePointerFileOffset+2] << 16) | 
        (boxreflect_dll[exportNamePointerFileOffset+1] << 8) | boxreflect_dll[exportNamePointerFileOffset];

    DWORD symbolFileOffset = ( symbolNameRVA - edataVirtualAddress ) + pointerToRawData;
    unsigned char symbolName[MAX_PATH] = { 0 };
    for (int i = 0; i < MAX_PATH; i++) {
        if (boxreflect_dll[symbolFileOffset+i] == 0) {
            break;
        }
        symbolName[i] = boxreflect_dll[symbolFileOffset+i];
    }
    printf("         [-] [0x%04x] [symbolName] : %s\n", symbolFileOffset, symbolName);

    DWORD exportAddressTableRVA = (boxreflect_dll[exportAddressTableRVAOffset+3] << 24) | (boxreflect_dll[exportAddressTableRVAOffset+2] << 16) |
        (boxreflect_dll[exportAddressTableRVAOffset+1] << 8) | boxreflect_dll[exportAddressTableRVAOffset];

    printf("         Calculation = (0x%X - 0x%X) + 0x%X\n", exportAddressTableRVA, edataVirtualAddress, pointerToRawData);

    DWORD symbolRVAOffset = ( exportAddressTableRVA - edataVirtualAddress ) + pointerToRawData;
    DWORD symbolRVA = (boxreflect_dll[symbolRVAOffset+3] << 24) | (boxreflect_dll[symbolRVAOffset+2] << 16) | (boxreflect_dll[symbolRVAOffset+1] << 8) | boxreflect_dll[symbolRVAOffset];
    printf("         [-] [0x%04x] [symbolRVA] : 0x%08X\n", symbolRVAOffset, symbolRVA);
    return symbolRVA;
}

void findSectionHeaders(DWORD firstSectionHeaderOffset, DWORD noOfSections) {
    printf("\n [Sections headers start at: 0x%04x]\n", firstSectionHeaderOffset);
    DWORD nextSectionHeaderOffset = firstSectionHeaderOffset;
    for (int i = 0; i < noOfSections; i++) {
        CHAR headerName[] = { boxreflect_dll[nextSectionHeaderOffset], boxreflect_dll[nextSectionHeaderOffset+1], boxreflect_dll[nextSectionHeaderOffset+2], 
        boxreflect_dll[nextSectionHeaderOffset+3], boxreflect_dll[nextSectionHeaderOffset+4], boxreflect_dll[nextSectionHeaderOffset+5], 
        boxreflect_dll[nextSectionHeaderOffset+6], boxreflect_dll[firstSectionHeaderOffset+7], 0x00 };

        printf(" [+] [Section Header %d]\n", i);
        printf("     [+] [0x%04x] [Name] : %s\n", nextSectionHeaderOffset, headerName);

        DWORD virtualSizeOffset = nextSectionHeaderOffset + 0x8;
        printf("     [+] [0x%04x] [VirtualSize] : 0x%02X%02X%02X%02X\n", virtualSizeOffset, boxreflect_dll[virtualSizeOffset+3], boxreflect_dll[virtualSizeOffset+2], 
            boxreflect_dll[virtualSizeOffset+1], boxreflect_dll[virtualSizeOffset]);

        DWORD virtualAddressOffset = virtualSizeOffset + 0x4;
        printf("     [+] [0x%04x] [VirtualAddress] : 0x%02X%02X%02X%02X\n", virtualAddressOffset, boxreflect_dll[virtualAddressOffset+3],
            boxreflect_dll[virtualAddressOffset+2], boxreflect_dll[virtualAddressOffset+1], boxreflect_dll[virtualAddressOffset]);

        DWORD sizeOfRawDataOffset = virtualAddressOffset + 0x4;
        printf("     [+] [0x%04x] [SizeOfRawData] : 0x%02X%02X%02X%02X\n", sizeOfRawDataOffset, boxreflect_dll[sizeOfRawDataOffset+3],
            boxreflect_dll[sizeOfRawDataOffset+2], boxreflect_dll[sizeOfRawDataOffset+1], boxreflect_dll[sizeOfRawDataOffset]);

        DWORD pointerToRawDataOffset = sizeOfRawDataOffset + 0x4;
        printf("     [+] [0x%04x] [PointerToRawData] : 0x%02X%02X%02X%02X\n", pointerToRawDataOffset, boxreflect_dll[pointerToRawDataOffset+3],
            boxreflect_dll[pointerToRawDataOffset+2], boxreflect_dll[pointerToRawDataOffset+1], boxreflect_dll[pointerToRawDataOffset]);

        DWORD pointerToRelocationsOffset = pointerToRawDataOffset + 0x4;
        printf("     [+] [0x%04x] [PointerToRelocations] : 0x%02X%02X%02X%02X\n", pointerToRelocationsOffset,  boxreflect_dll[pointerToRelocationsOffset+3],
            boxreflect_dll[pointerToRelocationsOffset+2], boxreflect_dll[pointerToRelocationsOffset+1], boxreflect_dll[pointerToRelocationsOffset]);

        DWORD pointerToLinenumbersOffset = pointerToRelocationsOffset + 0x4;
        printf("     [+] [0x%04x] [PointerToLinenumbers] : 0x%02X%02X%02X%02X\n", pointerToLinenumbersOffset, boxreflect_dll[pointerToLinenumbersOffset+3],
            boxreflect_dll[pointerToLinenumbersOffset+2], boxreflect_dll[pointerToLinenumbersOffset+1], boxreflect_dll[pointerToLinenumbersOffset]);

        DWORD numberOfLinenumbersOffset = pointerToLinenumbersOffset + 0x4;
        printf("     [+] [0x%04x] [NumberOfLinenumbers] : 0x%02X%02X%02X%02X\n", numberOfLinenumbersOffset, boxreflect_dll[numberOfLinenumbersOffset+3],
            boxreflect_dll[numberOfLinenumbersOffset+2], boxreflect_dll[numberOfLinenumbersOffset+1], boxreflect_dll[numberOfLinenumbersOffset]);

        DWORD characteristicsOffset = numberOfLinenumbersOffset + 0x4;
        printf("     [+] [0x%04x] [Characteristics] : 0x%02X%02X%02X%02X\n", characteristicsOffset, boxreflect_dll[characteristicsOffset+3],
            boxreflect_dll[characteristicsOffset+2], boxreflect_dll[characteristicsOffset+1], boxreflect_dll[characteristicsOffset]);

        if (strstr(headerName, ".edata")) {
            DWORD firstByte = boxreflect_dll[pointerToRawDataOffset+3];
            DWORD secondByte = boxreflect_dll[pointerToRawDataOffset+2];
            DWORD thirdByte = boxreflect_dll[pointerToRawDataOffset+1];
            DWORD fourthByte = boxreflect_dll[pointerToRawDataOffset+0];

            DWORD pointerToRawData = ( firstByte << 24 ) | ( secondByte << 16 ) | ( thirdByte << 8 ) | fourthByte;
            DWORD symbolRVA = findExportDirectoryInfo(pointerToRawData, virtualAddressOffset);

            DWORD tempSectionHeaderOffset = firstSectionHeaderOffset;
            for (int i = 0; i < 11; i++) {
                // VirtualAddress offset is 12 bytes from firstSectionHeaderOffset ( Name = 8 bytes, VirtualSize = 4 bytes )
                DWORD sectionVirtualAddressOffset = firstSectionHeaderOffset + 0xC;
                DWORD sectionVirtualAddress = (boxreflect_dll[sectionVirtualAddressOffset+3] << 24) | (boxreflect_dll[sectionVirtualAddressOffset+2] << 16) | (boxreflect_dll[sectionVirtualAddressOffset+1] << 8) | boxreflect_dll[sectionVirtualAddressOffset];
                // SizeOfRawData offset is 4 bytes from VirtualAddress ( VirtualAddress = 4 )
                DWORD sectionSizeOfRawDataOffset = sectionVirtualAddressOffset + 0x4;
                DWORD sectionSizeOfRawData = (boxreflect_dll[sectionSizeOfRawDataOffset+3] << 24) | (boxreflect_dll[sectionSizeOfRawDataOffset+2] << 16) | (boxreflect_dll[sectionSizeOfRawDataOffset+1] << 8) | boxreflect_dll[sectionSizeOfRawDataOffset];
                // SizeOfRawData offset is 4 bytes from SizeOfRawData ( SizeOfRawData = 4 )
                DWORD sectionPointerToRawDataOffset = sectionSizeOfRawDataOffset + 0x4;
                DWORD sectionPointerToRawData = (boxreflect_dll[sectionPointerToRawDataOffset+3] << 24) | (boxreflect_dll[sectionPointerToRawDataOffset+2] << 16) | (boxreflect_dll[sectionPointerToRawDataOffset+1] << 8) | boxreflect_dll[sectionPointerToRawDataOffset];

                if  (symbolRVA > sectionVirtualAddress && (symbolRVA < sectionVirtualAddress + sectionSizeOfRawData) ) {
                    DWORD symbolFileOffset = ( symbolRVA - sectionVirtualAddress ) + sectionPointerToRawData;
                    printf("     [*] [0x%04x] [symbolFileOffset] : 0x%08X\n", symbolRVA, symbolFileOffset);

                    // LPVOID boxreflectDllExectuableBuffer = VirtualAllocEx(GetCurrentProcess(), NULL, boxreflect_dll_len, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                    // WriteProcessMemory(GetCurrentProcess(), boxreflectDllExectuableBuffer, boxreflect_dll, boxreflect_dll_len, NULL);
                    unsigned char* boxreflectDllExectuableBuffer = (unsigned char*) VirtualAlloc(NULL, boxreflect_dll_len, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
                    memcpy(boxreflectDllExectuableBuffer, boxreflect_dll, boxreflect_dll_len);

                    printf("------------------------ boxreflectDllExectuableBuffer: 0x%x\n", boxreflectDllExectuableBuffer);

                    // boxreflectDllExectuableBuffer[0] = 0;
                    // boxreflectDllExectuableBuffer[1] = 0;
                    for (int i = 0; i< 0x84; i++) {
                        if (i == 0x3c) {
                            i+=4;
                        }
                        boxreflectDllExectuableBuffer[i] = 0;
                    }

                    // adding new NT header
                    boxreflectDllExectuableBuffer[0x80] = 0x23;
                    boxreflectDllExectuableBuffer[0x81] = 0x12;

                    // getchar();

                    DWORD flOldProtect;
                    VirtualProtect(boxreflectDllExectuableBuffer, boxreflect_dll_len, PAGE_EXECUTE_READ, &flOldProtect);

                    LPTHREAD_START_ROUTINE symbolExecutableAddress = (LPTHREAD_START_ROUTINE)( (ULONG_PTR)boxreflectDllExectuableBuffer + symbolFileOffset );
                    DWORD lpThreadId;
                    HANDLE hThread = CreateRemoteThread( GetCurrentProcess(), NULL, 1024*1024, symbolExecutableAddress, NULL, NULL, &lpThreadId);
                    WaitForSingleObject(hThread, INFINITE);
                    break;
                }
                tempSectionHeaderOffset += 0x28;
            }
        }

        nextSectionHeaderOffset += 0x28;
        printf("\n");
    }
}

int main() {
    DWORD initialOffset = 0x3c;
    
    printf("Boxreflect base addr: 0x%x", boxreflect_dll);

    // DWORD peHeaderOffset = boxreflect_dll[initialOffset];
    DWORD peHeaderOffset = (boxreflect_dll[initialOffset+2] << 16) | (boxreflect_dll[initialOffset+1] << 8) | boxreflect_dll[initialOffset];
	printf(" [0x%04x] [peHeader offset] : 0x%02X\n", initialOffset, peHeaderOffset);
	printf(" [0x%04x] [peHeader] : %c%c\n", peHeaderOffset, boxreflect_dll[peHeaderOffset], boxreflect_dll[peHeaderOffset+1]);

	DWORD machineTypeOffset = peHeaderOffset + 4;
	printf(" [0x%04x] [machineType] : x%x%x\n", machineTypeOffset, boxreflect_dll[machineTypeOffset+1], boxreflect_dll[machineTypeOffset]);

	DWORD noOfSectionsOffset = machineTypeOffset + 0x2;
    DWORD noOfSections = ( boxreflect_dll[noOfSectionsOffset+1] << 8 ) | ( boxreflect_dll[noOfSectionsOffset] );
	printf(" [0x%04x] [noOfSections] : (%d) 0x%02X\n", noOfSectionsOffset,  noOfSections, noOfSections);

	DWORD timeDateStampOffset = noOfSectionsOffset + 0x2;
	printf(" [0x%04x] [timeDateStamp] : 0x%02X%02X%02X%02X\n", timeDateStampOffset, boxreflect_dll[timeDateStampOffset+3], 
        boxreflect_dll[timeDateStampOffset+2], boxreflect_dll[timeDateStampOffset+1], boxreflect_dll[timeDateStampOffset]
        );

    //PointerToSymbolTable deprecated = 0x4 bytes
    //NumberOfSymbols  deprecated = 0x4 bytes
    DWORD sizeOfOptionalHeaderOffset = timeDateStampOffset + 0x4 + 0x4 + 0x4;
    DWORD sizeOfOptionalHeader = ( boxreflect_dll[sizeOfOptionalHeaderOffset+1]<<8) | (boxreflect_dll[sizeOfOptionalHeaderOffset]);
	printf(" [0x%04x] [sizeOfOptionalHeader] : 0x%02X\n", sizeOfOptionalHeaderOffset, sizeOfOptionalHeader);

    //Characteristics = 0x2 bytes
    //Data at sizeOfOptionalHeaderOffset = 0x2 bytes
    //First Section Header Offset = start of sizeOfOptionalHeaderOffset (0x94) + 0x2 (sizeOfOptionalHeaderOffset) + characteristicsOffset (2 bytes) + sizeOfOptionalHeader
    DWORD firstSectionHeaderOffset = sizeOfOptionalHeaderOffset + 0x2 + 0x2 + sizeOfOptionalHeader;
    findSectionHeaders(firstSectionHeaderOffset, noOfSections);
    return 1;
}



