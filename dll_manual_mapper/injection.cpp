#include "injection.h"
#include "debug.hpp"

/* 
* This just started working,
* I have no idea why.
* 
* The DLL only executes after running twice though
* so investigating that is the next task
*/

#ifdef _WIN64
// 64-bit relocation macro function
#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

typedef IMAGE_NT_HEADERS IMAGE_NT_HEADERS64;
typedef PIMAGE_NT_HEADERS PIMAGE_NT_HEADERS64;
typedef IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER64;
typedef PIMAGE_OPTIONAL_HEADER PIMAGE_OPTIONAL_HEADER64;

//#define IMAGE_NT_HEADERS IMAGE_NT_HEADERS64
//#define PIMAGE_NT_HEADERS PIMAGE_NT_HEADERS64
//#define IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER64
//#define PIMAGE_OPTIONAL_HEADER PIMAGE_OPTIONAL_HEADER64

#else
// 32-bit relocation macro function
#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)	

typedef IMAGE_NT_HEADERS IMAGE_NT_HEADERS64;
typedef PIMAGE_NT_HEADERS PIMAGE_NT_HEADERS64;
typedef IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER64;
typedef PIMAGE_OPTIONAL_HEADER PIMAGE_OPTIONAL_HEADER64;
//#define IMAGE_NT_HEADERS IMAGE_NT_HEADERS32
//#define PIMAGE_NT_HEADERS PIMAGE_NT_HEADERS32
//#define IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER32
//#define PIMAGE_OPTIONAL_HEADER PIMAGE_OPTIONAL_HEADER32

#endif

using namespace std;

BOOL ManualMap(HANDLE hProc, const char* szDllFile) { // szDllFile should be full path (not relative).
	BYTE* pSourceData = nullptr;
	//DWORD* pSourceData = nullptr;
	//IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	PIMAGE_NT_HEADERS pOldNtHeader = nullptr;
	//IMAGE_OPTIONAL_HEADER* pOldOptionalHeader = nullptr;
	PIMAGE_OPTIONAL_HEADER pOldOptionalHeader = nullptr;
	PIMAGE_FILE_HEADER pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;
	//DWORD* pTargetBase = nullptr;

	DWORD dwCheck = 0;
	if (!GetFileAttributesA(szDllFile)) {
		DbgErr("[ManualMap] File doesn't exist",false);
		return false;
	}

	// Open DLL File
	ifstream File(szDllFile, ios::binary | ios::ate);
	if (File.fail()) {
		// File error comes from File.rdstate(), instead of GetLastError()
		// ...for some reason
		DbgErr("[ManualMap] File failed",false,(DWORD)File.rdstate());
		File.close();
		return false;
	}
	DbgSuc("[ManualMap] Opened DLL");

	// Get filesize
	auto FileSize = File.tellg();
	if (FileSize < 0x1000) {
		DbgErr("[ManualMap] File size is invalid", false);
		File.close();
		return false;
	}

	// Allocate new memory array for DLL source data;
	MANUAL_MAPPING_DATA data{ 0 };

	// Get mapping functions
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress); // Recast to user-defined function type (w/e that means)

	//size_t SourceDataSize = static_cast<UINT_PTR>(FileSize);
	pSourceData = new BYTE[static_cast<UINT_PTR>(FileSize)];
	//pSourceData = new DWORD[static_cast<UINT_PTR>(FileSize)];

	if (!pSourceData) {
		DbgErr("[ManualMap] SourceData memory allocation failed");
		File.close();
		return false;
	}
	DbgSuc("[ManualMap] Allocated SourceData memory");

	// Shift to beginning of DLL
	File.seekg(0,ios::beg);
	// Read #FileSize bytes as char*'s into pSourceData
	File.read(reinterpret_cast<char*>(pSourceData), FileSize);
	File.close();
	DbgSuc("[ManualMap] Read DLL bytes into allocated memory");

	// Check for PE file header in DLL source data

	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pSourceData);
	//if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData)->e_magic != 0x5A4D) {
	if (pDosHeader->e_magic != 0x5A4D) {
		DbgErr("[ManualMap] Invalid DLL file");
		delete[] pSourceData; // Pluggin' those leaks
		return false;
	}

	// pSourceData is currently the DLL base address +
	// e_lfanew component of IMAGE_DOS_HEADER(pSourceData) is offset of NTHeader in DLL
	// = NtHeader position
	// tldr; Gets the NT header from the DLL
	//pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSourceData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData)->e_lfanew);
	//pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSourceData + pDosHeader->e_lfanew);
	pOldNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(pSourceData + pDosHeader->e_lfanew);
	
	// Grab Optional and File headers from NT header
	pOldOptionalHeader = &(pOldNtHeader->OptionalHeader);
	pOldFileHeader = &(pOldNtHeader->FileHeader);

// Architecture check
#ifdef _WIN64	// 64-bit DLL
	//if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
	if (pOldNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		DbgErr("[ManualMap] Invalid 64-bit DLL");
		delete[] pSourceData;
		return false;
	}
#else			// 32-bit DLL
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
		DbgErr("[ManualMap] Invalid 32-bit DLL");
		delete[] pSourceData;
		return false;
	}
#endif

	/* A CAUTIONARY TALE */

	//pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc,reinterpret_cast<void*>(pOldOptionalHeader->ImageBase),pOldOptionalHeader->SizeOfImage,(MEM_COMMIT|MEM_RESERVE),PAGE_EXECUTE_READWRITE));
	//if (!pTargetBase) {
	//	DbgErr("[ManualMap] Failed to allocate at OptionalHeader->ImageBase");
	//	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc,nullptr,pOldOptionalHeader->SizeOfImage,(MEM_COMMIT|MEM_RESERVE),PAGE_EXECUTE_READWRITE));
	//	//pTargetBase = reinterpret_cast<DWORD*>(VirtualAllocEx(hProc,nullptr,pOldOptionalHeader->SizeOfImage,(MEM_COMMIT|MEM_RESERVE),PAGE_EXECUTE_READWRITE));
	//	if (!pTargetBase) {
	//		DbgErr("[ManualMap] Memory allocation in target process failed");
	//		delete[] pSourceData;
	//		return false;
	//	}
	//}

	/*                  */

	// Allocate virtual memory for DLL image in target process
	
	// I shit on GuidedHacking's tutorial. I am God and they are trash. (see above)
	//pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptionalHeader->SizeOfImage, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE));
	pTargetBase = static_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptionalHeader->SizeOfImage, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE));
	if (!pTargetBase) {
		DbgErr("[ManualMap] Virtual memory allocation failed");
		delete[] pSourceData;
		return false;
	}
	DbgSucH("[ManualMap] Allocated virtual memory @: ",&pTargetBase);

	/*DbgLogH("OldNtHeader @: ", &pOldNtHeader, pOldNtHeader);
	DbgLogH("OldOptional @: ", &pOldOptionalHeader, pOldOptionalHeader);
	DbgLogH("OldFileHeader @: ", &pOldFileHeader, pOldFileHeader);
	DbgLogH("Target Base @: ", &pTargetBase);*/
	cout << hex << "OldNtHeader @: " << &pOldNtHeader << " : " << pOldNtHeader << endl;
	cout << hex << "OldOptionalHeader @: " << &pOldOptionalHeader << " : " << pOldOptionalHeader << endl;
	cout << hex << "OldFileHeader @: " << &pOldFileHeader << " : " << pOldFileHeader << endl;
	cout << hex << "Target Base@: " << &pTargetBase << endl;

	//MANUAL_MAPPING_DATA data{ 0 };

	//// Get mapping functions
	//data.pLoadLibraryA = LoadLibraryA;
	//data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress); // Recast to user-defined function type (w/e that means)

	// Get first DLL section header
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);

	// Loop through DLL sections
	DbgLog("[ManualMap] Iterating DLL sections...");
	for (UINT i = 0; i < pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		// If SizeOfRawData, then section data must be initialised (not all 0's)
		// We only care about these sections, with raw data
		if (pSectionHeader->SizeOfRawData) {
			// Write current section's data to target process memory
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSourceData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				DbgErr("[ManualMap] WriteProcessMemory failed");
				delete[] pSourceData;
				// Using MEM_RELEASE will release all allocated pages, meaning size doesn't need to be specified
				// (MEM_DECOMMIT would require a size)
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE); // Free allocated memory in target proc
				return false;
			}
		}
	}
	DbgSuc("[ManualMap] Finished iterating sections");


	// pData must be written to start of the module
	// (Error checking unnecessary as memory has been successfully allocated
	// and written to at this point, so it should never fail (see above))
	memcpy(pSourceData, &data, sizeof(data)); // Copy PE headers to pSourceData
	//memcpy(pSourceData, &data, SourceDataSize); // Copy PE headers to pSourceData
	//if (!WriteProcessMemory(hProc, pTargetBase, pSourceData, 0x1000, nullptr)) {
	if (!WriteProcessMemory(hProc, pTargetBase, pSourceData, 0x1000, nullptr)) {
		DbgErr("[ManualMap] WriteProcessMemory header write failed");
		delete[] pSourceData;
		return false;
	}
	DbgSuc("[ManualMap] Wrote Source Data to target proc");

	delete[] pSourceData;

	// Allocate shellcode memory in target proc
	// (1 page = 0x1000 bytes)
	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		DbgErr("[ManualMap] Shellcode memory allocation failed");
		// Using MEM_RELEASE will release all allocated pages, meaning size doesn't need to be specified
		if (pShellcode == 0) { 
			DbgErr("Invalid shellcode"); 
			return false; 
		}
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}
	DbgSuc("[ManualMap] Allocated Shellcode memory");

	// Write Shellcode content to pShellCode address in target proc
	if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr)) {
		DbgErr("Failed to write Shellcode to target procmem");
		return 1;
	}

	// Create shellcode thread in target proc
	DbgLog("[ManualMap] Opening shellcode thread...");

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, NULL, nullptr);
	if (!hThread) {
		DbgErr("[ManualMap] Create shellcode thread failed");
		// Using MEM_RELEASE will release all allocated pages, meaning size doesn't need to be specified
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}
	DbgSuc("[ManualMap] Created shellcode thread");

	// Check if shellcode has finished executing
	HINSTANCE hCheck = NULL;
	DbgLog("[ManualMap] Waiting for shellcode...");
	while (!hCheck) {
		MANUAL_MAPPING_DATA data_checked{ 0 };
		if (!ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr)) {
			DbgErr("[ManualMap] Couldn't check target procmem");
			return false;
		}
		//DbgLog("[ManualMap] Checked target memory successfully");
		hCheck = data_checked.hModule;
		//Sleep(3);
	}
	DbgSuc("[ManualMap] Shellcode finished");
	
	

	// Free allocated shellcode memory
	if (!VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE)) {
		DbgErr("[ManualMap] Failed to free virtual procmem");
		return false;
	}
	VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);

	// Close thread handle
	CloseHandle(hThread);

	return true;
}



//void WINAPI Shellcode(MANUAL_MAPPING_DATA* pData) {
DWORD WINAPI Shellcode(MANUAL_MAPPING_DATA* pData) {
	if (!pData) { // No data, no mapping
		return FALSE;
	}

	// Get base address from pData
	BYTE* pBase = reinterpret_cast<BYTE*>(pData);
	//DWORD* pBase = reinterpret_cast<DWORD*>(pData);

	// Grab optional header from pData (offset by pBase)
	// Return type changes between x86 and x64 so `auto` is used
	//auto* pOptional = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;
	PIMAGE_OPTIONAL_HEADER pOptional = &reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	/* Required Function Injection */

	// Loading these functions is necessary because the shellcode won't
	// be able to call functions
	// All needed functions must be passed to the pData structure as a result.
	// From here, we can grab the function pointers.
	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOptional->AddressOfEntryPoint); // Grab relative address to entry point of DLL (DllMain)


	/* Relocation */
	// Determine where ImageBase was allocated

	BYTE* LocationDelta = pBase - pOptional->ImageBase; // base_addr - image_base_addr = location_offset
	//DWORD* LocationDelta = pBase - pOptional->ImageBase; // base_addr - image_base_addr = location_offset
	//DWORD LocationDelta = (DWORD((LPBYTE)pData->lpImageBase - pData->NtHeaders->OptionalHeader.ImageBase));

	if (LocationDelta) { // Not located at base_addr, relocation necessary

		// Can't relocate, there's no data
		if (!pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			return FALSE;
		}

		// Get data virtual address to relocate
		PIMAGE_BASE_RELOCATION pRelocData = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pBase + pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (pRelocData->VirtualAddress) {
			// Calculate the number of entries. (I don't really get this, check out the IMAGE_BASE_RELOCATION struct sometime I guess)
			//UIT EntryCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(DWORD);
			DWORD EntryCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(DWORD);
			

			// Get position of TypeOffset array in IMAGE_BASE_RELOCATION by adding 8 bytes to pRelocData.
			// sizeof(IMAGE_BASE_RELOCATION*) is 8 bytes so adding 1 to pRelocData does the same thing

			//WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + sizeof(IMAGE_BASE_RELOCATION));
			DWORD* pRelativeInfo = reinterpret_cast<DWORD*>(pRelocData + sizeof(IMAGE_BASE_RELOCATION));
			//WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			// Iterate through entries in TypeOffset array
			for (DWORD i = 0; i != EntryCount; ++i, ++pRelativeInfo) {
				// DWORD TypeOffset[]
				   //- high 12-bits are relocation
				   //- low 4-bits are relocation type flag

				if (RELOC_FLAG(*pRelativeInfo)) {
					// Get pointer to relocation address from pRelativeInfo (highest 12 bits)
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo)));


					// Insert DLL bytes into relocation address
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta); // ERROR: Writing to this address causes a MEMORY ACCESS VIOLATION EXCEPTION
				}

				// Shift pRelocData to next entry block (?)
				pRelocData = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
				//pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<DWORD*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}

		// If data in import directory. (If 0, no data, so do nothing)
		if (pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
			auto* pImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			while (pImportDescriptor->Name) { // Iterate through Import Descriptor
				while (pImportDescriptor->Characteristics) {
					// Grab name of current module to import
					char* szModule = reinterpret_cast<char*>(pBase + pImportDescriptor->Name);

					// Load import (with shellcode-imported LoadLibraryA function)
					HINSTANCE hDll = _LoadLibraryA(szModule);

					// First Thunk (whatever that is)
					ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->OriginalFirstThunk);
					ULONG_PTR* pFunctionRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->FirstThunk);

					if (!pThunkRef) { // There's a chance OriginalFirstThunk isn't defined, so use FirstThunk instead
						pThunkRef = pFunctionRef;
					}

					// Load Libraries
					for (; *pThunkRef; ++pThunkRef, ++pFunctionRef) { // While pThunkRef is defined (Non-incremental for loop)
						// Load functions (either through Name or Ordinal Number, depending on how it is defined)
						if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) { // Import by Ordinal Number
							// Ordinal Number is stored at *pThunkRef (grab lower 2 bytes to avoid warnings (?))
							*pFunctionRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF)); // Use shellcode-imported GetProcAddress
						}
						else { // Import by Name
							auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
							*pFunctionRef = _GetProcAddress(hDll, pImport->Name);
						}
					}
					++pImportDescriptor;
				}
			}
		}

		// Executing Thread Local Storage (TLS) callbacks
		if (pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
			// Grab TLS virtual address
			//auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			IMAGE_TLS_DIRECTORY* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		

			// Iterate through callbacks
			for (; pCallback && *pCallback; ++pCallback) {
				(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr); // Execute callback
			}
		}

		// Call DllMain() (Execute shellcode)
		_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

		// Setting this address lets us determine if the injection succeeded 
		// by checking it in our manual mapping code.
		pData->hModule = reinterpret_cast<HINSTANCE>(pBase);

	}
	return TRUE;
}