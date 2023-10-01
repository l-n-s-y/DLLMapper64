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

//typedef IMAGE_NT_HEADERS IMAGE_NT_HEADERS64;
//typedef PIMAGE_NT_HEADERS PIMAGE_NT_HEADERS64;
//typedef IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER64;
//typedef PIMAGE_OPTIONAL_HEADER PIMAGE_OPTIONAL_HEADER64;

//#define IMAGE_NT_HEADERS IMAGE_NT_HEADERS64
//#define PIMAGE_NT_HEADERS PIMAGE_NT_HEADERS64
//#define IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER64
//#define PIMAGE_OPTIONAL_HEADER PIMAGE_OPTIONAL_HEADER64

#else
// 32-bit relocation macro function

//typedef IMAGE_NT_HEADERS IMAGE_NT_HEADERS64;
//typedef PIMAGE_NT_HEADERS PIMAGE_NT_HEADERS64;
//typedef IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER64;
//typedef PIMAGE_OPTIONAL_HEADER PIMAGE_OPTIONAL_HEADER64;
//#define IMAGE_NT_HEADERS IMAGE_NT_HEADERS32
//#define PIMAGE_NT_HEADERS PIMAGE_NT_HEADERS32
//#define IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER32
//#define PIMAGE_OPTIONAL_HEADER PIMAGE_OPTIONAL_HEADER32

#endif

using namespace std;

//BOOL ManualMap(HANDLE hProc, BYTE* pSourceData, const char* szDllFile) { // szDllFile should be full path (not relative).
bool ManualMap(HANDLE hProc, BYTE* pSrcData, bool ClearHeader, bool ClearNonNeededSections, bool AdjustProtections, bool SEHExceptionSupport, DWORD fdwReason, LPVOID lpReserved) {
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) { //"MZ"
		DbgLog("Invalid file");
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	DbgLog("File ok");

	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pTargetBase) {
		DbgErr("Target process memory allocation failed (ex) 0x%X", true);
		return false;
	}

	DWORD oldp = 0;
	VirtualProtectEx(hProc, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
	data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else 
	SEHExceptionSupport = false;
#endif
	data.pBase = pTargetBase;
	data.fdwReasonParam = fdwReason;
	data.reservedParam = lpReserved;
	data.SEHSupport = SEHExceptionSupport;


	//File header
	if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr)) { //only first 0x1000 bytes for the header
		DbgErr("Can't write file header 0x%X", true);
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) { // here
				DbgErr("Can't map sections: 0x%x", true);
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	//Mapping params
	BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!MappingDataAlloc) {
		DbgErr("Target process mapping allocation failed (ex) 0x%X", true);
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
		DbgErr("Can't write mapping 0x%X", true);
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		return false;
	}

	//Shell code
	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		DbgErr("Memory shellcode allocation failed (ex) 0x%X", true);
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		return false;
	}

	if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr)) {
		DbgErr("Can't write shellcode 0x%X", true);
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, NULL, nullptr);
	if (!hThread) {
		DbgErr("Thread creation failed 0x%X", true);
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}
	CloseHandle(hThread);

	DbgLog("Thread created at: %p, waiting for return...", pShellcode);

	HINSTANCE hCheck = NULL;
	while (!hCheck) {
		DWORD exitcode = 0;
		GetExitCodeProcess(hProc, &exitcode);
		if (exitcode != STILL_ACTIVE) {
			DbgLog("Process crashed, exit code: ", exitcode);
			return false;
		}

		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hModule;

		if (hCheck == (HINSTANCE)0x404040) {
			DbgErr("Wrong mapping ptr");
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
			return false;
		}
		else if (hCheck == (HINSTANCE)0x505050) {
			DbgErr("WARNING: Exception support failed!\n");
		}

		Sleep(10);
	}
	DbgSuc("Shellcode executed");

	BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
	if (emptyBuffer == nullptr) {
		DbgErr("Unable to allocate memory");
		return false;
	}
	memset(emptyBuffer, 0, 1024 * 1024 * 20);

	//CLEAR PE HEAD
	if (ClearHeader) {
		if (!WriteProcessMemory(hProc, pTargetBase, emptyBuffer, 0x1000, nullptr)) {
			DbgErr("WARNING!: Can't clear HEADER");
		}
	}
	//END CLEAR PE HEAD


	if (ClearNonNeededSections) {
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				if ((SEHExceptionSupport ? 0 : strcmp((char*)pSectionHeader->Name, ".pdata") == 0) ||
					strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
					strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
					DbgLog("Processing %s removal", pSectionHeader->Name);
					if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr)) {
						DbgLog("Can't clear section %s: 0x%x", pSectionHeader->Name);
					}
				}
			}
		}
	}

	if (AdjustProtections) {
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				DWORD old = 0;
				DWORD newP = PAGE_READONLY;

				if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
					newP = PAGE_READWRITE;
				}
				else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
					newP = PAGE_EXECUTE_READ;
				}
				if (VirtualProtectEx(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old)) {
					DbgLog("section %s set as %lX ", (char*)pSectionHeader->Name);
				}
				else {
					DbgErr("FAIL: section %s not set as %lX ", (char*)pSectionHeader->Name);
				}
			}
		}
		DWORD old = 0;
		VirtualProtectEx(hProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
	}

	if (!WriteProcessMemory(hProc, pShellcode, emptyBuffer, 0x1000, nullptr)) {
		DbgErr("WARNING: Can't clear shellcode");
	}
	if (!VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE)) {
		DbgErr("WARNING: can't release shell code memory");
	}
	if (!VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE)) {
		DbgErr("WARNING: can't release mapping data memory");
	}

	return true;
}
//BOOL ManualMap(HANDLE hProc, BYTE* pSourceData) { // szDllFile should be full path (not relative).
//	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
//	IMAGE_OPTIONAL_HEADER* pOldOptionalHeader = nullptr;
//	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
//	BYTE* pTargetBase = nullptr;
//
//	// Check for PE file header in DLL source data
//
//	//IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData);
//	//if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData)->e_magic != 0x5A4D) {
//	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData)->e_magic != 0x5A4D) {
//		DbgErr("[ManualMap] Invalid DLL file");
//		delete[] pSourceData; // Pluggin' those leaks
//		return false;
//	}
//
//	// pSourceData is currently the DLL base address +
//	// e_lfanew component of IMAGE_DOS_HEADER(pSourceData) is offset of NTHeader in DLL
//	// = NtHeader position
//	// tldr; Gets the NT header from the DLL
//	//pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSourceData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData)->e_lfanew);
//	//pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSourceData + pDosHeader->e_lfanew);
//	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSourceData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData)->e_lfanew);
//	//pOldNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(pSourceData + pDosHeader->e_lfanew);
//	
//	// Grab Optional and File headers from NT header
//	pOldOptionalHeader = &pOldNtHeader->OptionalHeader;
//	pOldFileHeader = &pOldNtHeader->FileHeader;
//
//// Architecture check
//#ifdef _WIN64	// 64-bit DLL
//	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
//	//if (pOldNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
//		DbgErr("[ManualMap] Invalid 64-bit DLL");
//		delete[] pSourceData;
//		return false;
//	}
//#else			// 32-bit DLL
//	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
//		DbgErr("[ManualMap] Invalid 32-bit DLL");
//		delete[] pSourceData;
//		return false;
//	}
//#endif
//
//	/* A CAUTIONARY TALE */
//
//	//pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc,reinterpret_cast<void*>(pOldOptionalHeader->ImageBase),pOldOptionalHeader->SizeOfImage,(MEM_COMMIT|MEM_RESERVE),PAGE_EXECUTE_READWRITE));
//	//if (!pTargetBase) {
//	//	DbgErr("[ManualMap] Failed to allocate at OptionalHeader->ImageBase");
//	//	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc,nullptr,pOldOptionalHeader->SizeOfImage,(MEM_COMMIT|MEM_RESERVE),PAGE_EXECUTE_READWRITE));
//	//	//pTargetBase = reinterpret_cast<DWORD*>(VirtualAllocEx(hProc,nullptr,pOldOptionalHeader->SizeOfImage,(MEM_COMMIT|MEM_RESERVE),PAGE_EXECUTE_READWRITE));
//	//	if (!pTargetBase) {
//	//		DbgErr("[ManualMap] Memory allocation in target process failed");
//	//		delete[] pSourceData;
//	//		return false;
//	//	}
//	//}
//
//	/*                  */
//
//	// Allocate virtual memory for DLL image in target process
//	
//	//pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptionalHeader->SizeOfImage, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE));
//	pTargetBase = static_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
//	//pTargetBase = static_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE));
//	if (!pTargetBase) {
//		DbgErr("[ManualMap] Virtual memory allocation failed");
//		delete[] pSourceData;
//		return false;
//	}
//	DbgSucH("[ManualMap] Allocated virtual memory @: ",&pTargetBase);
//	// github pastin:
//	DWORD oldp = 0;
//	VirtualProtectEx(hProc, pTargetBase, pOldOptionalHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);
//
//	// Allocate new memory array for DLL source data;
//	MANUAL_MAPPING_DATA data{ 0 };
//
//	// Get mapping functions
//	data.pLoadLibraryA = LoadLibraryA;
//	data.pGetProcAddress = GetProcAddress; // Recast to user-defined function type (w/e that means)
//	//data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress); // Recast to user-defined function type (w/e that means)
//	
//#ifdef _WIN64
//	data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
//#endif
//	data.pBase = pTargetBase;
//
//	//MANUAL_MAPPING_DATA data{ 0 };
//
//	//// Get mapping functions
//	//data.pLoadLibraryA = LoadLibraryA;
//	// pData must be written to start of the module
//	
//	//memcpy(pSourceData, &data, sizeof(data)); // Copy PE headers to pSourceData
//	//memcpy(pSourceData, &data, SourceDataSize); // Copy PE headers to pSourceData -    here
//	//if (!WriteProcessMemory(hProc, pTargetBase, pSourceData, 0x1000, nullptr)) {
//	if (!WriteProcessMemory(hProc, pTargetBase, pSourceData, 0x1000, nullptr)) {
//		DbgErr("[ManualMap] WriteProcessMemory header write failed");
//		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
//		return false;
//	}
//	DbgSuc("[ManualMap] Wrote Source Data to target proc");
//
//	// Get first DLL section header
//
//	// Loop through DLL sections
//	DbgLog("[ManualMap] Iterating DLL sections...");
//	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
//	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
//		// If SizeOfRawData, then section data must be initialised (not all 0's)
//		// We only care about these sections, with raw data
//		if (pSectionHeader->SizeOfRawData) {
//			// Write current section's data to target process memory
//			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSourceData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
//				DbgErr("[ManualMap] WriteProcessMemory failed",true);
//				// Using MEM_RELEASE will release all allocated pages, meaning size doesn't need to be specified
//				// (MEM_DECOMMIT would require a size)
//				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE); // Free allocated memory in target proc
//				return false;
//			}
//		}
//	}
//	DbgSuc("[ManualMap] Finished iterating sections");
//
//
//	BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
//	if (!MappingDataAlloc) {
//		DbgErr("[ManualMap] Mapping allocation failed");
//		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
//		return false;
//	}
//
//	if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
//		DbgErr("[ManualMap] Couldn't write to allocated memory");
//		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
//		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
//		return false;
//	}
//
//	// Allocate shellcode memory in target proc
//	// (1 page = 0x1000 bytes)
//	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
//	if (!pShellcode) {
//		DbgErr("[ManualMap] Shellcode memory allocation failed");
//		// Using MEM_RELEASE will release all allocated pages, meaning size doesn't need to be specified
//		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
//		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
//		return false;
//	}
//	DbgSuc("[ManualMap] Allocated Shellcode memory");
//
//	// Write Shellcode content to pShellCode address in target proc
//	if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr)) {
//		DbgErr("Failed to write Shellcode to target procmem");
//		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
//		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
//		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
//		return 1;
//	}
//
//	// Create shellcode thread in target proc
//	DbgLog("[ManualMap] Spawning shellcode thread...");
//
//	//HANDLE hThread = CreateRemoteThread(hProc, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, NULL, nullptr);
//	HANDLE hThread = CreateRemoteThread(hProc, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, NULL, nullptr);
//	if (!hThread) {
//		DbgErr("[ManualMap] Couldn't spawn shellcode thread");
//		// Using MEM_RELEASE will release all allocated pages, meaning size doesn't need to be specified
//		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
//		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
//		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
//		return false;
//	}
//	// Close thread handle
//	CloseHandle(hThread);
//	DbgSuc("[ManualMap] Spawned shellcode thread");
//
//
//	// Check if shellcode has finished executing
//	HINSTANCE hCheck = NULL;
//	DbgLog("[ManualMap] Waiting for shellcode...");
//	while (!hCheck) {
//		// Exit code check
//		DWORD dwExitCode = 0;
//		GetExitCodeProcess(hProc, &dwExitCode);
//		if (dwExitCode != STILL_ACTIVE) {
//			DbgErr("[ManualMap] Process crashed");
//			return false;
//		}
//
//		MANUAL_MAPPING_DATA data_checked{ 0 };
//		ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
//
//		hCheck = data_checked.hModule;
//		if (hCheck == (HINSTANCE)0x404040) {
//			DbgErr("[ManualMap] Wrong mapping ptr\n");
//			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
//			VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
//			VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
//			return false;
//		}
//		else if (hCheck == (HINSTANCE)0x505050) {
//			DbgErr("[ManualMap] Exception support failed!\n");
//		}
//	}
//	DbgSuc("[ManualMap] Shellcode finished");
//	
//	
//	BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
//	if (emptyBuffer == nullptr) {
//		DbgErr("Unable to allocate memory");
//		return false;
//	}
//	memset(emptyBuffer, 0, 1024 * 1024 * 20);
//
//	//CLEAR PE HEAD
//	if (!WriteProcessMemory(hProc, pTargetBase, emptyBuffer, 0x1000, nullptr)) {
//		DbgErr("WARNING!: Can't clear HEADER");
//	}
//	//END CLEAR PE HEAD
//
//	pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
//	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
//		if (pSectionHeader->Misc.VirtualSize) {
//			if ((true ? 0 : strcmp((char*)pSectionHeader->Name, ".pdata") == 0) || strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 || strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
//				DbgErr("Processing %s removal", pSectionHeader->Name);
//				if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr)) {
//					DbgErr("Can't clear section %s: 0x%x", true, pSectionHeader->Name);
//				}
//			}
//		}
//	}
//
//	pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
//	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
//		if (pSectionHeader->Misc.VirtualSize) {
//			if ((strcmp((char*)pSectionHeader->Name, ".pdata") == 0) ||
//				strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
//				strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
//				printf("Processing %s removal\n", pSectionHeader->Name);
//				if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr)) {
//					printf("Can't clear section %s: 0x%x\n", pSectionHeader->Name, GetLastError());
//				}
//			}
//		}
//	}
//
//	/*if (AdjustProtections) {
//		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
//		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
//			if (pSectionHeader->Misc.VirtualSize) {
//				DWORD old = 0;
//				DWORD newP = PAGE_READONLY;
//
//				if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
//					newP = PAGE_READWRITE;
//				}
//				else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
//					newP = PAGE_EXECUTE_READ;
//				}
//				if (VirtualProtectEx(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old)) {
//					printf("section %s set as %lX\n", (char*)pSectionHeader->Name, newP);
//				}
//				else {
//					printf("FAIL: section %s not set as %lX\n", (char*)pSectionHeader->Name, newP);
//				}
//			}
//		}
//		DWORD old = 0;
//		VirtualProtectEx(hProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
//	}*/
//
//	if (!WriteProcessMemory(hProc, pShellcode, emptyBuffer, 0x1000, nullptr)) {
//		DbgErr("WARNING: Can't clear shellcode");
//	}
//	if (!VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE)) {
//		DbgErr("WARNING: can't release shell code memory");
//	}
//	if (!VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE)) {
//		DbgErr("WARNING: can't release mapping data memory");
//	}
//
//	return true;
//}


#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)	
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif


#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void WINAPI Shellcode(MANUAL_MAPPING_DATA* pData) {
	if (!pData) {
		pData->hModule = (HINSTANCE)0x404040;
		return;
	}

	BYTE* pBase = pData->pBase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
	auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef) {
				pThunkRef = pFuncRef;
			}

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);

		for (; pCallback && *pCallback; ++pCallback) {
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, 0);
}
//void WINAPI Shellcode(MANUAL_MAPPING_DATA* pData) {
//void WINAPI Shellcode(MANUAL_MAPPING_DATA* pData) {
//	if (!pData) { // No data, no mapping
//		pData->hModule = (HINSTANCE)0x404040;
//		return;
//	}
//
//	// Get base address from pData
//	//BYTE* pBase = reinterpret_cast<BYTE*>(pData);
//	BYTE* pBase = pData->pBase;
//	//DWORD* pBase = reinterpret_cast<DWORD*>(pData);
//
//	// Grab optional header from pData (offset by pBase)
//	// Return type changes between x86 and x64 so `auto` is used
//	//auto* pOptional = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;
//	auto* pOptional = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;
//
//	/* Required Function Injection */
//	  
//	// Loading these functions is necessary because the shellcode won't
//	// be able to call functions
//	// All needed functions must be passed to the pData structure as a result.
//	// From here, we can grab the function pointers.
//	auto _LoadLibraryA = pData->pLoadLibraryA;
//	auto _GetProcAddress = pData->pGetProcAddress;
//#ifdef _WIN64
//	auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
//#endif
//	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOptional->AddressOfEntryPoint); // Grab relative address to entry point of DLL (DllMain)
//
//
//	/* Relocation */
//	// Determine where ImageBase was allocated
//
//	BYTE* LocationDelta = pBase - pOptional->ImageBase; // base_addr - image_base_addr = location_offset
//	//DWORD* LocationDelta = pBase - pOptional->ImageBase; // base_addr - image_base_addr = location_offset
//	//DWORD LocationDelta = (DWORD((LPBYTE)pData->lpImageBase - pData->NtHeaders->OptionalHeader.ImageBase));
//
//	if (LocationDelta) { // Not located at base_addr, relocation necessary
//
//		// Can't relocate, there's no data
//		if (!pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
//			return;
//		}
//
//		// Get data virtual address to relocate
//		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
//		const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
//
//		//while (pRelocData->VirtualAddress) {
//		while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
//			// Calculate the number of entries. (I don't really get this, check out the IMAGE_BASE_RELOCATION struct sometime I guess)
//			//UIT EntryCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(DWORD);
//			UINT EntryCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
//			
//
//			// Get position of TypeOffset array in IMAGE_BASE_RELOCATION by adding 8 bytes to pRelocData.
//			// sizeof(IMAGE_BASE_RELOCATION*) is 8 bytes so adding 1 to pRelocData does the same thing
//
//			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
//			//DWORD* pRelativeInfo = reinterpret_cast<DWORD*>(pRelocData + sizeof(IMAGE_BASE_RELOCATION));
//			//WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
//
//			// Iterate through entries in TypeOffset array
//			for (UINT i = 0; i != EntryCount; ++i, ++pRelativeInfo) {
//				// DWORD TypeOffset[]
//				   //- high 12-bits are relocation
//				   //- low 4-bits are relocation type flag
//
//				if (RELOC_FLAG(*pRelativeInfo)) {
//					// Get pointer to relocation address from pRelativeInfo (highest 12 bits)
//					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
//
//
//					// Insert DLL bytes into relocation address
//					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta); // ERROR: Writing to this address causes a MEMORY ACCESS VIOLATION EXCEPTION
//				}
//
//				// Shift pRelocData to next entry block (?)
//				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
//				//pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<DWORD*>(pRelocData) + pRelocData->SizeOfBlock);
//			}
//		}
//
//		// If data in import directory. (If 0, no data, so do nothing)
//		if (pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
//			auto* pImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
//			while (pImportDescriptor->Name) { // Iterate through Import Descriptor
//				// Grab name of current module to import
//				char* szModule = reinterpret_cast<char*>(pBase + pImportDescriptor->Name);
//
//				// Load import (with shellcode-imported LoadLibraryA function)
//				HINSTANCE hDll = _LoadLibraryA(szModule);
//
//				// First Thunk (whatever that is)
//				ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->OriginalFirstThunk);
//				ULONG_PTR* pFunctionRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->FirstThunk);
//
//				if (!pThunkRef) { // There's a chance OriginalFirstThunk isn't defined, so use FirstThunk instead
//					pThunkRef = pFunctionRef;
//				}
//
//				// Load Libraries
//				for (; *pThunkRef; ++pThunkRef, ++pFunctionRef) { // While pThunkRef is defined (Non-incremental for loop)
//					// Load functions (either through Name or Ordinal Number, depending on how it is defined)
//					if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) { // Import by Ordinal Number
//						// Ordinal Number is stored at *pThunkRef (grab lower 2 bytes to avoid warnings (?))
//						*pFunctionRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF)); // Use shellcode-imported GetProcAddress
//					}
//					else { // Import by Name
//						auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
//						*pFunctionRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
//					}
//				}
//				++pImportDescriptor;
//			}
//		}
//
//		// Executing Thread Local Storage (TLS) callbacks
//		if (pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
//			// Grab TLS virtual address
//			//auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
//			auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
//			auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
//		
//
//			// Iterate through callbacks
//			for (; pCallback && *pCallback; ++pCallback) {
//				(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr); // Execute callback
//			}
//		}
//
//#ifdef _WIN64
//		bool ExceptionSupportFailed = false;
//		if (pData->SEHSupport) {
//			auto excep = pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
//			if (excep.Size) {
//				if (!_RtlAddFunctionTable(
//					reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
//					excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
//					ExceptionSupportFailed = true;
//				}
//			}
//		}
//#endif
//
//
//
//		// Call DllMain() (Execute shellcode)
//		_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);
//
//		// Setting this address lets us determine if the injection succeeded 
//		// by checking it in our manual mapping code.
//
//		if (ExceptionSupportFailed) {
//			pData->hModule = reinterpret_cast<HINSTANCE>(0x505050);
//		}
//		else {
//			pData->hModule = reinterpret_cast<HINSTANCE>(pBase);
//		}
//
//	}
//
//	return;
//}