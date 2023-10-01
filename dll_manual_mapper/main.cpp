/* DLL Manual Mapper */

/* Concept:
* To do what LoadLibrary() does, manually.
* - Undetectable (hopefully)
* - Module isn't linked to process environment
* - Kernel won't know the module exists, so NtQueryVirtualMemory won't find anything
*/

/* Method:
* 1. Load DLL as raw data into target process
* 2. Map DLL sections into target process
* 3. Inject shellcode into target process and run
* 4. Shellcode will relocate DLL,
*	- Fix imports,
*	- Execute TLS (thread local storage) callbacks,
*	- Call DLLMain()
* 5. Cleanup
*	- Deallocating memory in target process
*	- Deallocating buffers in injector
*/

//#include "debug.hpp"
//#include "injection.h"
//
//#define INVALID_PID_VALUE 0xcccccccc
//
//
//#define CREATE_NEW_PROC false
//// DLL path
//#ifdef _WIN64
////#define CREATE_NEW_PROC true
//const char szDllFile[] = "C:\\Users\\me\\Documents\\Programming\\Cheats\\DLLs\\DummyDLLS\\x64\\Debug\\DummyDLLs.dll";
//const char szProcName[] = "mspaint.exe"; // Process Name
//#else
//const char szDllFile[] = "C:\\Users\\me\\Documents\\Programming\\Cheats\\DLLs\\DummyDLLs\\Debug\\DummyDLLs.dll";
//const char szProcName[] = "csgo.exe";
//#endif
//const char szProcPath[] = "C:\\Windows\\System32";
////const char szProcName[] = "C:\\Windows\\System32\\mspaint.exe"; // Process Name
//
//int main() {
//	PROCESSENTRY32 PE32{ 0 };
//	PE32.dwSize = sizeof(PE32);
//
//	// Create new process if true;
//	// else attach to existing proc
//	DWORD dwPID = INVALID_PID_VALUE;
//	HANDLE hProcess;
//	if (!CREATE_NEW_PROC) {
//		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//		if (hSnapshot == INVALID_HANDLE_VALUE) {
//			DbgErr("[main] CreateToolhelp32Snapshot failed");
//			return 1;
//		}
//		DbgSuc("[main] Grabbed Toolhelp Snapshot");
//
//		// Grab target pid
//		BOOL bRet = Process32First(hSnapshot, &PE32);
//		DbgLog("[main] Scanning running processes");
//		while (bRet) {
//			if (!strcmp(szProcName, PE32.szExeFile) ) {
//				DbgSuc("[main] Found target process");
//				dwPID = PE32.th32ProcessID;
//				break;
//			}
//			bRet = Process32Next(hSnapshot, &PE32);
//		}
//
//		CloseHandle(hSnapshot);
//
//		if (dwPID == INVALID_PID_VALUE) {
//			DbgErr("[main] Target process couldn't be found", false);
//			return 1;
//		}
//	}
//	else {
//		STARTUPINFO si;
//		//ZeroMemory(&si, sizeof(si));
//		memset(&si, 0, sizeof(si));
//		si.cb = sizeof(si);
//
//		PROCESS_INFORMATION pi;
//		//ZeroMemory(&pi, sizeof(pi));
//		memset(&pi, 0, sizeof(pi));
//
//		string szAbsolutePath = string(szProcPath + string("\\") + szProcName);
//		BOOL bProcessCreated = CreateProcessA(szAbsolutePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
//		if (!bProcessCreated) {
//			DbgErr("[main] Couldn't create new target process");
//			return 1;
//		}
//		dwPID = pi.dwProcessId;
//		DbgSuc("[main] Created new target process");
//		DbgSleep(1); // Pause to bask in the new window
//		CloseHandle(pi.hProcess);
//		CloseHandle(pi.hThread);
//	}
//
//	// Open target process
//	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwPID);
//	if (hProcess == INVALID_HANDLE_VALUE) {
//		DbgErr("[main] OpenProcess failed");
//		return 1;
//	}
//	DbgSuc("[main] Opened target process");
//
//	// Map DLL into target proc
//	if (!ManualMap(hProcess, szDllFile)) {
//		DbgErr("[main] ManualMap failed",false);
//		CloseHandle(hProcess);
//		return 1;
//	}
//	DbgSuc("[main] ManualMap succeeded");
//
//	// Clean up proc handle
//	CloseHandle(hProcess);
//
//	Goodbye();
//	return 0;
//}


/* DLL Manual Mapper */

/* Concept:
* To do what LoadLibrary() does, manually.
* - Undetectable (hopefully)
* - Module isn't linked to process environment
* - Kernel won't know the module exists, so NtQueryVirtualMemory won't find anything
*/

/* Method:
* 1. Load DLL as raw data into target process
* 2. Map DLL sections into target process
* 3. Inject shellcode into target process and run
* 4. Shellcode will relocate DLL,
*	- Fix imports,
*	- Execute TLS (thread local storage) callbacks,
*	- Call DLLMain()
* 5. Cleanup
*	- Deallocating memory in target process
*	- Deallocating buffers in injector
*/

#include "injection.h"
#include "debug.hpp"

#define INVALID_PID_VALUE 0xcccccccc

#define CREATE_NEW_PROC false

// DLL path
#ifdef _WIN64
//const char szDllFile[] = "C:\\Users\\me\\Documents\\Programming\\Cheats\\DLLMapper64\\DummyDLLs.dll";
//const char szDllFile[] = "C:\\Users\\me\\Documents\\Programming\\Cheats\\Examples\\Simple-Manual-Map-Injector\\hello-world-x64.dll";
wchar_t* szDllFile = (wchar_t*)L"C:\\Users\\me\\Documents\\Programming\\Cheats\\Examples\\Simple-Manual-Map-Injector\\hello-world-x64.dll";

//const char szProcName[] = "mspaint.exe"; // Process Name
wchar_t* szProcName = (wchar_t*)L"mspaint.exe";
#else
const char szDllFile[] = "C:\\Users\\me\\Documents\\Programming\\Cheats\\DLLMapper64\\csgo_x32.dll";
const char szProcName[] = "csgo.exe";
#endif
//const char szProcPath[] = "C:\\Windows\\System32"; // Process Name
const wchar_t szProcPath[] = L"C:\\Windows\\System32"; // Process Name


// Check injector arch vs target proc arch
bool IsCorrectArchitecture(HANDLE hProc) {
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget)) {
		DbgErr("[IsCorrectArchitecture] Couldn't establish process arch",true);
		return false;
	}
	BOOL bHost = FALSE;
	IsWow64Process(GetCurrentProcess(), &bHost);

	return (bTarget == bHost);
}

int main() {
	PROCESSENTRY32W PE32{ 0 };
	PE32.dwSize = sizeof(PE32);

	// Create new process if true;
	// else attach to existing proc
	DWORD dwPID = INVALID_PID_VALUE;
	if (!CREATE_NEW_PROC) {
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			DbgErr("[main] CreateToolhelp32Snapshot failed");
			return 1;
		}
		DbgSuc("[main] Grabbed Toolhelp Snapshot");

		// Grab target pid
		BOOL bRet = Process32FirstW(hSnapshot, &PE32);
		DbgLog("[main] Scanning running processes");
		while (bRet) {
			//if (!strcmp(szProcName, PE32.szExeFile)) {
			if (!_wcsicmp(szProcName, PE32.szExeFile)) {
				DbgSuc("[main] Found target process");
				dwPID = PE32.th32ProcessID;
				break;
			}
			bRet = Process32NextW(hSnapshot, &PE32);
		}
		CloseHandle(hSnapshot);

		if (dwPID == INVALID_PID_VALUE) {
			DbgErr("[main] Target process couldn't be found", false);
			return 1;
		}
	}
	else {
		//STARTUPINFO si;
		//ZeroMemory(&si, sizeof(si));
		//si.cb = sizeof(si);

		//PROCESS_INFORMATION pi;
		//ZeroMemory(&pi, sizeof(pi));

		////string szAbsolutePath = string(szProcPath + string("\\") + static_cast<string>(szProcName));
		//wstring szAbsolutePath = szProcPath + wstring(L"\\") + szProcName;
		//BOOL bProcessCreated = CreateProcessA(szAbsolutePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
		//if (!bProcessCreated) {
		//	DbgErr("[main] Couldn't create new target process");
		//	return 1;
		//}
		//dwPID = pi.dwProcessId;
		//pi.hProcess = nullptr;
		//pi.hThread = nullptr;
		//DbgSuc("[main] Created new target process");
		//DbgSleep(1); // Pause to bask in the new window
	}

	DWORD dwCheck = 0;
	if (!GetFileAttributes(szDllFile)) {
		DbgErr("[main] File doesn't exist", false);
		return false;
	}

	

	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid)) {
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
		}

		CloseHandle(hToken);
	}


	// Open target process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (!hProcess) {
		DbgErr("[main] OpenProcess failed");
		return 1;
	}
	DbgSuc("[main] Opened target process");

	if (!IsCorrectArchitecture(hProcess)) {
		DbgErr("[main] Target architecture is invalid");
		return 1;
	}
	DbgSuc("[main] Target architecture is valid");

	if (GetFileAttributes(szDllFile) == INVALID_FILE_ATTRIBUTES) {
		DbgErr("[main] DLL File doesn't exist");
		CloseHandle(hProcess);
		return 1;
	}

	// Open DLL File
	ifstream File(szDllFile, ios::binary | ios::ate);
	if (File.fail()) {
		// File error comes from File.rdstate(), instead of GetLastError()
		// ...for some reason
		DbgErr("[main] File failed", false, (DWORD)File.rdstate());
		File.close();
		return false;
	}
	DbgSuc("[main] Opened DLL");

	// Get filesize
	auto FileSize = File.tellg();
	if (FileSize < 0x1000) {
		DbgErr("[main] File size is invalid", false);
		File.close();
		return false;
	}

	//size_t SourceDataSize = static_cast<UINT_PTR>(FileSize);
	BYTE* pSourceData = new BYTE[(UINT_PTR)FileSize];
	//BYTE* pSourceData = (BYTE*)new BYTE[(UINT_PTR)FileSize];
	//pSourceData = new DWORD[static_cast<UINT_PTR>(FileSize)];

	if (!pSourceData) {
		DbgErr("[main] SourceData memory allocation failed");
		File.close();
		return false;
	}
	DbgSuc("[main] Allocated SourceData memory");

	// Shift to beginning of DLL
	File.seekg(0, ios::beg);
	File.read((char*)(pSourceData), FileSize);
	File.close();
	DbgSuc("[main] Read DLL bytes into allocated memory");

	// Map DLL into target proc

	if (!ManualMap(hProcess, pSourceData)) {
		DbgErr("[main] ManualMap failed");
		CloseHandle(hProcess);
		return 1;
	}
	DbgSuc("[main] ManualMap succeeded");

	// Clean up proc handle
	CloseHandle(hProcess);

	Goodbye();
	return 0;
}
