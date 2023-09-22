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
//#define CREATE_NEW_PROC true
const char szDllFile[] = "C:\\Users\\melti\\Documents\\Programming\\Cheats\\csgo_internal_tutorial\\x64\\csgo_internal_tutorial.dll";
const char szProcName[] = "mspaint.exe"; // Process Name
#else
const char szDllFile[] = "C:\\Users\\melti\\Documents\\Programming\\Cheats\\csgo_internal_tutorial\\x32\\csgo_internal_tutorial.dll";
const char szProcName[] = "csgo.exe";
#endif
const char szProcPath[] = "C:\\Windows\\System32";
//const char szProcName[] = "C:\\Windows\\System32\\mspaint.exe"; // Process Name

int main() {
	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);

	// Create new process if true;
	// else attach to existing proc
	DWORD dwPID = INVALID_PID_VALUE;
	HANDLE hProcess;
	if (!CREATE_NEW_PROC) {
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			DbgErr("[main] CreateToolhelp32Snapshot failed");
			return 1;
		}
		DbgSuc("[main] Grabbed Toolhelp Snapshot");

		// Grab target pid
		BOOL bRet = Process32First(hSnapshot, &PE32);
		DbgLog("[main] Scanning running processes");
		while (bRet) {
			if (!strcmp(szProcName, PE32.szExeFile) ) {
				DbgSuc("[main] Found target process");
				dwPID = PE32.th32ProcessID;
				break;
			}
			bRet = Process32Next(hSnapshot, &PE32);
		}

		CloseHandle(hSnapshot);

		if (dwPID == INVALID_PID_VALUE) {
			DbgErr("[main] Target process couldn't be found", false);
			return 1;
		}
	}
	else {
		STARTUPINFO si;
		//ZeroMemory(&si, sizeof(si));
		memset(&si, 0, sizeof(si));
		si.cb = sizeof(si);

		PROCESS_INFORMATION pi;
		//ZeroMemory(&pi, sizeof(pi));
		memset(&pi, 0, sizeof(pi));

		string szAbsolutePath = string(szProcPath + string("\\") + szProcName);
		BOOL bProcessCreated = CreateProcessA(szAbsolutePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
		if (!bProcessCreated) {
			DbgErr("[main] Couldn't create new target process");
			return 1;
		}
		dwPID = pi.dwProcessId;
		DbgSuc("[main] Created new target process");
		DbgSleep(1); // Pause to bask in the new window
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	// Open target process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE) {
		DbgErr("[main] OpenProcess failed");
		return 1;
	}
	DbgSuc("[main] Opened target process");

	// Map DLL into target proc
	if (!ManualMap(hProcess, szDllFile)) {
		DbgErr("[main] ManualMap failed",false);
		CloseHandle(hProcess);
		return 1;
	}
	DbgSuc("[main] ManualMap succeeded");

	// Clean up proc handle
	CloseHandle(hProcess);

	Goodbye();
	return 0;
}
