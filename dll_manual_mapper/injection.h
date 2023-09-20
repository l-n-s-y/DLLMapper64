#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFileName);
//typedef HMODULE(__stdcall* f_LoadLibraryA)(LPCSTR);
using f_GetProcAddress = UINT_PTR(WINAPI*)(HINSTANCE hModule, const char* lpProcName);
//typedef FARPROC(__stdcall* f_GetProcAddress)(HMODULE, LPCSTR);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);
//typedef INT(__stdcall* f_DLL_ENTRY_POINT)(LPVOID, DWORD, LPVOID);

struct MANUAL_MAPPING_DATA {
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	HINSTANCE hModule;
};

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);

BOOL ManualMap(HANDLE hProc, const char* szDllFile); // szDllFile should be full path (not relative).