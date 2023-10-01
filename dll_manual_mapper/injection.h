#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFileName);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

struct MANUAL_MAPPING_DATA {
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
	f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
	HINSTANCE hModule;

	// ADDITIONS
	BYTE* pBase;
	DWORD fdwReasonParam;
	LPVOID reservedParam;
	BOOL SEHSupport;
};

//BOOL ManualMap(HANDLE hProc, BYTE* pSourceData, const char* szDllFile); // szDllFile should be full path (not relative).
//BOOL ManualMap(HANDLE hProc, BYTE* pSourceData); // szDllFile should be full path (not relative).
bool ManualMap(HANDLE hProc, BYTE* pSrcData, bool ClearHeader=true, bool ClearNonNeededSections=true, bool AdjustProtections=true, bool SEHExceptionSupport=true, DWORD fdwReason=DLL_PROCESS_ATTACH, LPVOID lpReserved=0);
void WINAPI Shellcode(MANUAL_MAPPING_DATA* pData);