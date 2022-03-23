#pragma once
#include <windows.h>
#include <windef.h>
#include <stdio.h>
#include <psapi.h>


#define MAP_VEH L"hzw_veh"
#define TYPE 0




#define DLL_NAME L"C:\\demo64.dll"






typedef struct _SHARE_VEH_
{
	ULONG DllImageSize;
	ULONG64 DllBase;
	ULONG64 export_fun;
	ULONG64 DllOfEntryPoint;
}SHARE_VEH, *PSHARE_VEH;


void OutputDebugPrintf(const char * strOutputString, ...);
typedef BOOL(APIENTRY *ProcDllMain)(LPVOID, DWORD, LPVOID);



