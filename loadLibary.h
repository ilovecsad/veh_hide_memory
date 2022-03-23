#pragma once

#include <Windows.h>
#include <Winternl.h>
#include "fun.h"
using namespace std;




typedef PVOID(WINAPI* pfnRtlFindExportedRoutineByName)(
	IN PVOID DllBase,
	IN PANSI_STRING AnsiImageRoutineName
	);
typedef PVOID(WINAPI* pfnImageDirectoryEntryToData)(
	_In_ PVOID Base,
	_In_ BOOLEAN MappedAsImage,
	_In_ USHORT DirectoryEntry,
	_Out_ PULONG Size
	);
typedef  PIMAGE_BASE_RELOCATION(WINAPI* pfnLdrProcessRelocationBlock)(IN ULONG_PTR VA, IN ULONG SizeOfBlock, IN PUSHORT NextOffset, IN LONGLONG Diff);
typedef PIMAGE_NT_HEADERS(WINAPI* pfnRtlImageNtHeader)(PVOID Base);
typedef NTSTATUS(WINAPI *LdrGetProcedureAddressT)(IN PVOID DllHandle, IN PANSI_STRING ProcedureName OPTIONAL, IN ULONG ProcedureNumber OPTIONAL, OUT FARPROC *ProcedureAddress);
typedef VOID(WINAPI *RtlFreeUnicodeStringT)(_Inout_ PUNICODE_STRING UnicodeString);
typedef  VOID(WINAPI *RtlInitAnsiStringT)(_Out_    PANSI_STRING DestinationString, _In_opt_ PCSZ         SourceString);
typedef NTSTATUS(WINAPI *RtlAnsiStringToUnicodeStringT)(_Inout_ PUNICODE_STRING DestinationString, _In_ PCANSI_STRING SourceString, _In_ BOOLEAN AllocateDestinationString);
typedef NTSTATUS(WINAPI *LdrLoadDllT)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef BOOL(APIENTRY *ProcDllMain)(LPVOID, DWORD, LPVOID);
typedef NTSTATUS(WINAPI *NtAllocateVirtualMemoryT)(IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress, IN ULONG ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);
PVOID MapFileByPath(LPCWSTR szFullPath, DWORD& pFileSize);
BOOL ImageFile(PVOID FileBuffer, PVOID* ImageModuleBase, DWORD& ImageSize);
UINT AlignSize(UINT nSize, UINT nAlign);
BOOL FixImportTable(PVOID pBuffer, ULONG_PTR dwLoadMemoryAddress);
BOOL FixBaseRelocTable(PVOID pBuffer, ULONG_PTR dwLoadMemoryAddress);
PSHARE_VEH my_loadLibrary(const WCHAR* szDllPath);
BOOL InitFileMapping(PSHARE_VEH* p);
BOOL initApi();
