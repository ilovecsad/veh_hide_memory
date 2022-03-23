#include "loadLibary.h"
#include <Shlwapi.h>
//Shlwapi.lib

#define  DWORDX ULONG_PTR
static pfnRtlImageNtHeader RtlImageNtHeader_ = NULL;
static pfnImageDirectoryEntryToData RtlImageDirectoryEntryToData = NULL;
static pfnRtlFindExportedRoutineByName RtlFindExportedRoutineByName = NULL;
static pfnLdrProcessRelocationBlock LdrProcessRelocationBlock = NULL;
static RtlFreeUnicodeStringT RtlFreeUnicodeString_ = NULL;
static LdrLoadDllT LdrLoadDll_ = NULL;
static RtlAnsiStringToUnicodeStringT RtlAnsiStringToUnicodeString_ = NULL;
static RtlInitAnsiStringT RtlInitAnsiString_ = NULL;
static LdrGetProcedureAddressT LdrGetProcedureAddress_ = NULL;

BOOL initApi()
{
	HMODULE h = GetModuleHandle(L"ntdll.dll");
	RtlImageNtHeader_ = (pfnRtlImageNtHeader)GetProcAddress(h, "RtlImageNtHeader");
	RtlInitAnsiString_ = (RtlInitAnsiStringT)GetProcAddress(h, "RtlInitAnsiString");
	RtlAnsiStringToUnicodeString_ = (RtlAnsiStringToUnicodeStringT)GetProcAddress(h, "RtlAnsiStringToUnicodeString");
	LdrLoadDll_ = (LdrLoadDllT)GetProcAddress(h, "LdrLoadDll");
	RtlFreeUnicodeString_ = (RtlFreeUnicodeStringT)GetProcAddress(h, "RtlFreeUnicodeString");
	RtlImageDirectoryEntryToData = (pfnImageDirectoryEntryToData)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlImageDirectoryEntryToData");
	LdrGetProcedureAddress_ = (LdrGetProcedureAddressT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrGetProcedureAddress");
	if (!RtlImageNtHeader_ || !RtlInitAnsiString_ || !RtlAnsiStringToUnicodeString_ || !LdrLoadDll_ || !RtlFreeUnicodeString_ ||
		!RtlImageDirectoryEntryToData || !LdrGetProcedureAddress_) {
		return FALSE;
	}


	return TRUE;
}


PVOID MapFileByPath(LPCWSTR szFullPath, DWORD& pImageSize)
{
	if (!PathFileExistsW(szFullPath))
	{
		return NULL;
	}

	HANDLE hFile = CreateFile(
		szFullPath,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}

	DWORD dwSize = GetFileSize(hFile, NULL);
	if (dwSize == 0)
	{
		CloseHandle(hFile);
		return NULL;
	}



	PVOID pBuffer = malloc(dwSize);
	if (!pBuffer)
	{
		CloseHandle(hFile);
		return NULL;
	}

	RtlZeroMemory(pBuffer, dwSize);
	DWORD dwRet = 0;
	if (!ReadFile(hFile, pBuffer, dwSize, &dwRet, NULL))
	{
		CloseHandle(hFile);
		free(pBuffer);
		return NULL;
	}

	CloseHandle(hFile);


	PVOID ImageBase = NULL;

	if (!ImageFile((PBYTE)pBuffer, &ImageBase, pImageSize) || ImageBase == NULL)
	{
		free(pBuffer);
		return NULL;
	}

	//DebugLog(L"New ImageBase: 0x%08X", ImageBase);
	free(pBuffer);

	return ImageBase;
}


BOOL ImageFile(PVOID FileBuffer, PVOID* ImageModuleBase, DWORD& ImageSize)
{

	PIMAGE_DOS_HEADER ImageDosHeader = NULL;
	PIMAGE_NT_HEADERS ImageNtHeaders = NULL;
	PIMAGE_SECTION_HEADER ImageSectionHeader = NULL;
	DWORD FileAlignment = 0, SectionAlignment = 0, NumberOfSections = 0, SizeOfImage = 0, SizeOfHeaders = 0;
	DWORD Index = 0;
	PVOID ImageBase = NULL;
	DWORD SizeOfNtHeaders = 0;

	if (!FileBuffer || !ImageModuleBase)
	{
		return FALSE;
	}

	__try
	{
		ImageDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
		if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return FALSE;
		}

		ImageNtHeaders = RtlImageNtHeader_(FileBuffer);


		if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			return FALSE;
		}

		FileAlignment = ImageNtHeaders->OptionalHeader.FileAlignment;
		SectionAlignment = ImageNtHeaders->OptionalHeader.SectionAlignment;
		NumberOfSections = ImageNtHeaders->FileHeader.NumberOfSections;
		SizeOfImage = ImageNtHeaders->OptionalHeader.SizeOfImage;
		SizeOfHeaders = ImageNtHeaders->OptionalHeader.SizeOfHeaders;
		SizeOfImage = AlignSize(SizeOfImage, SectionAlignment);

		ImageSize = SizeOfImage;

		ImageBase = malloc(SizeOfImage);
		if (ImageBase == NULL)
		{
			return FALSE;
		}
		RtlZeroMemory(ImageBase, SizeOfImage);

		SizeOfNtHeaders = sizeof(ImageNtHeaders->FileHeader) + sizeof(ImageNtHeaders->Signature) + ImageNtHeaders->FileHeader.SizeOfOptionalHeader;
		ImageSectionHeader = IMAGE_FIRST_SECTION(ImageNtHeaders);

		for (Index = 0; Index < NumberOfSections; Index++)
		{
			ImageSectionHeader[Index].SizeOfRawData = AlignSize(ImageSectionHeader[Index].SizeOfRawData, FileAlignment);
			ImageSectionHeader[Index].Misc.VirtualSize = AlignSize(ImageSectionHeader[Index].Misc.VirtualSize, SectionAlignment);
		}

		if (ImageSectionHeader[NumberOfSections - 1].VirtualAddress + ImageSectionHeader[NumberOfSections - 1].SizeOfRawData > SizeOfImage)
		{
			ImageSectionHeader[NumberOfSections - 1].SizeOfRawData = SizeOfImage - ImageSectionHeader[NumberOfSections - 1].VirtualAddress;
		}

		RtlCopyMemory(ImageBase, FileBuffer, SizeOfHeaders);

		for (Index = 0; Index < NumberOfSections; Index++)
		{
			DWORD FileOffset = ImageSectionHeader[Index].PointerToRawData;
			DWORD Length = ImageSectionHeader[Index].SizeOfRawData;
			ULONG64 ImageOffset = ImageSectionHeader[Index].VirtualAddress;
			RtlCopyMemory(&((PBYTE)ImageBase)[ImageOffset], &((PBYTE)FileBuffer)[FileOffset], Length);
		}

		*ImageModuleBase = ImageBase;


	}
	__except (1)
	{
		if (ImageBase)
		{
			free(ImageBase);
			ImageBase = NULL;
		}

		*ImageModuleBase = NULL;
		return FALSE;
	}

	return TRUE;
}

UINT AlignSize(UINT nSize, UINT nAlign)
{
	return ((nSize + nAlign - 1) / nAlign * nAlign);
}


BOOL FixImportTable(PVOID pBuffer, ULONG_PTR dwLoadMemoryAddress)
{
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	ANSI_STRING ansiStr;
	UNICODE_STRING UnicodeString;


	pNtHeaders = RtlImageNtHeader_(pBuffer);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	ULONG_PTR Offset = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	PIMAGE_IMPORT_DESCRIPTOR pID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pBuffer + Offset);
	PIMAGE_IMPORT_BY_NAME pByName = NULL;

	while (pID->Characteristics != 0)
	{
		PIMAGE_THUNK_DATA pRealIAT = (PIMAGE_THUNK_DATA)((ULONG_PTR)pBuffer + pID->FirstThunk);
		PIMAGE_THUNK_DATA pOriginalIAT = (PIMAGE_THUNK_DATA)((ULONG_PTR)pBuffer + pID->OriginalFirstThunk);
		//获取dll的名字
		char* pName = (char*)((ULONG_PTR)pBuffer + pID->Name);
		HANDLE hDll = 0;


		RtlInitAnsiString_(&ansiStr, pName);


		RtlAnsiStringToUnicodeString_(&UnicodeString, &ansiStr, true);


		LdrLoadDll_(NULL, NULL, &UnicodeString, &hDll);
	

		RtlFreeUnicodeString_(&UnicodeString);

		if (hDll == NULL) {

			return FALSE;
		}

		//获取DLL中每个导出函数的地址，填入IAT
		//每个IAT结构是 ：
		// union { PBYTE ForwarderString;
		// PDWORDX Function;
		// DWORDX Ordinal;
		// PIMAGE_IMPORT_BY_NAME AddressOfData;
		// } u1;
		// 长度是一个DWORDX ，正好容纳一个地址。
		for (ULONG i = 0; ; i++)
		{
			if (pOriginalIAT[i].u1.Function == 0)break;
			FARPROC lpFunction = NULL;
			if (IMAGE_SNAP_BY_ORDINAL(pOriginalIAT[i].u1.Ordinal)) //这里的值给出的是导出序号
			{
				if (IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal))
				{
	
					LdrGetProcedureAddress_(hDll, NULL, IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal), &lpFunction);
				}
			}
			else//按照名字导入
			{
				//获取此IAT项所描述的函数名称
				pByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)pBuffer + (ULONG_PTR)(pOriginalIAT[i].u1.AddressOfData));
				if ((char *)pByName->Name)
				{
					RtlInitAnsiString_(&ansiStr, (char *)pByName->Name);

					LdrGetProcedureAddress_(hDll, &ansiStr, 0, &lpFunction);

				}

			}

			//标记***********

			if (lpFunction != NULL) //找到了！
				pRealIAT[i].u1.Function = (ULONG_PTR)lpFunction;
			else {
				return FALSE;
			}
		}

		//move to next
		pID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pID + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}

	return FixBaseRelocTable(pBuffer, dwLoadMemoryAddress);

}







BOOL FixBaseRelocTable(PVOID pBuffer, ULONG_PTR dwLoadMemoryAddress)
{

	PIMAGE_NT_HEADERS pNTHeader = NULL;

	pNTHeader = RtlImageNtHeader_(pBuffer);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	__try {

		if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0
			&& pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
		{

			DWORDX Delta = (DWORDX)dwLoadMemoryAddress - pNTHeader->OptionalHeader.ImageBase;
			DWORDX * pAddress;
			//注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址
			PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((DWORDX)pBuffer
				+ pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
			{
				WORD *pLocData = (WORD *)((DWORDX)pLoc + sizeof(IMAGE_BASE_RELOCATION));
				//计算本节需要修正的重定位项（地址）的数目
				int NumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				for (int i = 0; i < NumberOfReloc; i++)
				{
					if ((DWORDX)(pLocData[i] & 0xF000) == 0x00003000 || (DWORDX)(pLocData[i] & 0xF000) == 0x0000A000) //这是一个需要修正的地址
					{
						// 举例：
						// pLoc->VirtualAddress = 0×1000;
						// pLocData[i] = 0×313E; 表示本节偏移地址0×13E处需要修正
						// 因此 pAddress = 基地址 + 0×113E
						// 里面的内容是 A1 ( 0c d4 02 10) 汇编代码是： mov eax , [1002d40c]
						// 需要修正1002d40c这个地址
						pAddress = (DWORDX *)((DWORDX)pBuffer + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
						*pAddress += Delta;
					}
				}
				//转移到下一个节进行处理
				pLoc = (PIMAGE_BASE_RELOCATION)((DWORDX)pLoc + pLoc->SizeOfBlock);
			}
			/***********************************************************************/
		}
		pNTHeader->OptionalHeader.ImageBase = (DWORDX)dwLoadMemoryAddress;
	}
	__except (1) {
		return FALSE;
	}
	return TRUE;
}

PSHARE_VEH my_loadLibrary(const WCHAR * szDllPath)
{
	PSHARE_VEH pInfo = NULL;
	if (!PathFileExistsW(szDllPath))
	{
		OutputDebugPrintf("hzw:DLL路径不存在,已经退出-%ws\n", szDllPath);
		return NULL;
	}

	if (!initApi()) {
		OutputDebugPrintf("hzw:initApi失败,已经退出\n");
		return NULL;
	}

	if (!InitFileMapping(&pInfo)) {

		OutputDebugPrintf("hzw:创建共享内存失败 %d,已经退出\n",GetLastError());
		return NULL;
	}

	DWORD dwImageSize = 0;

	PVOID pBufferFromPe = MapFileByPath(szDllPath, dwImageSize);
	if (pBufferFromPe && dwImageSize)
	{

		PIMAGE_NT_HEADERS pNtHeaders = RtlImageNtHeader_(pBufferFromPe);

		PVOID pTargetAddress = VirtualAlloc(NULL, dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pTargetAddress)
		{
			OutputDebugPrintf("hzw:申请地址失败,已经退出\n");
			UnmapViewOfFile(pInfo);
			pInfo = NULL;
			goto __end;
		}

		if (!FixImportTable(pBufferFromPe, (ULONG_PTR)pTargetAddress)) {
			OutputDebugPrintf("hzw:修复重定位or导出表 fail,已经退出\n");
			UnmapViewOfFile(pInfo);
			pInfo = NULL;
			goto __end;
		}
		
		SIZE_T dwRetSize = 0;
		if (!WriteProcessMemory(GetCurrentProcess(), pTargetAddress, pBufferFromPe, dwImageSize, &dwRetSize))
		{
			OutputDebugPrintf("hzw:写入 目标地址失败 %llx,已经退出\n",pTargetAddress);
			UnmapViewOfFile(pInfo);
			pInfo = NULL;
			goto __end;
		}

	
		//RtlZeroMemory(pTargetAddress, pNtHeaders->OptionalHeader.SizeOfHeaders);

		pInfo->DllBase = (ULONG_PTR)pTargetAddress;
		pInfo->export_fun = 0x10D0 + (ULONG_PTR)pTargetAddress;
		pInfo->DllOfEntryPoint = (ULONG_PTR)pNtHeaders->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)pTargetAddress;
		pInfo->DllImageSize = dwRetSize;

	}
__end:

	if (pBufferFromPe)
	{
		free(pBufferFromPe);
		pBufferFromPe = NULL;
	}
	return pInfo;
}


BOOL InitFileMapping(PSHARE_VEH* p)
{
	SECURITY_ATTRIBUTES sa = { 0 };
	SECURITY_DESCRIPTOR sd = { 0 };
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
	sa.bInheritHandle = FALSE;
	sa.lpSecurityDescriptor = &sd;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	HANDLE hFileMapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_EXECUTE_READWRITE, 0, sizeof(PSHARE_VEH), MAP_VEH);
	*p = (PSHARE_VEH)MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (hFileMapping == NULL)
	{

		return false;
	}

	if (*p == NULL)
	{
		return false;
	}

	return true;
}
void OutputDebugPrintf(const char * strOutputString, ...)
{
#define PUT_PUT_DEBUG_BUF_LEN   256
	char strBuffer[PUT_PUT_DEBUG_BUF_LEN] = { 0 };
	va_list vlArgs;
	va_start(vlArgs, strOutputString);
	_vsnprintf_s(strBuffer, sizeof(strBuffer) - 1, strOutputString, vlArgs);  //_vsnprintf_s  _vsnprintf
	//vsprintf(strBuffer,strOutputString,vlArgs);
	va_end(vlArgs);
	OutputDebugStringA(strBuffer);  //OutputDebugString    // OutputDebugStringW

}