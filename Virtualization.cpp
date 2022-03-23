#include "globals.h"
#include "HideMemory.h"
#include "fun.h"
DWORD64 hidemem;

//如果只想读写的话可以删除这个锁,并打开在VEH处理函数内的锁, 要执行的话可能会在执行时触发双重异常,所以在这里加锁
//std::mutex m;

typedef NTSTATUS (NTAPI* _NtClose)(IN HANDLE ObjectHandle);
typedef NTSTATUS (NTAPI* _NtReadVirtualMemory)(HANDLE ProcessHandle,PVOID BaseAddress,PVOID Buffer,ULONG NumberOfBytesToRead,PULONG NumberOfBytesReaded);

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_INVALID_HANDLE            ((NTSTATUS)0xC0000008L)   


extern PSHARE_VEH pInfo;



typedef VOID(WINAPI *_testDemo)();
_testDemo pTestDemo = NULL;


BOOL IsMemoryHidden()
{
	MEMORY_BASIC_INFORMATION MemInfo = { 0 };
	VirtualQuery((LPVOID)hidemem, &MemInfo, sizeof(MemInfo));
	if (MemInfo.Protect != PAGE_NOACCESS)
	{		
		return FALSE;
	}
	return TRUE;
}

BOOL bOnce = FALSE;
void ReadThreadProc2()
{
	while (1)
	{

		if (!bOnce)
		{
			pTestDemo = (_testDemo)pInfo->export_fun;

			//因为是自己拉伸 必须要执行 pDllMain()
			ProcDllMain  pDllMain = ((ProcDllMain)(pInfo->DllOfEntryPoint));
			pDllMain(0, DLL_PROCESS_ATTACH, (PVOID)pInfo->DllBase);
			bOnce = TRUE;
		}
	
		/*	__try {
				pTestDemo();
			}
			__except (1)
			{

			}*/
		pTestDemo();
		printf("testDemo already run  %llx \n", pTestDemo);

		Sleep(1000);		
	}
}

void ReadThreadProc3()
{
	while (1)
	{
		ULONGLONG tick = GetTickCount64();
		//m.lock();
		printf("Thread3 ReadTime %llu ms Data:%llx\n", GetTickCount64() - tick, *(DWORD64*)hidemem);
		//m.unlock();
		Sleep(100);
	}
}


int main()
{
	WCHAR title[64];
	_snwprintf_s(title, sizeof(title), L"PID: %lx", GetCurrentProcessId());
	SetConsoleTitleW(title);
	
	Init();
	hidemem = AllocateHiddenMemory(NULL, 1, 
		[](DWORD64 lpAddress, size_t _Size) {
			for (int i = 0; i < _Size; i++)
			{
				((char*)lpAddress)[i] += (char)6;
				((char*)lpAddress)[i] = ((char*)lpAddress)[i] ^ 'a';
			}
		},
		[](DWORD64 lpAddress, size_t _Size) {
			for (int i = 0; i < _Size; i++)
			{
				((char*)lpAddress)[i] = ((char*)lpAddress)[i] ^ 'a';
				((char*)lpAddress)[i] -= (char)6;
			} 
		});	

	
	

	std::thread ReadThread1(ReadThreadProc2);
	//std::thread ReadThread2(ReadThreadProc3);

	//BOOL MessageBoxState = TRUE;

	getchar();

	//while (1)
	//{
	//	printf("Allocated %llx\n\n", hidemem);

	//	ULONGLONG tick = GetTickCount64();

	//	//R/W ==========================================================================================
	//	//m.lock();
	//	*(DWORD64*)hidemem += 1;
	//	printf("ReadWriteTime %llu ms Data:%llx\n", GetTickCount64() - tick, *(DWORD64*)hidemem);
	//	//m.unlock();
	//	//R/W ==========================================================================================

	//	//Execute =======================================================================================
	//	//tick = GetTickCount64(); 请查看当前文件头部的锁
	//	//m.lock();
	//	//if (ExecuteHiddenMemory())
	//	//	printf("ExecuteTime   %llu ms \n", GetTickCount64() - tick);
	//	//else
	//	//	printf("Execute Failed\n");
	//	//m.unlock();
	//	//Execute =======================================================================================


	//	//SEH ===========================================================================================
	//	tick = GetTickCount64();
	//	//m.lock();
	//	if(CheckSEH())
	//		printf("Support SEH   %llu ms\n", GetTickCount64() - tick);
	//	//m.unlock();
	//	//SEH ===========================================================================================

	//	Sleep(200);
	//	system("cls");
	//}

END:
	//m.lock();
	FreeHiddenMemory(hidemem);
	//m.unlock();
}

