#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <windows.h>
#include <conio.h>

#ifdef _WIN64
#define ADDRESS INT64
#else
#define ADDRESS INT32
#endif  

#define DENY_LIST_COUNT 32

typedef struct BREAK_POINT_INFO
{
	HANDLE ProcessHandle;

	CHAR* TargetName;
	HMODULE TargetModule;

	LPVOID* BreakPoint;
	BYTE* BreakPointOriginal;
	CHAR** BreakPointSymbol;
	DWORD BreakPointCount;

}BREAK_POINT_INFO;

typedef struct SYMBOL_FIND_INFO
{
	CHAR* AllowSymbol[32];
	DWORD AllowSymbolCount;
	CHAR* DenySymbol[32];
	DWORD DenySymbolCount;
}SYMBOL_FIND_INFO;

typedef struct DEBUG_INFO
{
	BOOL signal;
	FILE* fp;
	SYMBOL_FIND_INFO SymbolInfo;
	BREAK_POINT_INFO BpInfo;
}DEBUG_INFO;


DWORD GetProcedureNameNumber(ADDRESS hModule)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	int* ExportTableRva;
	int NameIndex = 0;
	ADDRESS ExportTableVa;
	ADDRESS ExportNames;
	PIMAGE_EXPORT_DIRECTORY ExportTableHeader;

	pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + hModule);

	ExportTableRva = (int*)(&pNtHeader->OptionalHeader.DataDirectory[0]);
	ExportTableVa = (ADDRESS)*ExportTableRva;
	ExportTableVa += hModule;

	ExportTableHeader = (PIMAGE_EXPORT_DIRECTORY)ExportTableVa;
	ExportNames = ExportTableHeader->AddressOfNames;
	ExportNames += hModule;

	int* NameRVA = (int*)((ADDRESS)ExportTableHeader->AddressOfNames + hModule);

	return (DWORD)ExportTableHeader->NumberOfNames - 1;
}

DWORD GetProcedureNumber(ADDRESS hModule)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	int* ExportTableRva;
	int NameIndex = 0;
	ADDRESS ExportTableVa;
	ADDRESS ExportNames;
	PIMAGE_EXPORT_DIRECTORY ExportTableHeader;

	pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + hModule);

	ExportTableRva = (int*)(&pNtHeader->OptionalHeader.DataDirectory[0]);
	ExportTableVa = (ADDRESS)*ExportTableRva;
	ExportTableVa += hModule;

	ExportTableHeader = (PIMAGE_EXPORT_DIRECTORY)ExportTableVa;
	ExportNames = ExportTableHeader->AddressOfNames;
	ExportNames += hModule;

	int* NameRVA = (int*)((ADDRESS)ExportTableHeader->AddressOfNames + hModule);

	return (DWORD)ExportTableHeader->NumberOfFunctions - 1;
}

ADDRESS GetProcedureAddressNameFromIndex(ADDRESS hModule, DWORD ProcedureIndex)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	int* ExportTableRva;
	int NameIndex = 0;
	ADDRESS ExportTableVa;
	ADDRESS ExportNames;
	PIMAGE_EXPORT_DIRECTORY ExportTableHeader;

	pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + hModule);

	ExportTableRva = (int*)(&pNtHeader->OptionalHeader.DataDirectory[0]);
	ExportTableVa = (ADDRESS)*ExportTableRva;
	ExportTableVa += hModule;

	ExportTableHeader = (PIMAGE_EXPORT_DIRECTORY)ExportTableVa;
	ExportNames = ExportTableHeader->AddressOfNames;
	ExportNames += hModule;

	int* NameRVA = (int*)((ADDRESS)ExportTableHeader->AddressOfNames + hModule);

	return (ADDRESS)((char*)((int)NameRVA[ProcedureIndex] + hModule));
}

const char* FindString(const char* MainString, const char* SubString)
{
	return strstr(MainString, SubString);
}

int InitializeTargetModuleBreakPoints(DEBUG_INFO* DebugInfo)
{
	//get API address from index
	DWORD NameCount = GetProcedureNameNumber((ADDRESS)DebugInfo->BpInfo.TargetModule);

	DebugInfo->BpInfo.BreakPointSymbol = (CHAR**)malloc(NameCount * sizeof(CHAR*));
	DebugInfo->BpInfo.BreakPointOriginal = (BYTE*)malloc(GetProcedureNumber((ADDRESS)DebugInfo->BpInfo.TargetModule) * sizeof(BYTE*));
	DebugInfo->BpInfo.BreakPoint = (LPVOID*)malloc(GetProcedureNumber((ADDRESS)DebugInfo->BpInfo.TargetModule) * sizeof(LPVOID));

	for (DWORD i = 0; i != NameCount; i += 1)
	{
		DebugInfo->BpInfo.BreakPointSymbol[i] = (CHAR*)GetProcedureAddressNameFromIndex((ADDRESS)DebugInfo->BpInfo.TargetModule, i);

		BOOL error = TRUE;
		for (DWORD k = 0; k != DebugInfo->SymbolInfo.DenySymbolCount; k += 1)
		{
			if (strstr(DebugInfo->BpInfo.BreakPointSymbol[i], DebugInfo->SymbolInfo.DenySymbol[k]) != NULL)
			{
				error = FALSE;
				break;
			}
		}

		DebugInfo->BpInfo.BreakPoint[i] = 0;
		if (error == TRUE)
		{
			for (DWORD k = 0; k != DebugInfo->SymbolInfo.AllowSymbolCount; k += 1)
			{
				if (strstr(DebugInfo->BpInfo.BreakPointSymbol[i], DebugInfo->SymbolInfo.AllowSymbol[k]) != NULL)
				{
					DebugInfo->BpInfo.BreakPoint[i] = GetProcAddress(DebugInfo->BpInfo.TargetModule, DebugInfo->BpInfo.BreakPointSymbol[i]);

					//printf("[%p]\t%s\n", DebugInfo->BpInfo.BreakPoint[i], DebugInfo->BpInfo.BreakPointSymbol[i]);

					ReadProcessMemory(
						DebugInfo->BpInfo.ProcessHandle,
						DebugInfo->BpInfo.BreakPoint[i],
						&DebugInfo->BpInfo.BreakPointOriginal[i],
						sizeof(DebugInfo->BpInfo.BreakPointOriginal[i]),
						NULL
					);

					BYTE int3 = 0xCC;

					WriteProcessMemory(
						DebugInfo->BpInfo.ProcessHandle,
						DebugInfo->BpInfo.BreakPoint[i],
						&int3,
						sizeof(int3),
						NULL
					);

					DebugInfo->BpInfo.BreakPointCount += 1;

					break;
				}
			}
		}
	}

	return 0;
}


void CleanupTargetModuleBreakPoints(DEBUG_INFO* DebugInfo)
{
	//get API address from index
	DWORD NameCount = GetProcedureNameNumber((ADDRESS)DebugInfo->BpInfo.TargetModule);

	int j = 0;
	for (int i = 0;; i++)
	{
		if (DebugInfo->BpInfo.BreakPoint[i] != 0)
		{
			WriteProcessMemory(
				DebugInfo->BpInfo.ProcessHandle,
				DebugInfo->BpInfo.BreakPoint[j],
				&DebugInfo->BpInfo.BreakPointOriginal[j],
				sizeof(BYTE),
				NULL
			);

			j++;
			if (j == DebugInfo->BpInfo.BreakPointCount) break;
		}
	}

	free(DebugInfo->BpInfo.BreakPoint);
	free(DebugInfo->BpInfo.BreakPointOriginal);
	free(DebugInfo->BpInfo.BreakPointSymbol);

	return;
}

void DebugEventHandler(DEBUG_INFO *DebugInfo)
{
	DEBUG_EVENT DebugEvent;
	EXCEPTION_RECORD ExceptionRecord;
	memset(&ExceptionRecord, 0, sizeof(ExceptionRecord));
	MEMORY_BASIC_INFORMATION MemoryInfo;

	fprintf(DebugInfo->fp, "Return,\tBreakPoint,\tSymbol\n");

	for (;;)
	{
		if (WaitForDebugEvent(&DebugEvent, INFINITE) != FALSE)
		{
			EXCEPTION_RECORD ExceptionEvent = DebugEvent.u.Exception.ExceptionRecord;

			if (DebugInfo->signal == TRUE) break;

			if (DebugEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
			{
				//printf("attached..\n");
			}

			if (DebugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
			{
				//printf("exit..\n");
				break;
			}

			if (EXCEPTION_DEBUG_EVENT == DebugEvent.dwDebugEventCode && ExceptionEvent.ExceptionCode == EXCEPTION_BREAKPOINT)
			{
				ExceptionRecord = DebugEvent.u.Exception.ExceptionRecord;

				HANDLE ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);

				CONTEXT Ctx;
				Ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(ThreadHandle, &Ctx);

#ifdef _WIN64
				ADDRESS* CurrentInstructionPointer = (ADDRESS*)&Ctx.Rip;
				ADDRESS StackPointer = Ctx.Rsp;
#else 
				ADDRESS* CurrentInstructionPointer = (ADDRESS*)&Ctx.Eip;
				ADDRESS StackPointer = Ctx.Esp;
#endif 

				int j = 0;
				for (int i = 0;; i++)
				{
					if (DebugInfo->BpInfo.BreakPoint[i] != 0)
					{
						if (DebugInfo->BpInfo.BreakPoint[i] == ExceptionRecord.ExceptionAddress)
						{
							ADDRESS ReturnAddress = 0;

							ReadProcessMemory(
								DebugInfo->BpInfo.ProcessHandle,
								(LPVOID)StackPointer,
								&ReturnAddress,
								sizeof(ReturnAddress),
								NULL
							);

							fprintf(DebugInfo->fp, "%p,\t%p,\t%s\n", ReturnAddress, DebugInfo->BpInfo.BreakPoint[i], DebugInfo->BpInfo.BreakPointSymbol[i]);

							WriteProcessMemory(
								DebugInfo->BpInfo.ProcessHandle,
								DebugInfo->BpInfo.BreakPoint[i],
								&DebugInfo->BpInfo.BreakPointOriginal[i],
								sizeof(BYTE),
								NULL
							);

							*CurrentInstructionPointer -= 1;
							SetThreadContext(ThreadHandle, &Ctx);

							ContinueDebugEvent(
								DebugEvent.dwProcessId,
								DebugEvent.dwThreadId,
								DBG_CONTINUE
							);
							Sleep(0);

							BYTE int3 = 0xCC;
							WriteProcessMemory(
								DebugInfo->BpInfo.ProcessHandle,
								DebugInfo->BpInfo.BreakPoint[i],
								&int3,
								sizeof(BYTE),
								NULL
							);

							goto __CONTINUE__;
						}

						j++;
						if (j == DebugInfo->BpInfo.BreakPointCount) break;
					}
				}

				CloseHandle(ThreadHandle);
			}

			ContinueDebugEvent(
				DebugEvent.dwProcessId,
				DebugEvent.dwThreadId,
				DBG_CONTINUE
			);
		}

	__CONTINUE__:;
	}
}

void Quiter(DEBUG_INFO *DebugInfo)
{
	for (;;)
	{
		if (_getch() == 0x0D)
		{
			DebugInfo->signal = TRUE;
			DebugActiveProcessStop(GetProcessId(DebugInfo->BpInfo.ProcessHandle));
			CleanupTargetModuleBreakPoints(DebugInfo);
			if (DebugInfo->fp != NULL) fclose(DebugInfo->fp);
			CloseHandle(DebugInfo->BpInfo.ProcessHandle);

			ExitProcess(0);
		}
	}
}

int main(int argc, char** argv)
{
	//usage
	if (argc == 1)
	{
		printf("usage..\n");
		printf("-exec <path>: execute new file\n");
		printf("-attach <PID>: attach exist process\n");
		printf("-module <name>: trace API module\n");
		printf("-find <symbol>: find symbol\n");
		printf("-skip <symbol>: skip symbol\n");
		printf("-auto-save <>: create report file (.csv) automatically\n");
		printf("-save <>: create report file manually\n\n");
		return 0;
	}

	const char* Mode = NULL;
	char* Target = NULL;
	char* AutoSavePath = NULL;
	char* ManulalSavePath = NULL;
	
	DEBUG_INFO DebugInfo;
	memset(&DebugInfo, 0, sizeof(DebugInfo));

	//parse
	for (int i = 1; i != argc; i += 1)
	{
		int k = 0;
		int m = 0;

		if (strcmp(argv[i], "-exec") == 0)
		{
			if (i + 1 < argc)
			{
				Target = argv[i + 1];
				Mode = argv[i];
			}
		}

		if (strcmp(argv[i], "-attach") == 0)
		{
			if (i + 1 < argc)
			{
				Target = argv[i + 1];
				Mode = argv[i];
			}
		}

		if (strcmp(argv[i], "-module") == 0)
		{
			if (i + 1 < argc)
			{
				DebugInfo.BpInfo.TargetModule = GetModuleHandleA(argv[i + 1]);

				if (DebugInfo.BpInfo.TargetModule == NULL)
				{
					DebugInfo.BpInfo.TargetModule = LoadLibraryA(argv[i + 1]);
				}
			}
		}

		if (strcmp(argv[i], "-find") == 0)
		{
			for (
				int j = i + 1;
				j != argc
				&&
				argv[j][0] != ';'
				&&
				argv[j][0] != '-';
				j += 1)
			{
				DebugInfo.SymbolInfo.AllowSymbol[DebugInfo.SymbolInfo.AllowSymbolCount++] = argv[j];
				i += 1;
			}
		}

		if (strcmp(argv[i], "-skip") == 0)
		{
			for (
				int j = i + 1;
				j != argc
				&&
				argv[j][0] != ';'
				&&
				argv[j][0] != '-';
				j += 1)
			{
				DebugInfo.SymbolInfo.DenySymbol[DebugInfo.SymbolInfo.DenySymbolCount++] = argv[j];
				i += 1;
			}
		}

		if (strcmp(argv[i], "-auto-save") == 0)
		{
			if (i + 1 < argc)
			{
				AutoSavePath = argv[i + 1];
			}
		}

		if (strcmp(argv[i], "-save") == 0)
		{
			if (i + 1 < argc)
			{
				ManulalSavePath = argv[i + 1];
			}
		}
	}

	char _SavePath[MAX_PATH];
	DebugInfo.signal = FALSE;

	if (Target != NULL && strcmp(Mode, "-attach") == 0)
	{
		DWORD Pid = atoi(Target);

		HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
		if (ProcessHandle != NULL)
		{
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Quiter, &DebugInfo, 0, NULL);
			DebugActiveProcess(Pid);

			DebugInfo.BpInfo.ProcessHandle = ProcessHandle;
			InitializeTargetModuleBreakPoints(&DebugInfo);

			DebugInfo.fp = stdout;

			if (AutoSavePath != NULL)
			{
				sprintf(_SavePath, "%s%s", AutoSavePath, ".csv");
				DebugInfo.fp = fopen(_SavePath, "w");
			}

			if (ManulalSavePath != NULL)
			{
				DebugInfo.fp = fopen(ManulalSavePath, "w");
			}

			DebugEventHandler(&DebugInfo);

			ResumeThread(ProcessHandle);
			DebugEventHandler(&DebugInfo);
			DebugActiveProcessStop(Pid);
			CleanupTargetModuleBreakPoints(&DebugInfo);

			if (DebugInfo.fp != NULL) fclose(DebugInfo.fp);
		}
	}

	if (Target != NULL && strcmp(Mode, "-exec") == 0)
	{
		PROCESS_INFORMATION pi = { 0 };
		STARTUPINFOA si = { 0 };
		si.cb = sizeof(STARTUPINFO);
		si.dwFlags = SW_SHOW;
		if (CreateProcessA(NULL, Target, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
		{
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Quiter, &DebugInfo, 0, NULL);
			DebugActiveProcess(pi.dwProcessId);
			
			DebugInfo.BpInfo.ProcessHandle = pi.hProcess;
			InitializeTargetModuleBreakPoints(&DebugInfo);

			DebugInfo.fp = stdout;
			if (AutoSavePath != NULL)
			{
				sprintf(_SavePath, "%s%s", AutoSavePath, ".csv");
				DebugInfo.fp = fopen(_SavePath, "w");
			}

			if (ManulalSavePath != NULL)
			{
				DebugInfo.fp = fopen(ManulalSavePath, "w");
			}

			ResumeThread(pi.hThread);
			DebugEventHandler(&DebugInfo);
			DebugActiveProcessStop(pi.dwProcessId);
			CleanupTargetModuleBreakPoints(&DebugInfo);

			if (DebugInfo.fp != NULL) fclose(DebugInfo.fp);
		}
	}

	return 0;
}