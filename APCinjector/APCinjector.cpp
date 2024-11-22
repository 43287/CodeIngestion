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

	// �򿪵�ǰ���̵ķ�������
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		std::cerr << "�޷��򿪽������ơ�����: " << GetLastError() << std::endl;
		return FALSE;
	}

	// ���ҵ�����Ȩ��LUID
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		std::cerr << "�޷����ҵ�����Ȩ��LUID������: " << GetLastError() << std::endl;
		CloseHandle(hToken);
		return FALSE;
	}

	// ������Ȩ
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// ������Ȩ
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		std::cerr << "�޷�����������Ȩ������: " << GetLastError() << std::endl;
		CloseHandle(hToken);
		return FALSE;
	}

	// ��������Ȩ�Ľ��
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		std::cerr << "���Ʋ�����ָ������Ȩ������: " << GetLastError() << std::endl;
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}


//��ȡĿ��pid->����ռ�->д��DLL·��->��ȡLoadLibrary��ַ->��APC�ҹ���������LoadLibrary����������DLL·��


PVOID getFunction(LPCSTR ModuleName, LPCSTR funcName, HMODULE& hMoule) {
	hMoule = GetModuleHandleA(ModuleName);
	if (!hMoule) {
		std::cerr << "ģ���ʧ��" << std::endl;
		exit(1);
	}
	PVOID pfunc = GetProcAddress(hMoule, funcName);
	if (!pfunc) {
		std::cerr << "��������ʧ��" << std::endl;
		exit(2);
	}
	return pfunc;
}
//

int main(void) {
	//��ֹ����Ȩ�޲�����ʹ���������Ȩ��
	if (!EnableDebugPrivilege()) {
		std::cerr << "����Ȩ��ʧ��" << std::endl;
		return 1;
	}

	//��ȡNtdll��NtQueueApcThreadEx
	HMODULE hNtdll;
	pNtQueueApcThreadEx = (NtQueueApcThreadEx)getFunction("Ntdll", "NtQueueApcThreadEx", hNtdll);

	//��ȡkernal32��LoadLibrary
	HMODULE hKernel32;
	pLoadLibrary = (LPTHREAD_START_ROUTINE)getFunction("kernel32", "LoadLibraryW", hKernel32);

	//��ȡPID
	DWORD dwPid = 0;
	std::cout << "���������PID��";
	std::cin >> dwPid;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);



	//����ռ�
	WCHAR dllpath[] = L"C:\\Users\\a2879\\source\\repos\\valentForAPCinject\\x64\\Debug\\messageboxDLL.dll";
	LPVOID lpDLLpath = VirtualAllocEx(hProcess, NULL, sizeof(dllpath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpDLLpath) {
		std::cerr << "�ڴ����ʧ��" << std::endl;
		return 0;
	}
	//д��dll·��
	SIZE_T bytesWritten;
	if (!WriteProcessMemory(hProcess, lpDLLpath, dllpath, sizeof(dllpath) + 1, &bytesWritten)) {
		std::cerr << "д��ʧ��" << std::endl;
		return 0;
	}

	//ȡ�߳�
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
			std::cout << "�ɹ�ִ��:" << *it << std::endl;
			CloseHandle(hThread);
			//break;
		}
		else {
			std::cerr << "�޷����߳�\n";
		}
	}

	std::cout << "ִ�н���" << std::endl;
	system("pause");
}
