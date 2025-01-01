#include<iostream>
#include<Windows.h>

struct Data {
	DWORD64 pLoadLibraryA;
	DWORD64 pGetProcAddress;
	DWORD64 pMassage;
}data;




LPVOID writeMemory(
	HANDLE hProcess,
	PVOID pReadyToWrite,
	DWORD size)
{
	LPVOID pMassage = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pMassage)
	{
		std::cerr << "申请内存失败" << std::endl;
		return 0;
	}
	size_t bytewritten;
	WriteProcessMemory(hProcess, pMassage, pReadyToWrite, size, &bytewritten);
	if (bytewritten != size)
	{
		std::cerr << "写入字节失败" << std::endl;
		return 0;
	}
	std::cout << "[+] 写入成功" << std::endl;

	return pMassage;
}









void code() {
	MessageBoxA(NULL, "hello", "SUCCESS", NULL);
}






void targetCode(Data* data) {
	char user32[] = { 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', '\0' };
	char messageBox[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', '\0' };
	HMODULE hModule = ((HMODULE(*)(char*))(data->pLoadLibraryA))(user32);
	if (!hModule)
	{
		return;
	}
	LPVOID pMessagebox = ((FARPROC(*)(HMODULE, LPCSTR))(data->pGetProcAddress))(hModule, messageBox);
	((int (*)(HWND, LPCSTR, LPCSTR, UINT))pMessagebox)(NULL, (char*)(data->pMassage), (char*)(data->pMassage), MB_OKCANCEL);
}


//获取目标句柄
//申请空间，写入参数
//申请空间写入函数
//远程线程执行


void injectCode(DWORD pid) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	char message[] = "SUCCESS";
	LPVOID pMessage = writeMemory(hProcess, message, sizeof(message) + 1);


	data.pMassage = (DWORD64)pMessage;
	data.pGetProcAddress = (DWORD64)GetProcAddress(GetModuleHandleA("kernel32"), "GetProcAddress");
	data.pLoadLibraryA = (DWORD64)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");

	LPVOID pData = writeMemory(hProcess, &data, sizeof(data) + 1);

	uintptr_t funcSize = (uintptr_t)writeMemory - (uintptr_t)targetCode;

	LPVOID pfunc = writeMemory(hProcess, (PVOID)targetCode, funcSize);


	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pfunc, pData, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

}



void injectCodeAsm(DWORD pid) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	BYTE code[] = { 0xeb, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x00, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x6f, 0x78, 0x41, 0x00, 0x53, 0x55, 0x43, 0x43, 0x45, 0x53, 0x53, 0x00, 0x60, 0x94, 0xbc, 0x20, 0xfd, 0x7f, 0x00, 0x00, 0x30, 0x3c, 0xbc, 0x20, 0xfd, 0x7f, 0x00, 0x00, 0x6a, 0x00, 0x48, 0x8d, 0x0d, 0xc8, 0xff, 0xff, 0xff, 0x48, 0x8b, 0x05, 0xe0, 0xff, 0xff, 0xff, 0xff, 0xd0, 0x48, 0x89, 0xc1, 0x48, 0x8d, 0x15, 0xc0, 0xff, 0xff, 0xff, 0x48, 0x8b, 0x05, 0xd5, 0xff, 0xff, 0xff, 0xff, 0xd0, 0x48, 0x8d, 0x1d, 0xbc, 0xff, 0xff, 0xff, 0x49, 0xc7, 0xc1, 0x01, 0x00, 0x00, 0x00, 0x49, 0x89, 0xd8, 0x48, 0x89, 0xda, 0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd0, 0xc3 };
	LPVOID pcode = writeMemory(hProcess, code, sizeof(code));

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pcode, NULL, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
}

int main(int argc, char* argv[]) {
	DWORD pid;
	std::cin >> pid;


	//pid = atol(argv[1]);
	injectCodeAsm(pid);
	return 0;
}
