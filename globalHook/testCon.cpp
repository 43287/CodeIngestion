int main() {
	// 获取 ZwQuerySystemInformation 函数地址
	//setProcName(L"notepad.exe");
	system("pause");
	PZwQuerySystemInformation pZwQuerySystemInformation = reinterpret_cast<PZwQuerySystemInformation>(
		getProc("Ntdll.dll", "ZwQuerySystemInformation")
		);
	if (pZwQuerySystemInformation == NULL) {
		std::cerr << "Failed to get ZwQuerySystemInformation address!" << std::endl;
		return 1;
	}
	//hookByCode("Ntdll.dll", "ZwQuerySystemInformation", reinterpret_cast<PROC>(myZwQuerySystemInformation), &orgBytesA[0]);
	// 定义缓冲区大小
	ULONG bufferSize = 1024 * 1024; // 初始缓冲区大小（1MB）
	PVOID buffer = malloc(bufferSize);
	if (buffer == NULL) {
		std::cerr << "Failed to allocate memory!" << std::endl;
		return 1;
	}

	// 调用 ZwQuerySystemInformation
	NTSTATUS status;
	while ((status = pZwQuerySystemInformation(
		5, // SystemProcessInformation
		buffer,
		bufferSize,
		&bufferSize
		)) == STATUS_INFO_LENGTH_MISMATCH) {
		// 如果缓冲区不够大，重新分配更大的缓冲区
		free(buffer);
		bufferSize *= 2;
		buffer = malloc(bufferSize);
		if (buffer == NULL) {
			std::cerr << "Failed to allocate memory!" << std::endl;
			return 1;
		}
	}

	if (status != 0) {
		std::cerr << "ZwQuerySystemInformation failed with status: " << status << std::endl;
		free(buffer);
		return 1;
	}

	// 遍历进程信息
	PSYSTEM_PROCESS_INFORMATION pProcessInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);
	while (true) {
		// 输出进程ID和进程名
		std::wcout << "Process ID: " << reinterpret_cast<DWORD>(pProcessInfo->UniqueProcessId)
			<< ", Process Name: " << (pProcessInfo->ImageName.Buffer ? pProcessInfo->ImageName.Buffer : L"Unknown")
			<< std::endl;

		// 移动到下一个进程
		if (pProcessInfo->NextEntryOffset == 0) {
			break;
		}
		pProcessInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
			reinterpret_cast<BYTE*>(pProcessInfo) + pProcessInfo->NextEntryOffset
			);
	}

	// 释放缓冲区
	free(buffer);
	system("pause");
	return 0;
}