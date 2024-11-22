#include <windows.h>

// 窗口过程函数
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_CREATE: {
		// 创建一个按钮
		CreateWindow(
			L"BUTTON", L"Click Me",
			WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
			10, 10, 100, 30,
			hwnd, (HMENU)1, GetModuleHandle(NULL), NULL);
		break;
	}
	case WM_COMMAND: {
		if (LOWORD(wParam) == 1) {
			// 按钮被点击后执行SleepEx
			SleepEx(1000, TRUE);
		}
		break;
	}
	case WM_DESTROY: {
		PostQuitMessage(0);
		break;
	}
	default:
		return DefWindowProc(hwnd, uMsg, wParam, lParam);
	}
	return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	// 注册窗口类
	WNDCLASS wc = {};
	wc.lpfnWndProc = WindowProc;
	wc.hInstance = hInstance;
	wc.lpszClassName = L"SampleWindowClass";
	RegisterClass(&wc);

	// 创建窗口
	HWND hwnd = CreateWindowEx(
		0, L"SampleWindowClass", L"Sample Windows Program",
		WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 640, 480,
		NULL, NULL, hInstance, NULL);
	ShowWindow(hwnd, nCmdShow);

	// 消息循环
	MSG msg = {};
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return 0;
}
