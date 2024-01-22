#include <iostream>
#include <Windows.h>

using PFUN = int (WINAPI*)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType);
PFUN pfun = nullptr;


void* trampoline(void* src, void* dst, int len)
{
	BYTE* boxin = (BYTE*)VirtualAlloc(0, len + 5, 0x00001000, 0x40);
	memcpy(boxin, src, len);
	*(boxin + len) = 0xe9;
	*(DWORD*)(boxin + len + 1) = (BYTE*)src - boxin - 5;
	//以下为原hook的内容
	DWORD old;
	VirtualProtect(src, len, 0x40, &old);
	*(BYTE*)src = 0xE9;
	uintptr_t ra = (uintptr_t)dst - (uintptr_t)src - 5;
	*(DWORD*)((BYTE*)src + 1) = ra;
	VirtualProtect(src, len, old, &old);
	return boxin;
}

int WINAPI mybox(_In_opt_ HWND hWnd, 
				 _In_opt_ LPCWSTR lpText, 
				 _In_opt_ LPCWSTR lpCaption, 
				 _In_ UINT uType)
{
	lpText = L"hooked";
	pfun(hWnd, lpText, lpCaption, uType);
	//MessageBoxW(hWnd, lpText, lpCaption, uType);
	return 0;
}


int main()
{
	pfun = (PFUN)trampoline(MessageBoxW, mybox, 5);
	MessageBoxW(0, L"Hello", 0, 0);
	MessageBoxW(0, L"Hello", 0, 0);
	MessageBoxW(0, L"Hello", 0, 0);
	pfun(0, L"123123", 0, 0);
	return 0;
}
