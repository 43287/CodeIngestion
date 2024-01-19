#include <iostream>
#include <Windows.h>

BYTE back[5];

void unhook(void* src, void* back, int len) {
	DWORD old;
	VirtualProtect(src, len, 0x40, &old);
	memcpy(src, back, 5);
	VirtualProtect(src, len, old, &old);
}

void hooker(void* src, void* dst, int len) {
	DWORD old;
	VirtualProtect(src, len, 0x40, &old);
	memcpy(back, src, len);
	*(BYTE*)src = 0xE9;
	uintptr_t ra = (uintptr_t)dst - (uintptr_t)src - 5;
	*(DWORD*)((BYTE*)src + 1) = ra;
	VirtualProtect(src, len, old, &old);

}

int WINAPI mybox(_In_opt_ HWND hWnd, 
				 _In_opt_ LPCWSTR lpText, 
				 _In_opt_ LPCWSTR lpCaption, 
				 _In_ UINT uType)
{
	lpText = L"hooked";
	unhook(MessageBoxW, back, 5);
	MessageBoxW(hWnd, lpText, lpCaption, uType);
	hooker(MessageBoxW, mybox, 5);
	return 0;
}



int main()
{
	hooker(MessageBoxW, mybox, 5);
	MessageBoxW(0, L"Hello", 0, 0);
	return 0;
}
