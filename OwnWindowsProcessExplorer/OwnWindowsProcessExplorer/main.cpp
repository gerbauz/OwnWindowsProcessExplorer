#include <iostream>

#include <windows.h>
#include <tlhelp32.h>
#include "ProcessInfo.h"

VOID PrintModuleList(HANDLE CONST hStdOut, DWORD CONST dwProcessId) {
	MODULEENTRY32 meModuleEntry;
	TCHAR szBuff[1024];
	DWORD dwTemp;
	HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE, dwProcessId);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return;
	}

	meModuleEntry.dwSize = sizeof(MODULEENTRY32);
	Module32First(hSnapshot, &meModuleEntry);
	do {
		wsprintf(szBuff, L"  ba: %08X, bs: %08X, %s\r\n",
			meModuleEntry.modBaseAddr, meModuleEntry.modBaseSize,
			meModuleEntry.szModule);
		WriteConsole(hStdOut, szBuff, lstrlen(szBuff), &dwTemp, NULL);
	} while (Module32Next(hSnapshot, &meModuleEntry));

	CloseHandle(hSnapshot);
}

//VOID PrintProcessList(HANDLE CONST hStdOut) {
//	PROCESSENTRY32 peProcessEntry;
//	TCHAR szBuff[1024];
//	DWORD dwTemp;
//	HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(
//		TH32CS_SNAPPROCESS, 0);
//	if (INVALID_HANDLE_VALUE == hSnapshot) {
//		return;
//	}
//
//	peProcessEntry.dwSize = sizeof(PROCESSENTRY32);
//	Process32First(hSnapshot, &peProcessEntry);
//	do {
//		wsprintf(szBuff, L"=== %d %s ===\r\n",
//			peProcessEntry.th32ProcessID, peProcessEntry.szExeFile);
//		WriteConsole(hStdOut, szBuff, lstrlen(szBuff), &dwTemp, NULL);
//		PrintModuleList(hStdOut, peProcessEntry.th32ProcessID);
//	} while (Process32Next(hSnapshot, &peProcessEntry));
//
//	CloseHandle(hSnapshot);
//}

//INT main() {
//	HANDLE CONST hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
//	PrintProcessList(hStdOut);
//	ExitProcess(0);
//}

int main(int argc, char* argv[])
{
	//PrintProcessList(hStdOut);

	ProcessInfo pi;

	pi.make_process_list();
	pi.print_process_list();

	ExitProcess(0);

	return 0;
}