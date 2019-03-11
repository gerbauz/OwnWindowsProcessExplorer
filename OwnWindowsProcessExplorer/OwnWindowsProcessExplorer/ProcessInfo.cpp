#include "ProcessInfo.h"

ProcessInfo::ProcessInfo()
{
}

ProcessInfo::~ProcessInfo()
{
}

void ProcessInfo::print_process_list()
{
	for (std::vector<std::unique_ptr<ProcessInfoItem>>::iterator it = process_list.begin(); it != process_list.end(); ++it)
		std::cout << "ID: " << (*it)->pid_ << ' ' << "Name: " << (*it)->process_name_ << std::endl;
	std::cout << '\n';
}

void ProcessInfo::make_process_list()
{
	PROCESSENTRY32 peProcessEntry;
	HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPPROCESS,
		0);

	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		return;
	}

	peProcessEntry.dwSize = sizeof(PROCESSENTRY32);

	Process32First(hSnapshot, &peProcessEntry);

	do {
		/*wsprintf(szBuff, L"=== %d %s ===\r\n", peProcessEntry.th32ProcessID, peProcessEntry.szExeFile);
		WriteConsole(hStdOut, szBuff, lstrlen(szBuff), &dwTemp, NULL);
		PrintModuleList(hStdOut, peProcessEntry.th32ProcessID);*/
		std::wstring ws(peProcessEntry.szExeFile);
		std::unique_ptr<ProcessInfoItem> new_process_item = std::make_unique<ProcessInfoItem>(peProcessEntry.th32ProcessID, std::string(ws.begin(), ws.end()));
		process_list.push_back(std::move(new_process_item));
	} while (Process32Next(hSnapshot, &peProcessEntry));

	CloseHandle(hSnapshot);
}