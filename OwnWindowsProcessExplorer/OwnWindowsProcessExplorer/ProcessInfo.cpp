#include "ProcessInfo.h"

ProcessInfo::ProcessInfo()
{
}

ProcessInfo::~ProcessInfo()
{
}

std::string ProcessInfo::WsToCommonString(WCHAR * wcharstring)
{
	std::wstring ws(wcharstring);
	return std::string(ws.begin(), ws.end());
}

void ProcessInfo::print_process_list()
{
	for (std::vector<std::unique_ptr<ProcessInfoItem>>::iterator it = process_list.begin(); it != process_list.end(); ++it)
	{
		std::cout << "ID: " << (*it)->pid_ << ' ' << "Name: " << (*it)->process_name_ << std::endl;
		if (!(*it)->dll_list_.empty())
		{
			std::cout << "DLLs:" << std::endl;
			for (std::vector<std::string>::iterator sub_it = (*it)->dll_list_.begin(); sub_it != (*it)->dll_list_.end(); ++sub_it)
				std::cout << *sub_it << std::endl;
		}
	}
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
		//TODO: replace with except
		return;
	}

	peProcessEntry.dwSize = sizeof(PROCESSENTRY32);

	Process32First(hSnapshot, &peProcessEntry);

	do {
		/*wsprintf(szBuff, L"=== %d %s ===\r\n", peProcessEntry.th32ProcessID, peProcessEntry.szExeFile);
		WriteConsole(hStdOut, szBuff, lstrlen(szBuff), &dwTemp, NULL);
		PrintModuleList(hStdOut, peProcessEntry.th32ProcessID);*/
		std::unique_ptr<ProcessInfoItem> new_process_item = std::make_unique<ProcessInfoItem>(peProcessEntry.th32ProcessID, WsToCommonString(peProcessEntry.szExeFile));
		process_list.push_back(std::move(new_process_item));

		MODULEENTRY32 meModuleEntry;

		HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE,
			peProcessEntry.th32ProcessID);

		//if (INVALID_HANDLE_VALUE == hSnapshot)
		//{
		//	//TODO: replace with except	
		//	break;
		//}

		meModuleEntry.dwSize = sizeof(MODULEENTRY32);

		Module32First(hSnapshot, &meModuleEntry);
		do {
			//wsprintf(szBuff, L"  ba: %08X, bs: %08X, %s\r\n",
			//	meModuleEntry.modBaseAddr, meModuleEntry.modBaseSize,
			//	meModuleEntry.szModule);
			//WriteConsole(hStdOut, szBuff, lstrlen(szBuff), &dwTemp, NULL);

			process_list.back()->add_to_dll_list(WsToCommonString(meModuleEntry.szModule));

		} while (Module32Next(hSnapshot, &meModuleEntry));

	} while (Process32Next(hSnapshot, &peProcessEntry));

	CloseHandle(hSnapshot);
}