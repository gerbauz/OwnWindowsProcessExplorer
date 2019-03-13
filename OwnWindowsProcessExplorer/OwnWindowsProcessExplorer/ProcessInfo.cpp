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
		std::cout << "ID: " << (*it)->pid_ << ' ' << "Name: " << (*it)->process_name_ <<" PATH:"<<(*it)->file_path_<<std::endl;
		if (!(*it)->dll_list_.empty())
		{
			//std::cout << "DLLs:" << std::endl;
			//for (std::vector<std::string>::iterator sub_it = (*it)->dll_list_.begin(); sub_it != (*it)->dll_list_.end(); ++sub_it)
			//	std::cout << *sub_it << std::endl;
		}
	}
	std::cout << '\n';
}

void ProcessInfo::make_process_list()
{
	fill_pid_name();
	fill_path();
	


}

void ProcessInfo::fill_pid_name()
{
	PROCESSENTRY32 peProcessEntry;
	HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPPROCESS,
		0);

	/*if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		ErrorExit(TEXT("CreateToolhelp32Snapshot"));
		return;
	}*/
	peProcessEntry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &peProcessEntry);

	do {
		std::unique_ptr<ProcessInfoItem> new_process_item = std::make_unique<ProcessInfoItem>(peProcessEntry.th32ProcessID, WsToCommonString(peProcessEntry.szExeFile));
		process_list.push_back(std::move(new_process_item));

		MODULEENTRY32 meModuleEntry;

		HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE,
			peProcessEntry.th32ProcessID);

		/*if (INVALID_HANDLE_VALUE == hSnapshot)
		{
			ErrorExit(TEXT("CreateToolhelp32Snapshot"));
			return;
		}*/
		meModuleEntry.dwSize = sizeof(MODULEENTRY32);

		Module32First(hSnapshot, &meModuleEntry);
		do {
			process_list.back()->add_to_dll_list(WsToCommonString(meModuleEntry.szModule));

		} while (Module32Next(hSnapshot, &meModuleEntry));

	} while (Process32Next(hSnapshot, &peProcessEntry));

	CloseHandle(hSnapshot);
}

void ProcessInfo::fill_path()
{
	for (int i = 0; i < process_list.size(); i++)
	{
		HANDLE hProcess;

		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,
			FALSE,
			process_list[i]->pid_);

		if (hProcess == NULL)
		{
			process_list[i]->file_path_ = WsToCommonString(L"ERROR_ACCESS_DENIED ");
			continue;
			//ErrorExit(TEXT("OpenProcess"));
			//return;
		}

		TCHAR szExeName[MAX_PATH];

		GetModuleFileNameEx(
			hProcess,
			NULL,
			szExeName,
			sizeof(szExeName) / sizeof(TCHAR)
		);
		
		process_list[i]->file_path_ = WsToCommonString(szExeName);
		CloseHandle(hProcess);
	}
}





void ProcessInfo::ErrorExit(LPTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}
