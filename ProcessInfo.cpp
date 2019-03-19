#include "ProcessInfo.h"

ProcessInfo::ProcessInfo()
{
}

ProcessInfo::~ProcessInfo()
{
}

std::wstring ProcessInfo::WsToCommonString(const WCHAR * wcharstring) const
{
	std::wstring ws(wcharstring);
	return std::wstring(ws.begin(), ws.end());
}


void ProcessInfo::print_process_list()
{
	setlocale(LC_ALL, "Russian");

		for (size_t i = 0; i < process_list.size(); i++)
		{
			std::wcout << "ID: " << process_list[i]->pid_ << ' ' << "Name: " << process_list[i]->process_name_;
			std::wcout << "ASLR: " << process_list[i]->ASLR_usage << " DEP: " << process_list[i]->DEP_usage << std::endl;
		}
}

			//std::cout << "Type: " << process_list[i]->type_of_process_ << std::endl;
			//std::cout << " PATH:" << process_list[i]->file_path_;
			//std::cout << " PARENT PID:" << process_list[i]->parent_pid_;
			//std::cout << " PARENT NAME:" << process_list[i]->parent_name_;
			//std::cout << " OWNER NAME: " << process_list[i]->owner_name_;
			//std::cout << " OWNER SID: " << process_list[i]->owner_sid_string_ << std::endl;

			/*if (!(process_list[i]->dll_list_.empty()))
			{
				std::cout << "DLLs:" << std::endl;
				for(int j=0;j<process_list[i]->dll_list_.size();j++)
					std::cout << process_list[i]->dll_list_[j] << std::endl;
			}*/
			//}

void ProcessInfo::make_process_list()
{
	create_vector();
	fill_path();
	fill_parent_name();
	fill_owner();
	fill_process_bit();
//	fill_ASLR_win7();
    fill_ASLR_win10();
    fill_DEP_win7();
//    fill_DEP_win10();

}

void ProcessInfo::create_vector()
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

		std::shared_ptr<ProcessInfoItem> new_process_item = std::make_shared<ProcessInfoItem>(
			peProcessEntry.th32ParentProcessID,
			peProcessEntry.th32ProcessID,
            WsToCommonString(peProcessEntry.szExeFile));

		process_list.push_back(new_process_item);

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
	for (size_t i = 0; i < process_list.size(); i++)
	{
		HANDLE hProcess;

		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE,
			process_list[i]->pid_);

		if (hProcess == NULL)
		{
            process_list[i]->file_path_ = (L"ERROR_ACCESS_DENIED ");
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

		process_list[i]->file_path_ = szExeName;
		CloseHandle(hProcess);
	}
}

void ProcessInfo::fill_parent_name()
{
	for (size_t i = 0; i < process_list.size(); i++)
	{
		DWORD parent_pid = process_list[i]->parent_pid_;

		for (size_t j = 0; j < process_list.size(); j++)
		{
			if (process_list[j]->pid_ == parent_pid)
			{
                process_list[i]->parent_name_ = process_list[j]->process_name_;
				break;
			}

			if (j == process_list.size() - 1)
                process_list[i]->parent_name_ = L"<Non-existent Process>";

		}
	}
}

void ProcessInfo::fill_owner()
{
	for (size_t i = 0; i < process_list.size(); i++)
	{
		HANDLE hProcess;

		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE,
			process_list[i]->pid_);

		if (hProcess == NULL)
		{
			continue;
			//ErrorExit(TEXT("OpenProcess"));
			//return;
		}

		HANDLE hAccessToken;
		TCHAR InfoBuffer[1000], szAccountName[200], szDomainName[200];

		PTOKEN_USER pTokenUser = (PTOKEN_USER)InfoBuffer;
		DWORD dwInfoBufferSize, dwAccountSize = 200, dwDomainSize = 200;
		SID_NAME_USE snu;


		OpenProcessToken(hProcess, TOKEN_READ, &hAccessToken);

		GetTokenInformation(hAccessToken, TokenUser, InfoBuffer, 1000, &dwInfoBufferSize);

		LookupAccountSid(NULL, pTokenUser->User.Sid, szAccountName, &dwAccountSize,
			szDomainName, &dwDomainSize, &snu);

		process_list[i]->owner_sid_ = pTokenUser->User.Sid;

        //std::wstring owner_name_string = std::wstring(CW2A(szAccountName));
		process_list[i]->owner_name_ = szAccountName;

		LPTSTR string_sid;
		ConvertSidToStringSid(process_list[i]->owner_sid_, &string_sid);
        process_list[i]->owner_sid_string_ = WsToCommonString(string_sid);
	}

}

void ProcessInfo::fill_process_bit()
{
	for (size_t i = 0; i < process_list.size(); i++)
	{
		HANDLE hProcess;

		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE,
			process_list[i]->pid_);

		if (hProcess == NULL)
		{
			continue;
			//ErrorExit(TEXT("OpenProcess"));
			//return;
		}

		BOOL Wow64Process;
		if (IsWow64Process(hProcess, &Wow64Process) == NULL)
		{
			process_list[i]->type_of_process_ = L"Unknown";
		}
		else
		{
			if(Wow64Process == TRUE)
				process_list[i]->type_of_process_ = L"x86";
			else
				process_list[i]->type_of_process_ = L"x64";
		}

		CloseHandle(hProcess);
	}


}

void ProcessInfo::fill_ASLR_win10()
{
    for (size_t i = 0; i < process_list.size(); i++)
    {
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION,
            FALSE,
            process_list[i]->pid_);

        _PROCESS_MITIGATION_ASLR_POLICY lpBuffer;
        int success = 0;

        success = GetProcessMitigationPolicy(
                hProcess,
                ProcessASLRPolicy,
                &lpBuffer,
                sizeof(lpBuffer));

        if (success == FALSE)
        {
            continue;
            //ErrorExit(TEXT("GetProcessMitigationPolicy"));
        }

        if (lpBuffer.EnableBottomUpRandomization == 1)
            process_list[i]->ASLR_usage = L"Enabled";
        else
            process_list[i]->ASLR_usage = L"Disabled";


    }

}

void ProcessInfo::fill_DEP_win10()
{
    for (size_t i = 0; i < process_list.size(); i++)
    {
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION,
            FALSE,
            process_list[i]->pid_);

        _PROCESS_MITIGATION_DEP_POLICY lpBuffer;
        int success = 0;

        success = GetProcessMitigationPolicy(
            hProcess,
            ProcessDEPPolicy,
            &lpBuffer,
            sizeof(lpBuffer));

        if (success == FALSE)
        {
            continue;
            //ErrorExit(TEXT("GetProcessMitigationPolicy"));
        }
        if (lpBuffer.Enable == 1)
            process_list[i]->DEP_usage = L"Enabled";
        else
            process_list[i]->DEP_usage = L"Disabled";

        CloseHandle(hProcess);
    }
    return;
}

void ProcessInfo::fill_ASLR_win7()
{

	for (size_t i = 0; i < process_list.size(); i++)
	{
		IMAGE_DOS_HEADER pDos = { 0 };
		IMAGE_NT_HEADERS pNT = { 0 };
		void *BaseAddress;

		MODULEENTRY32 ME32;
		HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_list[i]->pid_);

		if (INVALID_HANDLE_VALUE == hModule) continue;

		ME32.dwSize = sizeof(ME32);

		if (Module32First(hModule, &ME32) == FALSE)
		{
			CloseHandle(hModule);
			continue;
		}

		CloseHandle(hModule);

		BaseAddress = ME32.modBaseAddr;

		HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, process_list[i]->pid_);

		if (hProcess == NULL) continue;

		if (0 == ReadProcessMemory(hProcess, BaseAddress, (char*)&pDos, sizeof(IMAGE_DOS_HEADER), 0))
		{
			CloseHandle(hProcess);
			continue;
		}

		if (0 == ReadProcessMemory(hProcess, (void*)((unsigned long)BaseAddress + pDos.e_lfanew), &pNT, sizeof(IMAGE_NT_HEADERS), 0))
		{
			CloseHandle(hProcess);
			continue;
		}

		CloseHandle(hProcess);

		if (pNT.Signature == IMAGE_NT_SIGNATURE)
		{
			if (pNT.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
				process_list[i]->ASLR_usage = L"Enabled";
			else
				process_list[i]->ASLR_usage = L"Disabled";
		}
	}
}

void ProcessInfo::fill_DEP_win7()
{
	for (size_t i = 0; i < process_list.size(); i++)
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, process_list[i]->pid_);

		if (NULL == hProcess)
		{
			continue;
		}

		DWORD Flags;
		BOOL Permanent = FALSE;

		if (FALSE == GetProcessDEPPolicy(hProcess, &Flags, &Permanent))
		{
			CloseHandle(hProcess);

			if ( process_list[i]->type_of_process_ == L"x64")
			{
				process_list[i]->DEP_usage = L"Enabled (permanent)";
			}
		}
		else
		{
			if (Flags == 0)
				process_list[i]->DEP_usage = (Permanent == TRUE) ? L"Disabled (permanent)" : L"Disabled";
			else if (Flags == 0x00000001 || Flags == 3)
				process_list[i]->DEP_usage = (Permanent == TRUE) ? L"Enabled (permanent)" : L"Enabled";
			else if (Flags == 0x00000002)
				process_list[i]->DEP_usage = L"DEP-ATL thunk emulation is disabled for the specified process.";
		}
		CloseHandle(hProcess);
	}

}



std::vector<std::shared_ptr<ProcessInfoItem> > ProcessInfo::get_process_list() const
{
    return process_list;
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
