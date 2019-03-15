#include "ProcessInfo.h"

ProcessInfo::ProcessInfo()
{
}

ProcessInfo::~ProcessInfo()
{
}

std::string ProcessInfo::WsToCommonString(const WCHAR * wcharstring) const
{
	std::wstring ws(wcharstring);
	return std::string(ws.begin(), ws.end());
}


void ProcessInfo::print_process_list()
{
	setlocale(LC_ALL, "Russian");

	for (size_t i = 0; i < process_list.size(); i++)
	{
		std::cout << "ID: " << process_list[i]->pid_ << ' ' << "Name: " << process_list[i]->process_name_;
		std::cout << " Integrity: " << process_list[i]->integrity_level_ << std::endl;
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
	}
}

void ProcessInfo::make_process_list()
{
	create_vector();
	fill_path();
	fill_parent_name();
	fill_owner();
	fill_process_bit();

	fill_integrity_level();

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
            peProcessEntry.szExeFile);

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

        std::string owner_name_string = std::string(CW2A(szAccountName));
		process_list[i]->owner_name_ = owner_name_string;

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
			process_list[i]->type_of_process_ = "Unknown";
		}
		else
		{
			if(Wow64Process == TRUE)
				process_list[i]->type_of_process_ = "x86";
			else
				process_list[i]->type_of_process_ = "x64";
		}

		CloseHandle(hProcess);
	}


}

void ProcessInfo::fill_integrity_level() //TODO: change integrity level by SetTokenInformation
{
	for (size_t i = 0; i < process_list.size(); i++)
	{
		HANDLE hProcess;

		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION,
			FALSE,
			process_list[i]->pid_);

		if (hProcess == NULL)
		{
			continue;
			//ErrorExit(TEXT("OpenProcess"));
			//return;
		}

		HANDLE hToken;

		if (!OpenProcessToken(
			hProcess,
			TOKEN_QUERY,
			&hToken))
		{
			continue;
			ErrorExit(TEXT("OpenProcessToken"));
			return;
		}

		PTOKEN_MANDATORY_LABEL pToken = NULL;
		DWORD returnLength=0;
		
		GetTokenInformation(
			hToken,
			TokenIntegrityLevel,
			NULL,
			returnLength,
			&returnLength
		);
		

		pToken = (TOKEN_MANDATORY_LABEL *)LocalAlloc(LPTR, returnLength);
		if (pToken == NULL)
		{
			ErrorExit(TEXT("LocalAlloc"));
		}

		if (!GetTokenInformation(hToken, TokenIntegrityLevel, pToken,
			returnLength, &returnLength))
		{
			ErrorExit(TEXT("GetTokenInformation"));
		}
		DWORD dwIntegrityLevel = *GetSidSubAuthority(pToken->Label.Sid,
			(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pToken->Label.Sid) - 1));
		
		if (dwIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID)
		{
			process_list[i]->integrity_level_ = "Untrusted";
		}
		else if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
		{
			process_list[i]->integrity_level_ = "Low Integrity";
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
			dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
		{
			process_list[i]->integrity_level_ = "Medium Integrity";
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID && 
			dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
		{
			process_list[i]->integrity_level_ = "High Integrity";
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
		{
			process_list[i]->integrity_level_ = "System Integrity";
		}
		CloseHandle(hToken);
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
