#include "ProcessInfoItem.h"

void ProcessInfoItem::add_to_dll_list(std::string dll_name)
{
	dll_list_.push_back(dll_name);
}

BOOL ProcessInfoItem::change_integrity_level(int new_level)
{
	
	HANDLE hProcess;
	//SetPrivilege(SE_TCB_NAME, TRUE);

	hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION,
		FALSE,
		this->pid_);

	if (hProcess == NULL)
	{
		//ErrorExit(TEXT("OpenProcess"));
		return FALSE;
		//return;
	}

	HANDLE hToken;

	if (!OpenProcessToken(
		hProcess,
		TOKEN_DUPLICATE | TOKEN_QUERY |
		TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY| TOKEN_ADJUST_PRIVILEGES,
		&hToken))
	{
		//ErrorExit(TEXT("OpenProcessToken"));
		return FALSE;
	}

	DWORD new_level_dword;

	if (new_level == UNTRUSTED_INTEGRITY)
	{
		new_level_dword = SECURITY_MANDATORY_UNTRUSTED_RID;
	}
	else if (new_level == LOW_INTEGRITY)
	{
		new_level_dword = SECURITY_MANDATORY_LOW_RID;
	}
	else if (new_level == MEDIUM_INTEGRITY)
	{
		new_level_dword = SECURITY_MANDATORY_MEDIUM_RID;
	}
	else if (new_level == HIGH_INTEGRITY)
	{
		new_level_dword = SECURITY_MANDATORY_HIGH_RID;
	}
	else if (new_level == SYSTEM_INTEGRITY)
	{
		new_level_dword = SECURITY_MANDATORY_SYSTEM_RID;
	}
	else
		return FALSE;

	SID_IDENTIFIER_AUTHORITY MAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
	PSID pSid = NULL;
	AllocateAndInitializeSid(&MAuthority, 1, new_level_dword, 0, 0, 0, 0, 0, 0, 0, &pSid);
	
	TOKEN_MANDATORY_LABEL tml = { 0 };
	tml.Label.Sid = pSid;
	tml.Label.Attributes = SE_GROUP_INTEGRITY;


	if (!SetTokenInformation(
		hToken,
		TokenIntegrityLevel,
		&tml,
		(sizeof(tml) + GetLengthSid(pSid))))
	{
		//return FALSE;
		ErrorExit(TEXT("SetTokenInformation"));
	}

	CloseHandle(hToken);
	CloseHandle(hProcess);

	return TRUE;;

}

BOOL ProcessInfoItem::change_privileges(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION,
		FALSE,
		this->pid_);

	if (hProcess == NULL)
	{
		//ErrorExit(TEXT("OpenProcess"));
		return FALSE;
		//return;
	}

	HANDLE hToken;

	if (!OpenProcessToken(
		hProcess,
		TOKEN_DUPLICATE | TOKEN_QUERY |
		TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_PRIVILEGES,
		&hToken))
	{
		//ErrorExit(TEXT("OpenProcessToken"));
		return FALSE;
	}

	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            
		lpszPrivilege,  
		&luid))      
	{
		//ErrorExit(TEXT("LookupPrivilegeValue"));
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		ErrorExit(TEXT("AdjustTokenPrivileges"));
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		//ErrorExit(TEXT("The token does not have the specified privilege. \n"));
		return FALSE;
	}

	return TRUE;
}

void ProcessInfoItem::fill_integrity_level()
{
		HANDLE hProcess;

		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION,
			FALSE,
			this->pid_);

		if (hProcess == NULL)
		{
			//ErrorExit(TEXT("OpenProcess"));
			return;
		}

		HANDLE hToken;

		if (!OpenProcessToken(
			hProcess,
			TOKEN_QUERY,
			&hToken))
		{
			//      ErrorExit(TEXT("OpenProcessToken"));
			return;
		}

		PTOKEN_MANDATORY_LABEL pToken = NULL;
		DWORD returnLength = 0;

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
			return;
			//            ErrorExit(TEXT("LocalAlloc"));
		}

		if (!GetTokenInformation(hToken, TokenIntegrityLevel, pToken,
			returnLength, &returnLength))
		{
			return;
			//            ErrorExit(TEXT("GetTokenInformation"));
		}
		DWORD dwIntegrityLevel = *GetSidSubAuthority(pToken->Label.Sid,
			(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pToken->Label.Sid) - 1));

		if (dwIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID)
		{
			this->integrity_level_ = "Untrusted";
		}
		else if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
		{
			this->integrity_level_ = "Low Integrity";
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
			dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
		{
			this->integrity_level_ = "Medium Integrity";
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
			dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
		{
			this->integrity_level_ = "High Integrity";
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
		{
			this->integrity_level_ = "System Integrity";
		}
		CloseHandle(hToken);
		CloseHandle(hProcess);
}

void ProcessInfoItem::fill_privileges()
{
	
		HANDLE hProcess;

		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION,
			FALSE,
			this->pid_);

		if (hProcess == NULL)
		{
			//continue;
			//ErrorExit(TEXT("OpenProcess"));
			return;
		}

		HANDLE hToken;

		if (!OpenProcessToken(
			hProcess,
			TOKEN_QUERY | TOKEN_READ,
			&hToken))
		{
			//continue;
			//         ErrorExit(TEXT("OpenProcessToken"));
			return;
		}

		PTOKEN_PRIVILEGES pToken = NULL;
		DWORD returnLength = 0;

		GetTokenInformation(
			hToken,
			TokenPrivileges,
			NULL,
			returnLength,
			&returnLength
		);


		pToken = (TOKEN_PRIVILEGES *)LocalAlloc(LPTR, returnLength);
		if (pToken == NULL)
		{
			return;
			//     ErrorExit(TEXT("LocalAlloc"));
		}

		if (!GetTokenInformation(hToken, TokenPrivileges, pToken,
			returnLength, &returnLength))
		{
			return;
			//      ErrorExit(TEXT("GetTokenInformation"));
		}

		for (DWORD j = 0; j < pToken->PrivilegeCount; j++)
		{
			DWORD dwSize = 0;
			LookupPrivilegeName(NULL, &pToken->Privileges[j].Luid, NULL, &dwSize);

			LPSTR szName = new CHAR[dwSize + 1];

			LookupPrivilegeNameA(NULL, &pToken->Privileges[j].Luid, szName, &dwSize);

			std::pair<std::string, std::string> privileges_pair;

			privileges_pair.first = szName;

			if (pToken->Privileges[j].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
			{
				privileges_pair.second = "Enabled";
			}
			else if (pToken->Privileges[j].Attributes & SE_PRIVILEGE_ENABLED)
			{
				privileges_pair.second = "Enabled by default";
			}
			else if (pToken->Privileges[j].Attributes & SE_PRIVILEGE_REMOVED)
			{
				privileges_pair.second = "Removed";
			}
			else if (pToken->Privileges[j].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS)
			{
				privileges_pair.second = "Used for access";
			}
			else
			{
				privileges_pair.second = "Disabled";
			}
			privileges_list_.push_back(privileges_pair);
		}
		CloseHandle(hToken);
		CloseHandle(hProcess);
}


//void ProcessInfoItem::check_ASLR()
//{
//	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, this->pid_);
//	_PROCESS_MITIGATION_ASLR_POLICY lpBuffer;
//
//	int success = 0;
//
//	success = GetProcessMitigationPolicy(
//		hProcess,
//		ProcessASLRPolicy,
//		&lpBuffer,
//		sizeof(lpBuffer));
//
//	if (success == FALSE)
//		ErrorExit(TEXT("GetProcessMitigationPolicy"));
//	
//	if (lpBuffer.EnableBottomUpRandomization == 1)
//		this->ASLR_usage = TRUE;
//	else
//		this->ASLR_usage = FALSE;
//
//	return;
//}
//
//void ProcessInfoItem::check_DEP()
//{
//	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, this->pid_);
//	_PROCESS_MITIGATION_DEP_POLICY lpBuffer;
//
//	int success = 0;
//
//	success = GetProcessMitigationPolicy(
//		hProcess,
//		ProcessDEPPolicy,
//		&lpBuffer,
//		sizeof(lpBuffer));
//
//	if (success == FALSE)
//		ErrorExit(TEXT("GetProcessMitigationPolicy"));
//
//	if (lpBuffer.Enable == 1)
//		this->DEP_usage = TRUE;
//	else
//		this->DEP_usage = FALSE;
//
//	return;
//}



ProcessInfoItem::ProcessInfoItem(
	//DWORD owner_sid,
	DWORD parent_pid,
	DWORD pid,
	//std::string file_path,
	//std::string owner_name,
	//std::string parent_name,
    std::string process_name//,
	//std::vector<std::string> dll_list
) :
	//owner_sid_(owner_sid),
	parent_pid_(parent_pid),
	pid_(pid),
	//file_path_(file_path),
	//owner_name_(owner_name),
	//parent_name_(parent_name),
	process_name_(process_name)//,
	//dll_list_(dll_list)
{
	fill_integrity_level();
	fill_privileges();
}
void ProcessInfoItem::ErrorExit(LPTSTR lpszFunction)
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


//BOOL ProcessInfoItem::SetPrivilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege)
//{
//	TOKEN_PRIVILEGES priv = { 0,0,0,0 };
//	HANDLE hToken = NULL;
//	LUID luid = { 0,0 };
//	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
//	{
//		if (hToken)
//			CloseHandle(hToken);
//		return FALSE;
//	}
//	if (!LookupPrivilegeValueW(0, lpszPrivilege, &luid))
//	{
//		if (hToken)
//			CloseHandle(hToken);
//		return FALSE;
//	}
//	priv.PrivilegeCount = 1;
//	priv.Privileges[0].Luid = luid;
//	priv.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
//
//	if (!AdjustTokenPrivileges(hToken, FALSE, &priv, 0, 0, 0))
//	{
//		if (hToken)
//			CloseHandle(hToken);
//		return FALSE;
//	}
//	if (hToken)
//		CloseHandle(hToken);
//	return TRUE;
//}
