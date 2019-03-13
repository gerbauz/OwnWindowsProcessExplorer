#include "ProcessInfoItem.h"

void ProcessInfoItem::add_to_dll_list(std::string dll_name)
{
	dll_list_.push_back(dll_name);
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
