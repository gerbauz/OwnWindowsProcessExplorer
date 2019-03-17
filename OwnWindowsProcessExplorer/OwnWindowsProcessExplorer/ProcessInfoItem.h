#pragma once

#define UNTRUSTED_INTEGRITY 0
#define LOW_INTEGRITY 1
#define MEDIUM_INTEGRITY 2
#define HIGH_INTEGRITY 3
#define SYSTEM_INTEGRITY 4


#include <strsafe.h> //Only for debug (GetLastError)
#include <Windows.h>
#include <string>
#include <vector>




struct ProcessInfoItem
{
	bool							DEP_usage;
	bool							ASLR_usage;
	std::wstring 					type_of_process_;
	PSID							owner_sid_;
	std::wstring						owner_sid_string_;
	DWORD							parent_pid_;
	DWORD							pid_;
	std::wstring						file_path_;
	std::wstring						owner_name_;
	std::wstring						parent_name_;
	std::wstring						process_name_;
	std::wstring						integrity_level_;

	std::vector<std::wstring>		dll_list_;
	std::vector<std::pair<std::wstring, std::wstring>> privileges_list_;

	void ErrorExit(LPTSTR lpszFunction); //Only for debug (GetLastError)

	void add_to_dll_list(std::wstring dll_name);

	void fill_privileges();
	void fill_integrity_level();


	BOOL change_integrity_level(int);
	BOOL change_privileges(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);

	BOOL SetPrivilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege); //Only for debug (up privilege for this app)

	//void check_ASLR();
	//void check_DEP();

	ProcessInfoItem(
		//DWORD owner_sid,
		DWORD parent_pid,
		DWORD pid,
		//std::wstring	file_path,
		//std::wstring owner_name,
		//std::wstring parent_name,
        std::wstring    process_name//,
		//std::vector<std::wstring> dll_list
	);

	~ProcessInfoItem() {};
};
