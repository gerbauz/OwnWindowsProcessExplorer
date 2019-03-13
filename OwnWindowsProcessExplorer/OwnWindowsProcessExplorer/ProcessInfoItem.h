#pragma once

#define X64 0;
#define X86 1;


#include <strsafe.h> //Only for debug (GetLastError)
#include <windows.h>
#include <string>
#include <vector>


class ProcessInfoItem
{
private:

	friend class ProcessInfo;

	//bool							DEP_usage;
	//bool							ASLR_usage;
	int 							type_of_process;
	PSID							owner_sid_;
	std::string						owner_sid_string_;
	DWORD							parent_pid_;
	DWORD							pid_;
	std::string						file_path_;
	std::string						owner_name_;
	std::string						parent_name_;
	std::string						process_name_;
	std::vector<std::string>		dll_list_;

public:
	void ErrorExit(LPTSTR lpszFunction); //Only for debug (GetLastError)

	void add_to_dll_list(std::string dll_name);

	//void check_ASLR();
	//void check_DEP();

	ProcessInfoItem(
		//DWORD owner_sid,
		DWORD parent_pid,
		DWORD pid,
		//std::string	file_path,
		//std::string owner_name,
		//std::string parent_name,
		std::string	process_name//,
		//std::vector<std::string> dll_list
	);

	~ProcessInfoItem() {};
};
