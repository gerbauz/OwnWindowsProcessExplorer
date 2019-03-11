#pragma once

#include <windows.h>
#include <string>
#include <vector>

class ProcessInfoItem
{
private:

	friend class ProcessInfo;
	//bool						DEP_usage;
	//bool						ASLR_usage;
	//TODO: add type_of_process (x86/x64)
	//DWORD						owner_sid_;
	//DWORD						parent_pid_;
	DWORD						pid_;
	//std::string					file_path_;
	//std::string					owner_name_;
	//std::string					parent_name_;
	std::string					process_name_;
	//std::vector<std::string>	dll_list_;

public:

	//void add_to_dll_list(std::string dll_name);

	ProcessInfoItem(
		//DWORD owner_sid,
		//DWORD parent_pid,
		DWORD pid,
		//std::string	file_path,
		//std::string owner_name,
		//std::string parent_name,
		std::string	process_name//,
		//std::vector<std::string> dll_list
	);

	~ProcessInfoItem() {};
};
