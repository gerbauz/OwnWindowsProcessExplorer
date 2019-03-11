#include "ProcessInfoItem.h"

void ProcessInfoItem::add_to_dll_list(std::string dll_name)
{
	dll_list_.push_back(dll_name);
}

ProcessInfoItem::ProcessInfoItem(
	//DWORD owner_sid,
	//DWORD parent_pid,
	DWORD pid,
	//std::string file_path,
	//std::string owner_name,
	//std::string parent_name,
	std::string process_name//,
	//std::vector<std::string> dll_list
) :
	//owner_sid_(owner_sid),
	//parent_pid_(parent_pid),
	pid_(pid),
	//file_path_(file_path),
	//owner_name_(owner_name),
	//parent_name_(parent_name),
	process_name_(process_name)//,
	//dll_list_(dll_list)
{
}