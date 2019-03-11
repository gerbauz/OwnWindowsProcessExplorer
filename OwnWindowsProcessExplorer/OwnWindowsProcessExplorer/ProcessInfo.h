#pragma once

#include "ProcessInfoItem.h"
#include <iostream>
#include <tlhelp32.h>
#include <vector>
#include <memory>

class ProcessInfo
{
private:
	std::vector<std::unique_ptr<ProcessInfoItem>> process_list;

public:
	ProcessInfo();
	~ProcessInfo();

	std::string WsToCommonString(WCHAR * wcharstring);
	void print_process_list(); // TODO: delete this functionality in advance
	void make_process_list();
	//void make_dll_list();
};

