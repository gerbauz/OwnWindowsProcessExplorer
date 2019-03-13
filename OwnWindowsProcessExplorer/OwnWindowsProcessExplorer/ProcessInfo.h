#pragma once

#include "ProcessInfoItem.h"
#include <psapi.h>
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

	void ErrorExit(LPTSTR lpszFunction);

	std::string WsToCommonString(WCHAR * wcharstring);
	void print_process_list(); // TODO: delete this functionality in advance
	void make_process_list();
	void fill_pid_name();
	void fill_path();
	//void make_dll_list();
};

