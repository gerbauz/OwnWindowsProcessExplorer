#pragma once

#include "ProcessInfoItem.h"
#include <psapi.h>
#include <iostream>
#include <tlhelp32.h>
#include <vector>
#include <sddl.h>
#include <atlstr.h>
#include <memory>

class ProcessInfo
{
private:
    std::vector<std::shared_ptr<ProcessInfoItem>> process_list;

public:
    ProcessInfo();
    ~ProcessInfo();

    void ErrorExit(LPTSTR lpszFunction);

    std::string WsToCommonString(const WCHAR * wcharstring) const;
    void print_process_list(); // TODO: delete this functionality in advance
    void make_process_list();
    void create_vector();
    void fill_path();
    void fill_parent_name();
    void fill_owner();
    void fill_process_bit();

    void fill_integrity_level();
    //void make_dll_list();

    std::vector<std::shared_ptr<ProcessInfoItem>> get_process_list() const;

};

