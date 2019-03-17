#include <iostream>
#include <locale.h>
#include <windows.h>
#include <tlhelp32.h>
#include "ProcessInfo.h"
#include "FilesystemObject.h"

int main(int argc, char* argv[])
{
	setlocale(LC_ALL, "Russian");

	//ProcessInfo pi;
	
	//pi.make_process_list();
	//pi.print_process_list();

	FilesystemObject fo("C:\\");
	for (size_t i = 0; i < fo.data_acl.size(); i++)
	{
		std::cout << "USERNAME: " << fo.data_acl[i].username << std::endl;
		std::cout << "SID: " << fo.data_acl[i].SID << std::endl;
		std::cout << "SID TYPE: " << fo.data_acl[i].sid_type << std::endl;
		std::cout << "ACE TYPE: " << fo.data_acl[i].ace_type << std::endl;
		std::cout << "MASK: " << fo.data_acl[i].mask << std::endl;
		std::cout << "RIGHTS\n";
		for (size_t j = 0; j < fo.data_acl[i].access_rights.size(); j++)
		{
			std::cout << fo.data_acl[i].access_rights[j] << std::endl;
		}
		std::cout << std::endl;
	}
	ExitProcess(0);

	return 0;
}