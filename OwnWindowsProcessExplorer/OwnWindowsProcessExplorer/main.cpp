#include <iostream>
#include <locale.h>
#include <windows.h>
#include <tlhelp32.h>
#include "ProcessInfo.h"
#include "FilesystemObject.h"

int main(int argc, char* argv[])
{
	setlocale(LC_ALL, "Russian");

	ProcessInfo pi;
	
	pi.make_process_list();

	pi.print_process_list();

	/*FilesystemObject fo(L"C:\\MyDumper.exe");
	for (size_t i = 0; i < fo.data_acl.size(); i++)
	{
		std::wcout << "USERNAME: " << fo.data_acl[i].username << std::endl;
		std::wcout << "SID: " << fo.data_acl[i].SID << std::endl;
		std::wcout << "SID TYPE: " << fo.data_acl[i].sid_type << std::endl;
		std::wcout << "ACE TYPE: " << fo.data_acl[i].ace_type << std::endl;
		std::wcout << "MASK: " << fo.data_acl[i].mask << std::endl;
		std::wcout << "RIGHTS\n";
		for (size_t j = 0; j < fo.data_acl[i].access_rights.size(); j++)
		{
			std::wcout << fo.data_acl[i].access_rights[j] << std::endl;
		}
		std::cout << std::endl;
	}*/
	//std::cout << "OWNER: " << fo.owner << std::endl;
	//std::cout << "INTEGRITY: " << fo.integrity_level << std::endl;

	//FilesystemObject fo(L"C:\\MyDumper.exe");
	//if(fo.change_integrity_level(HIGH_INTEGRITY)==TRUE)
	//		std::cout<<"NICE";


	//FilesystemObject fo(L"C:\\MyDumper.exeexe");
	
	/*DWORD mask = DELETE;
	fo.change_acl_info(L"Пользователи", mask, DENY_ACCSS);

	for (size_t i = 0; i < fo.data_acl.size(); i++)
	{
		std::wcout << "USERNAME: " << fo.data_acl[i].username << std::endl;
		std::wcout << "SID: " << fo.data_acl[i].SID << std::endl;
		std::wcout << "SID TYPE: " << fo.data_acl[i].sid_type << std::endl;
		std::wcout << "ACE TYPE: " << fo.data_acl[i].ace_type << std::endl;
		std::wcout << "MASK: " << fo.data_acl[i].mask << std::endl;
		std::wcout << "RIGHTS\n";
		for (size_t j = 0; j < fo.data_acl[i].access_rights.size(); j++)
		{
			std::wcout << fo.data_acl[i].access_rights[j] << std::endl;
		}
		std::cout << std::endl;
	}*/


	ExitProcess(0);

	return 0;
}