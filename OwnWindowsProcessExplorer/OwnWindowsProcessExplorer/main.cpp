#include <iostream>
#include <locale.h>
#include <windows.h>
#include <tlhelp32.h>
#include "ProcessInfo.h"

int main(int argc, char* argv[])
{
	setlocale(LC_ALL, "Russian");

	ProcessInfo pi;
	
	pi.make_process_list();
	pi.print_process_list();

	ExitProcess(0);

	return 0;
}