#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define MAX_NAME 256
#include <string>
#include <Windows.h>
#include <aclapi.h>
#include <strsafe.h>
#include <vector>
#include <Sddl.h>


struct ACL_INFO
{
	std::wstring SID;
	std::wstring username;
	std::wstring sid_type;
	std::wstring ace_type;
	std::wstring mask;
	std::vector<std::wstring> access_rights;
};

class FilesystemObject
{
private:
	std::wstring path_;
	void ErrorExit(LPTSTR lpszFunction);
	void fill_acl_info();
	void fill_owner();
	void fill_integrity_level();



	std::wstring fill_sid(PSID);
	std::wstring fill_sid_type(PSID);
	BOOL sid_to_text(PSID, wchar_t*, int);
	std::wstring fill_username(PSID);
	std::wstring fill_ace_type(BYTE);
	std::wstring fill_mask(ACCESS_MASK);
	std::vector<std::wstring> fill_access_rights(ACCESS_MASK);
	std::wstring WsToCommonString(const WCHAR* wcharstring) const;
	


public:
	FilesystemObject(std::wstring);
	std::vector<ACL_INFO> data_acl;
	std::wstring owner;
	std::wstring integrity_level;


	BOOL change_acl_info();
	BOOL change_owner(std::wstring);
	BOOL change_integrity_level();


	~FilesystemObject();
};

