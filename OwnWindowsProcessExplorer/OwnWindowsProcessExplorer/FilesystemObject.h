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
	std::string SID;
	std::string username;
	std::string sid_type;
	std::string ace_type;
	std::string mask;
	std::vector<std::string> access_rights;
};

class FilesystemObject
{
private:
	std::string path_;
	void ErrorExit(LPTSTR lpszFunction);
	void fill_acl_info();
	void fill_owner();
	void fill_integrity_level();

	std::string fill_sid(PSID);
	std::string fill_sid_type(PSID);
	BOOL sid_to_text(PSID, char*, int);
	std::string fill_username(PSID);
	std::string fill_ace_type(BYTE);
	std::string fill_mask(ACCESS_MASK);
	std::vector<std::string> fill_access_rights(ACCESS_MASK);
	std::string WsToCommonString(const WCHAR* wcharstring) const;
	


public:
	FilesystemObject(std::string);
	std::vector<ACL_INFO> data_acl;
	std::string owner;
	std::string integrity_level;

	~FilesystemObject();
};

