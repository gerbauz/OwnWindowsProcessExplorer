#include "FilesystemObject.h"


SID_NAME_USE SidTypeArray[] = {
	SidTypeUser,
	SidTypeGroup,
	SidTypeDomain,
	SidTypeAlias,
	SidTypeWellKnownGroup,
	SidTypeDeletedAccount,
	SidTypeInvalid,
	SidTypeUnknown,
	SidTypeComputer,
	SidTypeLabel
};
std::wstring SidStrTypeArray[] = {
	L"SidTypeUser",
	L"SidTypeGroup",
	L"SidTypeDomain",
	L"SidTypeAlias",
	L"SidTypeWellKnownGroup",
	L"SidTypeDeletedAccount",
	L"SidTypeInvalid",
	L"SidTypeUnknown",
	L"SidTypeComputer",
	L"SidTypeLabel" };
BYTE AceTypeArray[] = {
	ACCESS_ALLOWED_ACE_TYPE,
	ACCESS_DENIED_ACE_TYPE,
	SYSTEM_AUDIT_ACE_TYPE,
	SYSTEM_ALARM_ACE_TYPE,
	ACCESS_MAX_MS_V2_ACE_TYPE,
	ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
	ACCESS_MAX_MS_V3_ACE_TYPE,
	ACCESS_MIN_MS_OBJECT_ACE_TYPE,
	ACCESS_ALLOWED_OBJECT_ACE_TYPE,
	ACCESS_DENIED_OBJECT_ACE_TYPE,
	SYSTEM_AUDIT_OBJECT_ACE_TYPE,
	SYSTEM_ALARM_OBJECT_ACE_TYPE,
	ACCESS_MAX_MS_OBJECT_ACE_TYPE,
	ACCESS_MAX_MS_V4_ACE_TYPE,
	ACCESS_MAX_MS_ACE_TYPE,
	ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
	ACCESS_DENIED_CALLBACK_ACE_TYPE,
	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
	ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
	SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
	SYSTEM_ALARM_CALLBACK_ACE_TYPE,
	SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
	SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
	SYSTEM_MANDATORY_LABEL_ACE_TYPE,
	ACCESS_MAX_MS_V5_ACE_TYPE
};
std::wstring AceTypeStrArray[] = {
	L"ACCESS_ALLOWED_ACE_TYPE",
	L"ACCESS_DENIED_ACE_TYPE",
	L"SYSTEM_AUDIT_ACE_TYPE",
	L"SYSTEM_ALARM_ACE_TYPE",
	L"ACCESS_MAX_MS_V2_ACE_TYPE",
	L"ACCESS_ALLOWED_COMPOUND_ACE_TYPE",
	L"ACCESS_MAX_MS_V3_ACE_TYPE",
	L"ACCESS_MIN_MS_OBJECT_ACE_TYPE",
	L"ACCESS_ALLOWED_OBJECT_ACE_TYPE",
	L"ACCESS_DENIED_OBJECT_ACE_TYPE",
	L"SYSTEM_AUDIT_OBJECT_ACE_TYPE",
	L"SYSTEM_ALARM_OBJECT_ACE_TYPE",
	L"ACCESS_MAX_MS_OBJECT_ACE_TYPE",
	L"ACCESS_MAX_MS_V4_ACE_TYPE",
	L"ACCESS_MAX_MS_ACE_TYPE",
	L"ACCESS_ALLOWED_CALLBACK_ACE_TYPE",
	L"ACCESS_DENIED_CALLBACK_ACE_TYPE",
	L"ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE",
	L"ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE",
	L"SYSTEM_AUDIT_CALLBACK_ACE_TYPE",
	L"SYSTEM_ALARM_CALLBACK_ACE_TYPE",
	L"SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE",
	L"SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE",
	L"SYSTEM_MANDATORY_LABEL_ACE_TYPE",
	L"ACCESS_MAX_MS_V5_ACE_TYPE"
};
DWORD AccessRightArray[] = {
	GENERIC_READ,
	GENERIC_WRITE,
	GENERIC_EXECUTE,
	GENERIC_ALL,
	DELETE,
	READ_CONTROL,
	WRITE_DAC,
	WRITE_OWNER,
	SYNCHRONIZE,
	STANDARD_RIGHTS_REQUIRED,
	STANDARD_RIGHTS_ALL,
	ACTRL_DS_OPEN,
	ACTRL_DS_CREATE_CHILD,
	ACTRL_DS_DELETE_CHILD,
	ACTRL_DS_LIST,
	ACTRL_DS_READ_PROP,
	ACTRL_DS_WRITE_PROP,
	ACTRL_DS_SELF,
	ACTRL_DS_DELETE_TREE,
	ACTRL_DS_LIST_OBJECT,
	ACTRL_DS_CONTROL_ACCESS };
std::wstring AccessRightStrArray[] = {
	L"GENERIC_READ",
	L"GENERIC_WRITE",
	L"GENERIC_EXECUTE",
	L"GENERIC_ALL",
	L"DELETE",
	L"READ_CONTROL",
	L"WRITE_DAC",
	L"WRITE_OWNER",
	L"SYNCHRONIZE",
	L"STANDARD_RIGHTS_REQUIRED",
	L"STANDARD_RIGHTS_ALL",
	L"ACTRL_DS_OPEN",
	L"ACTRL_DS_CREATE_CHILD",
	L"ACTRL_DS_DELETE_CHILD",
	L"ACTRL_DS_LIST",
	L"ACTRL_DS_READ_PROP",
	L"ACTRL_DS_WRITE_PROP",
	L"ACTRL_DS_SELF",
	L"ACTRL_DS_DELETE_TREE",
	L"ACTRL_DS_LIST_OBJECT",
	L"ACTRL_DS_CONTROL_ACCESS" };


FilesystemObject::FilesystemObject(std::wstring path) :
	path_(path)
{
	fill_acl_info();
	fill_owner();
	fill_integrity_level();


}


FilesystemObject::~FilesystemObject()
{
}

void FilesystemObject::fill_acl_info()
{
	PACL acl;

	ACL_SIZE_INFORMATION acl_info;

	LPVOID pAce;

	PSID pSID;

	PSECURITY_DESCRIPTOR pSD;

	SE_OBJECT_TYPE type = SE_FILE_OBJECT;
	if (GetNamedSecurityInfoW(
		this->path_.c_str(),
		type, DACL_SECURITY_INFORMATION,
		NULL, NULL,
		&acl,
		NULL,
		&pSD))
	{
		//ErrorExit(TEXT("GETNAMED"));
	}

	if (!GetAclInformation(acl, &acl_info, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation))
	{
		//ErrorExit(TEXT("GETACLINFO"));
	}

	this->data_acl.clear();

	int offset = 0;
	for (DWORD i = 0; i < acl_info.AceCount; i++)
	{
		if (!GetAce(acl, i, &pAce))
		{
			//ErrorExit(TEXT("GETACE"));
		}

		ACL_INFO acl_struct;

		pSID = (PSID)(&(static_cast<PACCESS_ALLOWED_ACE>(pAce)->SidStart));

		acl_struct.SID = fill_sid(pSID);

		acl_struct.username = fill_username(pSID);

		acl_struct.sid_type = fill_sid_type(pSID);

		acl_struct.ace_type = fill_ace_type(static_cast<PACCESS_ALLOWED_ACE>(pAce)->Header.AceType);

		acl_struct.mask = fill_mask(static_cast<PACCESS_ALLOWED_ACE>(pAce)->Mask);

		acl_struct.access_rights = fill_access_rights(static_cast<PACCESS_ALLOWED_ACE>(pAce)->Mask);

		this->data_acl.push_back(acl_struct);
	}
}

std::wstring FilesystemObject::fill_sid(PSID pSID)
{
	wchar_t buf[512];
	memset(buf, 0, 512);
	sid_to_text(pSID,buf,512);
	return buf;
}

std::wstring FilesystemObject::fill_username(PSID pSID)
{
	DWORD UserLen=MAX_NAME;
	DWORD DomainLen=MAX_NAME;
	SID_NAME_USE TypeOfpSid;
	wchar_t UserName[MAX_NAME];
	wchar_t DomainName[MAX_NAME];
	if (!LookupAccountSidW(NULL, pSID, UserName, &UserLen, DomainName, &DomainLen, &TypeOfpSid))
	{
		//ErrorExit(TEXT("Lookup"));
	}
	return UserName;
	//return UserName;

}

std::wstring FilesystemObject::fill_sid_type(PSID pSID)
{
	DWORD UserLen=MAX_NAME;
	DWORD DomainLen=MAX_NAME;
	SID_NAME_USE TypeOfpSid;
	char UserName[MAX_NAME];
	char DomainName[MAX_NAME];
	if (!LookupAccountSidA(NULL, pSID, UserName, &UserLen, DomainName, &DomainLen, &TypeOfpSid))
	{
		//ErrorExit(TEXT("Lookup"));
	}

	for (size_t i = 0; i < 10; i++)
	{
		if (TypeOfpSid == SidTypeArray[i])
			return SidStrTypeArray[i];
	}
	return L"ERROR";

}

std::wstring FilesystemObject::fill_ace_type(BYTE type)
{
	for (size_t i=0; i < 25; i++)
	{
		if (type == AceTypeArray[i])
			return AceTypeStrArray[i];
	}
	return L"ERROR";
}

std::wstring FilesystemObject::fill_mask(ACCESS_MASK mask)
{
	std::wstring mask_bin;
	mask_bin.resize(33);
	for (size_t i = 0; i < 32; i++)
	{
		if (mask % 2)
			mask_bin[31 - i] = '1';
		else
			mask_bin[31 - i] = '0';
		mask /= 2;
	}
	mask_bin[32] = '\0';
	return mask_bin;
}

std::vector<std::wstring> FilesystemObject::fill_access_rights(ACCESS_MASK mask)
{
	std::vector<std::wstring> access_rights_vector;
	for (size_t i = 0; i < 21; i++)
	{
		if (mask & AccessRightArray[i])
		{
			access_rights_vector.push_back(AccessRightStrArray[i]);
		}
	}
	return access_rights_vector;
}

BOOL FilesystemObject::sid_to_text(PSID ps, wchar_t *buf, int bufSize)
{
	PSID_IDENTIFIER_AUTHORITY psia;
	DWORD dwSubAuthorities;
	DWORD dwSidRev = SID_REVISION;
	DWORD i;
	int n, size;
	wchar_t *p;

	// Validate the binary SID.

	if (!IsValidSid(ps))
		return FALSE;

	// Get the identifier authority value from the SID.

	psia = GetSidIdentifierAuthority(ps);

	// Get the number of subauthorities in the SID.

	dwSubAuthorities = *GetSidSubAuthorityCount(ps);

	// Compute the buffer length.
	// S-SID_REVISION- + IdentifierAuthority- + subauthorities- + NULL

	size = 15 + 12 + (12 * dwSubAuthorities) + 1;

	// Check input buffer length.
	// If too small, indicate the proper size and set last error.

	if (bufSize < size)
	{
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}

	// Add 'S' prefix and revision number to the string.

	size = wsprintf(buf, L"S-%lu-", dwSidRev);
	p = buf + size;

	// Add SID identifier authority to the string.

	if (psia->Value[0] != 0 || psia->Value[1] != 0)
	{
		n = wsprintf(p, L"0x%02hx%02hx%02hx%02hx%02hx%02hx",
			(USHORT)psia->Value[0], (USHORT)psia->Value[1],
			(USHORT)psia->Value[2], (USHORT)psia->Value[3],
			(USHORT)psia->Value[4], (USHORT)psia->Value[5]);
		size += n;
		p += n;
	}
	else
	{
		n = wsprintf(p, L"%lu", ((ULONG)psia->Value[5]) +
			((ULONG)psia->Value[4] << 8) + ((ULONG)psia->Value[3] << 16) +
			((ULONG)psia->Value[2] << 24));
		size += n;
		p += n;
	}

	// Add SID subauthorities to the string.

	for (i = 0; i < dwSubAuthorities; ++i)
	{
		n = wsprintf(p, L"-%lu", *GetSidSubAuthority(ps, i));
		size += n;
		p += n;
	}

	return TRUE;
}

void FilesystemObject::fill_owner()
{
	PSECURITY_DESCRIPTOR pSD;
	DWORD needLength=0;
	if (!GetFileSecurityW(
		this->path_.c_str(),
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		0,
		0,
		&needLength))
	

	pSD = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needLength);

	if (!GetFileSecurityW(
		this->path_.c_str(),
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		pSD,
		needLength,
		&needLength))
	{
//		ErrorExit(TEXT("GetFileSecurity"));
	}

	PSID pSID;
	BOOL pFlag = FALSE;
	GetSecurityDescriptorOwner(pSD, &pSID, &pFlag);
	wchar_t UserName[MAX_NAME];
	wchar_t DomainName[MAX_NAME];
	DWORD UserLen = MAX_NAME;
	DWORD DomainLen = MAX_NAME;
	SID_NAME_USE snu;
	if (!LookupAccountSidW(
		NULL,
		pSID,
		UserName,
		&UserLen,
		DomainName,
		&DomainLen,
		&snu))
	{
//		ErrorExit(TEXT("LookupAccountSidA"));
		return;
	}
	this->owner = UserName;

	return;
}

void FilesystemObject::fill_integrity_level()
{
	DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL acl = 0;
	GetNamedSecurityInfoW(
		this->path_.c_str(),
		SE_FILE_OBJECT,
		LABEL_SECURITY_INFORMATION,
		0, 0, 0,
		&acl,
		&pSD);

	{
		if (0 != acl && 0 < acl->AceCount)
		{
			SYSTEM_MANDATORY_LABEL_ACE* ace = 0;
			if (GetAce(acl, 0, reinterpret_cast<void**>(&ace)))
			{
				SID* sid = reinterpret_cast<SID*>(&ace->SidStart);
				integrityLevel = sid->SubAuthority[0];
			}
		}

		PWSTR stringSD;
		ULONG stringSDLen = 0;

		ConvertSecurityDescriptorToStringSecurityDescriptor(
			pSD,
			SDDL_REVISION_1,
			LABEL_SECURITY_INFORMATION,
			&stringSD,
			&stringSDLen);

		if (pSD)
		{
			LocalFree(pSD);
		}
	}

	if (integrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID)
		this->integrity_level = L"Untrusted";
	else if (integrityLevel == SECURITY_MANDATORY_LOW_RID)
		this->integrity_level = L"Low Integrity";
	else if (integrityLevel == SECURITY_MANDATORY_MEDIUM_RID)
		this->integrity_level = L"Medium Integrity";
	else if (integrityLevel == SECURITY_MANDATORY_HIGH_RID)
		this->integrity_level = L"High Integrity";
	else if (integrityLevel == SECURITY_MANDATORY_SYSTEM_RID)
		this->integrity_level = L"System Integrity";

	return;

}

BOOL FilesystemObject::change_owner(std::wstring new_owner)
{
	PSID         sid = NULL;
	DWORD        sid_size = 0;
	WCHAR*	     domain = NULL;
	DWORD        domain_size = 0;
	SID_NAME_USE use;

	SetPrivilege(SE_TAKE_OWNERSHIP_NAME, TRUE);

	LookupAccountName(NULL, new_owner.c_str(), sid, &sid_size, domain, &domain_size, &use);
	sid = (PSID)LocalAlloc(LMEM_FIXED, sid_size);
	domain = (WCHAR*)malloc(domain_size * sizeof(WCHAR));
	if (!LookupAccountName(NULL, new_owner.c_str(), sid, &sid_size, domain, &domain_size, &use))
	{
		//ErrorExit(TEXT("LookupAccountNameW"));
		return FALSE;
	}
	int a;
	if (SetNamedSecurityInfoW(
		const_cast<LPWSTR>(this->path_.c_str()),
		SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION,
		sid,
		NULL,
		NULL,
		NULL) != ERROR_SUCCESS)
	{
		//ErrorExit(TEXT("LookupAccountNameW"));
		return FALSE;
	}

	return TRUE;

}

BOOL FilesystemObject::change_integrity_level(int new_integrity_level)
{
	LPCWSTR INTEGRITY_SDDL_SACL_W;

	if (new_integrity_level == LOW_INTEGRITY)
		INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;LW)";
	else if (new_integrity_level == MEDIUM_INTEGRITY)
		INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;ME)";
	else if (new_integrity_level == HIGH_INTEGRITY)
		INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;HI)";

	DWORD dwErr = ERROR_SUCCESS;
	PSECURITY_DESCRIPTOR pSD = NULL;

	PACL pSacl = NULL;
	BOOL fSaclPresent = FALSE;
	BOOL fSaclDefaulted = FALSE;

	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
		INTEGRITY_SDDL_SACL_W,
		SDDL_REVISION_1,
		&pSD,
		NULL))
	{
		if (GetSecurityDescriptorSacl(
			pSD,
			&fSaclPresent,
			&pSacl,
			&fSaclDefaulted))
		{
			dwErr = SetNamedSecurityInfoW(
				const_cast<LPWSTR>(this->path_.c_str()),
				SE_FILE_OBJECT,
				LABEL_SECURITY_INFORMATION,
				NULL,
				NULL,
				NULL,
				pSacl);

			if (dwErr == ERROR_SUCCESS)
			{
				if (pSD)
				{
					LocalFree(pSD);
				}
				return TRUE;
			}
		}
	}
	if (pSD)
	{
		LocalFree(pSD);
	}
	return FALSE;
}

BOOL FilesystemObject::change_acl_info(std::wstring name, DWORD mask, int ace_type)
{
	DWORD dwRes = 0;
	PACL pOldDACL = NULL, pNewDACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS ea;

	dwRes = GetNamedSecurityInfoW(
		this->path_.c_str(),
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION,
		NULL,
		NULL,
		&pOldDACL,
		NULL,
		&pSD);
	if (ERROR_SUCCESS != dwRes)
	{
		if (pSD != NULL)
			LocalFree((HLOCAL)pSD);
		if (pNewDACL != NULL)
			LocalFree((HLOCAL)pNewDACL);
		return FALSE;
	}

	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = mask;
	if (ace_type == DENY_ACCSS)
		ea.grfAccessMode = DENY_ACCESS;
	else if (ace_type == SET_ACCSS)
		ea.grfAccessMode = SET_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
	//	ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea.Trustee.ptstrName = const_cast<LPWSTR>(name.c_str());

	dwRes = SetEntriesInAcl(
		1,
		&ea,
		pOldDACL,
		&pNewDACL);
	if (ERROR_SUCCESS != dwRes)
	{
		if (pSD != NULL)
			LocalFree((HLOCAL)pSD);
		if (pNewDACL != NULL)
			LocalFree((HLOCAL)pNewDACL);
		return FALSE;
	}

	dwRes = SetNamedSecurityInfoW(
		const_cast<LPWSTR>(this->path_.c_str()),
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION,
		NULL,
		NULL,
		pNewDACL,
		NULL);
	if (ERROR_SUCCESS != dwRes)
	{
		if (pSD != NULL)
			LocalFree((HLOCAL)pSD);
		if (pNewDACL != NULL)
			LocalFree((HLOCAL)pNewDACL);
		return FALSE;
	}

	if (pSD != NULL)
		LocalFree((HLOCAL)pSD);
	if (pNewDACL != NULL)
		LocalFree((HLOCAL)pNewDACL);

	return TRUE;
}


void FilesystemObject::ErrorExit(LPTSTR lpszFunction)
{
		// Retrieve the system error message for the last-error code

		LPVOID lpMsgBuf;
		LPVOID lpDisplayBuf;
		DWORD dw = GetLastError();

		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dw,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&lpMsgBuf,
			0, NULL);

		// Display the error message and exit the process

		lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
			(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
		StringCchPrintf((LPTSTR)lpDisplayBuf,
			LocalSize(lpDisplayBuf) / sizeof(TCHAR),
			TEXT("%s failed with error %d: %s"),
			lpszFunction, dw, lpMsgBuf);
		MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

		LocalFree(lpMsgBuf);
		LocalFree(lpDisplayBuf);
		ExitProcess(dw);
}

std::wstring FilesystemObject::WsToCommonString(const WCHAR * wcharstring) const
{
	std::wstring ws(wcharstring);
	return std::wstring(ws.begin(), ws.end());
}

BOOL FilesystemObject::SetPrivilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES priv = { 0,0,0,0 };
	HANDLE hToken = NULL;
	LUID luid = { 0,0 };
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (hToken)
			CloseHandle(hToken);
		return FALSE;
	}
	if (!LookupPrivilegeValueW(0, lpszPrivilege, &luid))
	{
		if (hToken)
			CloseHandle(hToken);
		return FALSE;
	}
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = luid;
	priv.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &priv, 0, 0, 0))
	{
		if (hToken)
			CloseHandle(hToken);
		return FALSE;
	}
	if (hToken)
		CloseHandle(hToken);
	return TRUE;
}
