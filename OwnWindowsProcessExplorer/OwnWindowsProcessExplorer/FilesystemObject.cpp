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
std::string SidStrTypeArray[] = {
	"SidTypeUser",
	"SidTypeGroup",
	"SidTypeDomain",
	"SidTypeAlias",
	"SidTypeWellKnownGroup",
	"SidTypeDeletedAccount",
	"SidTypeInvalid",
	"SidTypeUnknown",
	"SidTypeComputer",
	"SidTypeLabel" };
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
std::string AceTypeStrArray[] = {
	"ACCESS_ALLOWED_ACE_TYPE",
	"ACCESS_DENIED_ACE_TYPE",
	"SYSTEM_AUDIT_ACE_TYPE",
	"SYSTEM_ALARM_ACE_TYPE",
	"ACCESS_MAX_MS_V2_ACE_TYPE",
	"ACCESS_ALLOWED_COMPOUND_ACE_TYPE",
	"ACCESS_MAX_MS_V3_ACE_TYPE",
	"ACCESS_MIN_MS_OBJECT_ACE_TYPE",
	"ACCESS_ALLOWED_OBJECT_ACE_TYPE",
	"ACCESS_DENIED_OBJECT_ACE_TYPE",
	"SYSTEM_AUDIT_OBJECT_ACE_TYPE",
	"SYSTEM_ALARM_OBJECT_ACE_TYPE",
	"ACCESS_MAX_MS_OBJECT_ACE_TYPE",
	"ACCESS_MAX_MS_V4_ACE_TYPE",
	"ACCESS_MAX_MS_ACE_TYPE",
	"ACCESS_ALLOWED_CALLBACK_ACE_TYPE",
	"ACCESS_DENIED_CALLBACK_ACE_TYPE",
	"ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE",
	"ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE",
	"SYSTEM_AUDIT_CALLBACK_ACE_TYPE",
	"SYSTEM_ALARM_CALLBACK_ACE_TYPE",
	"SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE",
	"SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE",
	"SYSTEM_MANDATORY_LABEL_ACE_TYPE",
	"ACCESS_MAX_MS_V5_ACE_TYPE"
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
std::string AccessRightStrArray[] = {
	"GENERIC_READ",
	"GENERIC_WRITE",
	"GENERIC_EXECUTE",
	"GENERIC_ALL",
	"DELETE",
	"READ_CONTROL",
	"WRITE_DAC",
	"WRITE_OWNER",
	"SYNCHRONIZE",
	"STANDARD_RIGHTS_REQUIRED",
	"STANDARD_RIGHTS_ALL",
	"ACTRL_DS_OPEN",
	"ACTRL_DS_CREATE_CHILD",
	"ACTRL_DS_DELETE_CHILD",
	"ACTRL_DS_LIST",
	"ACTRL_DS_READ_PROP",
	"ACTRL_DS_WRITE_PROP",
	"ACTRL_DS_SELF",
	"ACTRL_DS_DELETE_TREE",
	"ACTRL_DS_LIST_OBJECT",
	"ACTRL_DS_CONTROL_ACCESS" };


FilesystemObject::FilesystemObject(std::string path) :
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
	if (GetNamedSecurityInfoA(this->path_.c_str(),type, DACL_SECURITY_INFORMATION, NULL, NULL, &acl, NULL, &pSD))
	{
		ErrorExit(TEXT("GETNAMED"));
	}

	if (!GetAclInformation(acl, &acl_info, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation))
	{
		ErrorExit(TEXT("GETACLINFO"));
	}

	int offset = 0;
	for (DWORD i = 0; i < acl_info.AceCount; i++)
	{
		if (!GetAce(acl, i, &pAce))
		{
			ErrorExit(TEXT("GETACE"));
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

std::string FilesystemObject::fill_sid(PSID pSID)
{
	char buf[512];
	memset(buf, 0, 512);
	sid_to_text(pSID,buf,512);
	return buf;
}

std::string FilesystemObject::fill_username(PSID pSID)
{
	DWORD UserLen=MAX_NAME;
	DWORD DomainLen=MAX_NAME;
	SID_NAME_USE TypeOfpSid;
	char UserName[MAX_NAME];
	char DomainName[MAX_NAME];
	if (!LookupAccountSidA(NULL, pSID, UserName, &UserLen, DomainName, &DomainLen, &TypeOfpSid))
	{
		ErrorExit(TEXT("Lookup"));
	}
	return UserName;
	//return UserName;

}

std::string FilesystemObject::fill_sid_type(PSID pSID)
{
	DWORD UserLen=MAX_NAME;
	DWORD DomainLen=MAX_NAME;
	SID_NAME_USE TypeOfpSid;
	char UserName[MAX_NAME];
	char DomainName[MAX_NAME];
	if (!LookupAccountSidA(NULL, pSID, UserName, &UserLen, DomainName, &DomainLen, &TypeOfpSid))
	{
		ErrorExit(TEXT("Lookup"));
	}

	for (size_t i = 0; i < 10; i++)
	{
		if (TypeOfpSid == SidTypeArray[i])
			return SidStrTypeArray[i];
	}
	return "ERROR";

}

std::string FilesystemObject::fill_ace_type(BYTE type)
{
	for (size_t i=0; i < 25; i++)
	{
		if (type == AceTypeArray[i])
			return AceTypeStrArray[i];
	}
	return "ERROR";
}

std::string FilesystemObject::fill_mask(ACCESS_MASK mask)
{
	std::string mask_bin;
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

std::vector<std::string> FilesystemObject::fill_access_rights(ACCESS_MASK mask)
{
	std::vector<std::string> access_rights_vector;
	for (size_t i = 0; i < 21; i++)
	{
		if (mask & AccessRightArray[i])
		{
			access_rights_vector.push_back(AccessRightStrArray[i]);
		}
	}
	return access_rights_vector;
}

BOOL FilesystemObject::sid_to_text(PSID ps, char *buf, int bufSize)
{
	PSID_IDENTIFIER_AUTHORITY psia;
	DWORD dwSubAuthorities;
	DWORD dwSidRev = SID_REVISION;
	DWORD i;
	int n, size;
	char *p;

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

	size = sprintf(buf, "S-%lu-", dwSidRev);
	p = buf + size;

	// Add SID identifier authority to the string.

	if (psia->Value[0] != 0 || psia->Value[1] != 0)
	{
		n = sprintf(p, "0x%02hx%02hx%02hx%02hx%02hx%02hx",
			(USHORT)psia->Value[0], (USHORT)psia->Value[1],
			(USHORT)psia->Value[2], (USHORT)psia->Value[3],
			(USHORT)psia->Value[4], (USHORT)psia->Value[5]);
		size += n;
		p += n;
	}
	else
	{
		n = sprintf(p, "%lu", ((ULONG)psia->Value[5]) +
			((ULONG)psia->Value[4] << 8) + ((ULONG)psia->Value[3] << 16) +
			((ULONG)psia->Value[2] << 24));
		size += n;
		p += n;
	}

	// Add SID subauthorities to the string.

	for (i = 0; i < dwSubAuthorities; ++i)
	{
		n = sprintf(p, "-%lu", *GetSidSubAuthority(ps, i));
		size += n;
		p += n;
	}

	return TRUE;
}

void FilesystemObject::fill_owner()
{
	PSECURITY_DESCRIPTOR pSD;
	DWORD needLength=0;
	if (!GetFileSecurityA(
		this->path_.c_str(),
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		0,
		0,
		&needLength))
	

	pSD = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needLength);

	if (!GetFileSecurityA(
		this->path_.c_str(),
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		pSD,
		needLength,
		&needLength))
	{
		ErrorExit(TEXT("GetFileSecurity"));
	}

	PSID pSID;
	BOOL pFlag = FALSE;
	GetSecurityDescriptorOwner(pSD, &pSID, &pFlag);
	char UserName[MAX_NAME];
	char DomainName[MAX_NAME];
	DWORD UserLen = MAX_NAME;
	DWORD DomainLen = MAX_NAME;
	SID_NAME_USE snu;
	if (!LookupAccountSidA(NULL, pSID, UserName, &UserLen, DomainName, &DomainLen, &snu))
	{
		ErrorExit(TEXT("LookupAccountSidA"));
	}
	this->owner = UserName;

	return;
}

void FilesystemObject::fill_integrity_level()
{
	DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL acl = 0;
	GetNamedSecurityInfoA(this->path_.c_str(), SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, 0, 0, 0, &acl, &pSD);

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

		ConvertSecurityDescriptorToStringSecurityDescriptor(pSD, SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, &stringSD, &stringSDLen);

		if (pSD)
		{
			LocalFree(pSD);
		}
	}

	if (integrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID)
		this->integrity_level = "Untrusted";
	else if (integrityLevel == SECURITY_MANDATORY_LOW_RID)
		this->integrity_level = "Low Integrity";
	else if (integrityLevel == SECURITY_MANDATORY_MEDIUM_RID)
		this->integrity_level = "Medium Integrity";
	else if (integrityLevel == SECURITY_MANDATORY_HIGH_RID)
		this->integrity_level = "High Integrity";
	else if (integrityLevel == SECURITY_MANDATORY_SYSTEM_RID)
		this->integrity_level = "System Integrity";

	return;

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

std::string FilesystemObject::WsToCommonString(const WCHAR * wcharstring) const
{
	std::wstring ws(wcharstring);
	return std::string(ws.begin(), ws.end());
}
