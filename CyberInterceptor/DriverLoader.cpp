#include "StdAfx.h"
#include "DriverLoader.h"
#include <windows.h>
#include <StrSafe.h>


CDriverLoader::CDriverLoader(void)
{
	bDriverLoaded	=	false;
}

CDriverLoader::~CDriverLoader(void)
{
		bDriverLoaded	=	false;
}

#define STATUS_SUCCESS     ((NTSTATUS)0x00000000L)

////////////////////////////////////////////////////////////////////////////////

typedef LONG NTSTATUS;

typedef struct _STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PVOID Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;

typedef LSA_UNICODE_STRING UNICODE_STRING, *PUNICODE_STRING;


typedef DWORD (CALLBACK* RTLANSISTRINGTOUNICODESTRING)(PVOID, PVOID,DWORD);
RTLANSISTRINGTOUNICODESTRING RtlAnsiStringToUnicodeString;
typedef DWORD (CALLBACK* RTLFREEUNICODESTRING)(PVOID);
RTLFREEUNICODESTRING RtlFreeUnicodeString;
typedef DWORD (CALLBACK* ZWLOADDRIVER)(PVOID);
ZWLOADDRIVER ZwLoadDriver;
typedef DWORD (CALLBACK* ZWUNLOADDRIVER)(PVOID);
ZWUNLOADDRIVER ZwUnloadDriver;

BOOL GetLoadDriverPriv()
{
	HANDLE hToken;

	if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		LUID huid;
		if(LookupPrivilegeValue(NULL, "SeLoadDriverPrivilege", &huid))
		{
			LUID_AND_ATTRIBUTES priv;
			priv.Attributes = SE_PRIVILEGE_ENABLED;
			priv.Luid = huid;

			TOKEN_PRIVILEGES tp;
			tp.PrivilegeCount = 1;
			tp.Privileges[0] = priv;

			if(AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL))
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}

bool LoadDriver(char * szDrvName, char * szDrvPath)
{
	char szSubKey[MAX_PATH];
	char szDrvFullPath[MAX_PATH];
//	LSA_UNICODE_STRING buf1;
//	LSA_UNICODE_STRING buf2;
	int iBuffLen;
	HKEY hkResult;
//	char Data[4];
	DWORD dwOK;
	iBuffLen = sprintf_s(szSubKey, MAX_PATH, "System\\CurrentControlSet\\Services\\%s", szDrvName);
	szSubKey[iBuffLen]=0;
	dwOK = RegCreateKey(HKEY_LOCAL_MACHINE,szSubKey,&hkResult);
	if(dwOK!=ERROR_SUCCESS)
		return false;


	DWORD val;
	val = 1;
	if(RegSetValueEx(hkResult, "Type", 0, REG_DWORD, (PBYTE)&val, sizeof(val)) != ERROR_SUCCESS)
		return FALSE;

	if(RegSetValueEx(hkResult, "ErrorControl", 0, REG_DWORD, (PBYTE)&val, sizeof(val)) != ERROR_SUCCESS)
		return FALSE;

	val = 3;
	if(RegSetValueEx(hkResult, "Start", 0, REG_DWORD, (PBYTE)&val, sizeof(val)) != ERROR_SUCCESS)
		return FALSE;

	GetFullPathName(szDrvPath, MAX_PATH, szDrvFullPath, NULL);  
	printf("  Loading driver: %s\r\n", szDrvFullPath);
	iBuffLen = sprintf_s(szSubKey, MAX_PATH, "\\??\\%s", szDrvFullPath);
	szSubKey[iBuffLen]=0;
	dwOK=RegSetValueEx(hkResult,"ImagePath",0,1,(const unsigned char *)szSubKey,iBuffLen);
	RegCloseKey(hkResult); 


	HMODULE hntdll;

	hntdll = LoadLibrary( "ntdll.dll" ); 

	VOID (WINAPI *_RtlInitAnsiString)
		(IN OUT PANSI_STRING  DestinationString,
		IN PCHAR  SourceString);

	*(FARPROC *)&_RtlInitAnsiString = 
		GetProcAddress(hntdll, "RtlInitAnsiString");

	ANSI_STRING aStr;
	char szServicePath[MAX_PATH];
	sprintf_s(szServicePath, MAX_PATH, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", szDrvName);
	_RtlInitAnsiString(&aStr, szServicePath);

	UNICODE_STRING uStr;

	if(RtlAnsiStringToUnicodeString(&uStr, &aStr, TRUE) != STATUS_SUCCESS)
	{
		return FALSE;
	}
	else
	{
		DWORD	dwRet=ZwLoadDriver(&uStr); 
		#define STATUS_IMAGE_ALREADY_LOADED      ((NTSTATUS)0xC000010EL)
		if (STATUS_IMAGE_ALREADY_LOADED== dwRet)
		{
			OutputDebugString("ZwLoadDriver return STATUS_IMAGE_ALREADY_LOADED\n");
		}
		if( dwRet== STATUS_SUCCESS || dwRet==STATUS_IMAGE_ALREADY_LOADED )
		{
			RtlFreeUnicodeString(&uStr);
		}
		else
		{

			
			RtlFreeUnicodeString(&uStr);			
			return FALSE;
		}
	}

	iBuffLen=sprintf_s(szSubKey, MAX_PATH, "%s%s\\Enum","System\\CurrentControlSet\\Services\\", szDrvName);
	szSubKey[iBuffLen]=0;
	RegDeleteKey(HKEY_LOCAL_MACHINE,szSubKey);
	iBuffLen=sprintf_s(szSubKey, MAX_PATH, "%s%s\\Security","System\\CurrentControlSet\\Services\\", szDrvName);
	szSubKey[iBuffLen]=0;
	RegDeleteKey(HKEY_LOCAL_MACHINE,szSubKey);
	iBuffLen=sprintf_s(szSubKey, MAX_PATH, "%s%s","System\\CurrentControlSet\\Services\\", szDrvName);
	szSubKey[iBuffLen]=0;
	RegDeleteKey(HKEY_LOCAL_MACHINE,szSubKey);
	iBuffLen=sprintf_s(szSubKey, MAX_PATH, "\\\\.\\%s", szDrvName);
	szSubKey[iBuffLen]=0;
	return true;
}

bool UnloadDriver(char * szDrvName, char * szDrvPath)
{
	char szSubKey[MAX_PATH];
	char szDrvFullPath[MAX_PATH];
//	LSA_UNICODE_STRING buf1;
//	LSA_UNICODE_STRING buf2;
	int iBuffLen;
	HKEY hkResult;
//	char Data[4];
	DWORD dwOK;
	iBuffLen = sprintf_s(szSubKey, MAX_PATH, "System\\CurrentControlSet\\Services\\%s", szDrvName);
	szSubKey[iBuffLen]=0;
	dwOK = RegCreateKey(HKEY_LOCAL_MACHINE,szSubKey,&hkResult);
	if(dwOK!=ERROR_SUCCESS)
		return false;


	DWORD val;
	val = 1;
	if(RegSetValueEx(hkResult, "Type", 0, REG_DWORD, (PBYTE)&val, sizeof(val)) != ERROR_SUCCESS)
		return FALSE;

	if(RegSetValueEx(hkResult, "ErrorControl", 0, REG_DWORD, (PBYTE)&val, sizeof(val)) != ERROR_SUCCESS)
		return FALSE;

	val = 3;
	if(RegSetValueEx(hkResult, "Start", 0, REG_DWORD, (PBYTE)&val, sizeof(val)) != ERROR_SUCCESS)
		return FALSE;

	GetFullPathName(szDrvPath, MAX_PATH, szDrvFullPath, NULL);  
	printf("  Loading driver: %s\r\n", szDrvFullPath);
	iBuffLen = sprintf_s(szSubKey, MAX_PATH, "\\??\\%s", szDrvFullPath);
	szSubKey[iBuffLen]=0;
	dwOK=RegSetValueEx(hkResult,"ImagePath",0,1,(const unsigned char *)szSubKey,iBuffLen);
	RegCloseKey(hkResult); 


	HMODULE hntdll;

	hntdll = LoadLibrary( "ntdll.dll" ); 

	VOID (WINAPI *_RtlInitAnsiString)
		(IN OUT PANSI_STRING  DestinationString,
		IN PCHAR  SourceString);

	*(FARPROC *)&_RtlInitAnsiString = 
		GetProcAddress(hntdll, "RtlInitAnsiString");

	ANSI_STRING aStr;
	char szServicePath[MAX_PATH];
	sprintf_s(szServicePath, MAX_PATH, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", szDrvName);
	_RtlInitAnsiString(&aStr, szServicePath);

	UNICODE_STRING uStr;

	if(RtlAnsiStringToUnicodeString(&uStr, &aStr, TRUE) != STATUS_SUCCESS)
	{
		return FALSE;
	}
	else
	{
		if(ZwUnloadDriver(&uStr) == STATUS_SUCCESS)
		{
			RtlFreeUnicodeString(&uStr);
		}
		else
		{
			RtlFreeUnicodeString(&uStr);			
			return FALSE;
		}
	}

	iBuffLen=sprintf_s(szSubKey, MAX_PATH, "%s%s\\Enum","System\\CurrentControlSet\\Services\\", szDrvName);
	szSubKey[iBuffLen]=0;

	RegDeleteKey(HKEY_LOCAL_MACHINE,szSubKey);
	iBuffLen=sprintf_s(szSubKey, MAX_PATH, "%s%s\\Security","System\\CurrentControlSet\\Services\\", szDrvName);
	szSubKey[iBuffLen]=0;
	RegDeleteKey(HKEY_LOCAL_MACHINE,szSubKey);
	iBuffLen=sprintf_s(szSubKey, MAX_PATH, "%s%s","System\\CurrentControlSet\\Services\\", szDrvName);
	szSubKey[iBuffLen]=0;
	RegDeleteKey(HKEY_LOCAL_MACHINE,szSubKey);
	iBuffLen=sprintf_s(szSubKey, MAX_PATH, "\\\\.\\%s", szDrvName);
	szSubKey[iBuffLen]=0;
	return true;
}

bool CDriverLoader::MyZwLoadDriver(char * szDrvName, char * szDrvPath)
{

	if(!GetLoadDriverPriv())
	{
		return FALSE;
	}

	if (strrchr(szDrvPath,'\\')==NULL)
	{
		char path[512];	//无完整路径
		GetModuleFileName(NULL, path, 512);
		strncpy(strrchr(path, '\\')+1, szDrvPath, strlen(szDrvPath)+1);
		szDrvPath	=	path;
	}
	if (0xFFFFFFFF == ::GetFileAttributes(szDrvPath))
	{
		MessageBoxA(NULL,szDrvPath,"文件不存在",NULL);
		return false;
	}
	m_szDrvName	=	szDrvName;
	m_szDrvPath	=	szDrvPath;
	HMODULE hNtdll = NULL;
	hNtdll = LoadLibrary( "ntdll.dll" ); 
	RtlAnsiStringToUnicodeString = (RTLANSISTRINGTOUNICODESTRING) GetProcAddress( hNtdll, "RtlAnsiStringToUnicodeString");
	RtlFreeUnicodeString = (RTLFREEUNICODESTRING) GetProcAddress( hNtdll, "RtlFreeUnicodeString");
	ZwLoadDriver = (ZWLOADDRIVER) GetProcAddress( hNtdll, "ZwLoadDriver");
	ZwUnloadDriver = (ZWLOADDRIVER) GetProcAddress( hNtdll, "ZwUnloadDriver");
	//注册驱动程衼E
	if(LoadDriver(szDrvName, szDrvPath) == false)
	{
		FreeLibrary(hNtdll);
		return false;
	}
	bDriverLoaded	=	true;
	FreeLibrary(hNtdll);
	return true;
}

bool CDriverLoader::MyZwUnloadDriver(char * szDrvName, char * szDrvPath)
{     

	if(!GetLoadDriverPriv())
	{
		return FALSE;
	}
	if (szDrvName==NULL)
	{
		szDrvName=(char*)m_szDrvName.c_str();
	}
	if (szDrvPath==NULL)
	{
		szDrvPath=(char*)m_szDrvPath.c_str();
	}
	if (szDrvName==NULL||szDrvPath==NULL)
	{
		OutputDebugString("Driver do not Exist!!!\n");
		return false;
	}
	if (strlen(szDrvName)==0)
	{
		OutputDebugString("Driver do not Exist!!!\n");
		return false;
	}
	HMODULE hNtdll = NULL;
	hNtdll = LoadLibrary( "ntdll.dll" ); 
	RtlAnsiStringToUnicodeString = (RTLANSISTRINGTOUNICODESTRING) GetProcAddress( hNtdll, "RtlAnsiStringToUnicodeString");
	RtlFreeUnicodeString = (RTLFREEUNICODESTRING) GetProcAddress( hNtdll, "RtlFreeUnicodeString");
	ZwUnloadDriver = (ZWLOADDRIVER) GetProcAddress( hNtdll, "ZwUnloadDriver");
	if(UnloadDriver(szDrvName, szDrvPath) == false)
	{ 
		FreeLibrary(hNtdll);
		return false;
	}

	FreeLibrary(hNtdll);
	return true;
}
