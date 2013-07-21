
#include "comhdr.h"
//////////////////////////////////////////////////////////////////////////

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

LPFN_ISWOW64PROCESS fnIsWow64Process;

BOOL IsWow64()
{
	BOOL bIsWow64 = FALSE;

	//IsWow64Process is not available on all supported versions of Windows.
	//Use GetModuleHandle to get a handle to the DLL that contains the function
	//and GetProcAddress to get a pointer to the function if available.

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
		GetModuleHandle(("kernel32")),"IsWow64Process");

	if(NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(GetCurrentProcess(),&bIsWow64))
		{
			//handle error
		}
	}
	return bIsWow64;
}

bool	OnlyXpAnd2003OsVersionCheck()
{
	OSVERSIONINFOEX os;

	if (IsWow64())
	{
		MessageBoxA(NULL,"Not Support 64bit","test",NULL);
		return false;
	}
	os.dwOSVersionInfoSize=sizeof(os);

	if(!GetVersionEx((OSVERSIONINFO *)&os))
	{
		MessageBoxA(NULL,"check os version fail",NULL,NULL);
		return false;
	}

	//ver5.1 or 5.2
	if (!(os.dwMajorVersion==5&&(os.dwMinorVersion==1||os.dwMinorVersion==2))
		)
	{
		MessageBoxA(NULL,"this feature is only applied for xp or 2003",NULL,NULL);
		return false;
	}

	return true;

}
//////////////////////////////////////////////////////////////////////////

bool	Only_Xp_2003_win7_OsVersionCheck()
{

	OSVERSIONINFOEX os;
	if (IsWow64())
	{
		MessageBoxA(NULL,"Not Support 64bit","test",NULL);
		return false;
	}

	os.dwOSVersionInfoSize=sizeof(os);

	if(!GetVersionEx((OSVERSIONINFO *)&os))
	{
		MessageBoxA(NULL,"check os version fail",NULL,NULL);
		return false;
	}
	bool	bret =false;
	do 
	{
		if (os.dwMajorVersion==5&&os.dwMinorVersion==1)
		{
			bret= true ;//xp
		}
		if (os.dwMajorVersion==5&&os.dwMinorVersion==2)
		{
			bret= true ;//2003
		}

		if (os.dwMajorVersion==6&&os.dwMinorVersion==1)
		{
#define VER_NT_WORKSTATION 0x0000001
			if (os.wProductType!=VER_NT_WORKSTATION)
			{
				bret= false;
			}
			bret= true ;//win7
		}

	} while (0);

	if (!bret)
	{
		MessageBoxA(NULL,"version Not Support",NULL,NULL);
	}
	return bret;

}