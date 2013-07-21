
#include "comhdr.h"
#include "PatchWS.h"

CPatchWS::CPatchWS(void)
{


}

CPatchWS::~CPatchWS(void)
{
}


//////////////////////////////////////////////////////////////////////////

bool CPatchWS::doPatch( char *proName)
{
	DWORD	dwRet=0;
	DWORD	dwRetBuffer=0;
	bool bret = (bool)DeviceIoControl(g_SuperCIHandle, IOCTL_CHECKNPFSYS, proName, strlen(proName), &dwRetBuffer, sizeof(dwRetBuffer),&dwRet, NULL);
	if (!bret)
	{
		MessageBoxA(NULL,"oops, no wiresharek found installed on this machine","POP",NULL);
		return bret;
	}

	bret = DeviceIoControl(g_SuperCIHandle, IOCTL_PATCHWS, proName, strlen(proName), NULL, NULL,&dwRet, NULL);
	return bret;
}

//////////////////////////////////////////////////////////////////////////

bool CPatchWS::UndoPatch(char *name)
{

	DWORD	dwRet=0;
	DWORD	dwRetBuffer=0;
	bool bret = (bool)DeviceIoControl(g_SuperCIHandle, IOCTL_UNPATCHWS , name, strlen(name), &dwRetBuffer, sizeof(dwRetBuffer),&dwRet, NULL);
	return bret;
}
//////////////////////////////////////////////////////////////////////////

BOOL CPatchWS::PatchDontLoopback(void)
{
	DWORD	dwRet=0;
	DWORD	dwRetBuffer=0;
	BOOL bret = DeviceIoControl(g_SuperCIHandle, IOCTL_PATCH_NOSENTLOOPBACK ,0,0, 0,0,&dwRet, NULL);
	return bret;
}
//////////////////////////////////////////////////////////////////////////

BOOL CPatchWS::PatchRestoreDontLoopback(void)
{
	DWORD	dwRet=0;
	DWORD	dwRetBuffer=0;
	BOOL bret = DeviceIoControl(g_SuperCIHandle, IOCTL_PATCH_RESTORE_NOSENTLOOPBACK ,0,0, 0,0,&dwRet, NULL);
	return bret;
}
