
#include "comhdr.h"
#include "NetworkCentre.h"
#include <tchar.h>
#include <locale.h>
//////////////////////////////////////////////////////////////////////////

#define		MAXNUMBERPENDDING	(4)

LONG		g_CurrentPenddingAskUserEventNumber=0;

bool		g_ReleaseingPendding	=	false;
//////////////////////////////////////////////////////////////////////////
void ReleasePenddingCheckPortIrp()
{
	DWORD	dwRet;
	BOOL bRet;
	g_ReleaseingPendding	=true;
	bRet = DeviceIoControl(g_SuperCIHandle, IOCTL_ReleasePENDDINGCHECKPORT, NULL, 0, NULL, NULL,&dwRet, NULL);


}
CNetworkCentre::CNetworkCentre(void)
{
	m_pTcpBuffer=NULL;
	m_pUdpBuffer=NULL;
}

CNetworkCentre::~CNetworkCentre(void)
{
	if (m_pTcpBuffer)
	{
		delete	m_pTcpBuffer;
	}
	if (m_pUdpBuffer)
	{
		delete	m_pUdpBuffer;
	}
}
//////////////////////////////////////////////////////////////////////////

BOOL CNetworkCentre::GetTcpInfo(void)
{
	DWORD	dwRet=0;

	static DWORD	dwBufferSize=0;
//	char 	strOutput[512];
	BOOL	bRet	=	TRUE;
	do 
	{
		bRet = DeviceIoControl(g_SuperCIHandle, IOCTL_GET_TCPINFO, NULL, 0, NULL, NULL,&dwRet, NULL);
		if (!bRet)
		{
			break;
		}
		if (m_pTcpBuffer)
		{
			if (dwBufferSize<dwRet)
			{
				dwBufferSize	=	dwRet;
				m_pTcpBuffer	=	new char[dwBufferSize];

			}
		}
		else
		{
			dwBufferSize	=	dwRet;
			m_pTcpBuffer	=	new char[dwBufferSize];

		}
		ZeroMemory(m_pTcpBuffer, dwBufferSize);
		
		bRet = DeviceIoControl(g_SuperCIHandle, IOCTL_GET_TCPINFO, NULL, 0, m_pTcpBuffer, dwBufferSize,&dwRet, NULL);
		if (!bRet)
		{
			delete	m_pTcpBuffer;m_pTcpBuffer=NULL;dwBufferSize	=	0;
			break;
		}
		
		
	} while (0);
	
	return bRet;

}

//////////////////////////////////////////////////////////////////////////

BOOL CNetworkCentre::GetUdpInfo(void)
{
	DWORD	dwRet=0;

	static DWORD	dwBufferSize=0;
	BOOL	bRet	=	TRUE;
	do 
	{
		bRet = DeviceIoControl(g_SuperCIHandle, IOCTL_GET_UDPINFO, NULL, 0, NULL, NULL,&dwRet, NULL);
		if (!bRet)
		{
			break;
		}
		if (m_pUdpBuffer)
		{
			if (dwBufferSize<dwRet)
			{
				dwBufferSize	=	dwRet;
				m_pUdpBuffer	=	new char[dwBufferSize];
			}
		}
		else
		{
			dwBufferSize	=	dwRet;
			m_pUdpBuffer	=	new char[dwBufferSize];
		}
		ZeroMemory(m_pUdpBuffer, dwBufferSize);
		bRet = DeviceIoControl(g_SuperCIHandle, IOCTL_GET_UDPINFO, NULL, 0, m_pUdpBuffer, dwBufferSize,&dwRet, NULL);
		if (!bRet)
		{
			delete	m_pUdpBuffer;m_pUdpBuffer=NULL;dwBufferSize	=	0;
			break;
		}

	} while (0);

	return bRet;

}

//
//调用成功后，调用者负责释放 pPath
typedef TCHAR tchar;
BOOL CNetworkCentre::GetProcessPathByPid(int dwPid, PVOID	*pPath)
{
	DWORD	dwRet=0;

	DWORD	dwBufferSize=0;
	BOOL	bRet	=	TRUE;

	PUCHAR	pTmp=NULL;
	char *	pAniPath=NULL;
	if (dwPid==0||dwPid==4)
	{
		DWORD	dwtmp	=	_tcslen(_T("System"))+sizeof(tchar);
		*pPath=new	tchar[dwtmp];
		ZeroMemory(*pPath, dwtmp*sizeof(tchar));
		_tcscpy((char*)*pPath, _T("System"));
		return TRUE;
	}
	do 
	{
		bRet = DeviceIoControl(g_SuperCIHandle, IOCTL_GPATHBYPID, &dwPid, sizeof(dwPid), 0, 0,&dwRet, NULL);
		if (!bRet)
		{
			DWORD	dwError	=	GetLastError();
			if (ERROR_BAD_LENGTH!=dwError)
			{
				break;
			}
			
		}
		dwBufferSize	=	dwRet+2;
		pTmp	=	(PUCHAR)new char[dwBufferSize];
		ZeroMemory(pTmp, dwBufferSize);
		dwRet	=	0;
		bRet = DeviceIoControl(g_SuperCIHandle, IOCTL_GPATHBYPID, &dwPid, sizeof(dwPid), pTmp, dwBufferSize,&dwRet, NULL);
		if (!bRet)
		{
			break;
		}
			if (1)
			{
				DWORD	dwSize=wcslen((WCHAR*)pTmp)*2+1;
				pAniPath	=	(char *)new char[dwSize];
				ZeroMemory(pAniPath, dwSize);

				setlocale(LC_ALL,"");      //设置本地默认Locale. 或者是setlocale(LC_ALL, "chs")

				wcstombs(pAniPath, (wchar_t*)pTmp, dwSize);
				setlocale(LC_ALL,"C");      //默认
			}

		*pPath	=	pAniPath;
		pAniPath=NULL;

	}while(0);

	if (pTmp)
	{
		delete pTmp; pTmp=NULL;
	}
	if (pAniPath)
	{
		delete	pAniPath; pAniPath=NULL;
	}
	return bRet;
}
//////////////////////////////////////////////////////////////////////////

BOOL	CNetworkCentre::AskUserForPermission()
{
	OVERLAPPED	varOverLapped;  
	HANDLE		hNotifyEvent=0;
	DWORD varEventResult; 
	char strDebug[1024];

	hNotifyEvent	=	CreateEvent(NULL, FALSE, FALSE, "");
	memset(&varOverLapped,0,sizeof(OVERLAPPED));  
	varOverLapped.hEvent = hNotifyEvent;  
	varOverLapped.Offset = 0;  
	varOverLapped.OffsetHigh = 0;
	DWORD	dwRet;
	BOOL	bRet;
	DWORD	dwLastError=0;
	FIREWALL_ASKUSER	fas;
	ZeroMemory(&fas, sizeof(FIREWALL_ASKUSER));
	bRet	=	 DeviceIoControl(g_SuperCIHandleASyn, IOCTL_PENDDINGCHECKPORT,  NULL, NULL, (PVOID)&fas, sizeof(fas), &dwRet, &varOverLapped);
	dwLastError	=	GetLastError();
	sprintf(strDebug,"AskUserForPermission() send IOCTL_PENDDINGCHECKPORT bRet=%d, LastError:%d\n", bRet, dwLastError);
	OutputDebugString(strDebug);
	if (!bRet)
	{
		if (dwLastError!=ERROR_IO_PENDING)
		{
				InterlockedDecrement(&g_CurrentPenddingAskUserEventNumber);
				SetUpPenddingAskUserEvent();
				CloseHandle(hNotifyEvent);
				return bRet; 
		}
	}
	sprintf(strDebug, "waiting for Port Check\n");
	OutputDebugString(strDebug);

	varEventResult = WaitForSingleObject(hNotifyEvent,INFINITE);
	CloseHandle(hNotifyEvent);
	if (WAIT_OBJECT_0!=varEventResult)
	{
		InterlockedDecrement(&g_CurrentPenddingAskUserEventNumber);
		SetUpPenddingAskUserEvent();
		return bRet; 
	}
	if (g_ReleaseingPendding)
	{	//这个退出机制其实可以用waitformutilxxxobject来优化
		return bRet;
	}
	//调用回调，处理的结果返回在fas中
	DWORD	dwHandleResult	=	m_EventProcessHanlder((PVOID)&fas);

	InterlockedDecrement(&g_CurrentPenddingAskUserEventNumber);
	SetUpPenddingAskUserEvent();

	bRet	=	 DeviceIoControl(g_SuperCIHandle, IOCTL_RESPONSEPORTASK, (PVOID)&fas, sizeof(fas), NULL, NULL,&dwRet, NULL);
	return bRet;
}
//////////////////////////////////////////////////////////////////////////

DWORD	WINAPI	AskUserThread(PVOID Par)
{

	CNetworkCentre *pThis	=	(CNetworkCentre*)Par;

	return pThis->AskUserForPermission();
}
//////////////////////////////////////////////////////////////////////////

BOOL	CNetworkCentre::SetUpPenddingAskUserEvent(PNotifyArrival pHandler)
{

	long		oriValue=0;
	BOOL		bRet	=	TRUE;
	if (pHandler)
	{
		m_EventProcessHanlder	=	pHandler;
	}
	while(1)
	{
		oriValue	=	InterlockedIncrement(&g_CurrentPenddingAskUserEventNumber);
		if (oriValue>MAXNUMBERPENDDING)
		{
			InterlockedDecrement(&g_CurrentPenddingAskUserEventNumber);
			break;
		}
		DWORD	dwThread=0;
		HANDLE	hThread	=	CreateThread(NULL, NULL, AskUserThread, this, NULL, &dwThread);
		if (hThread==NULL)
		{
			MessageBoxA(NULL,"fuck CreateThread fail" ,"test",NULL);
		}
		else
		CloseHandle(hThread);
	}

	return	bRet;
}
//////////////////////////////////////////////////////////////////////////

BOOL	CNetworkCentre::SetUpFW(BOOL bSet)
{
	DWORD	dwRet;
	BOOL	bRet;
	if (bSet)
	{
			bRet	=	 DeviceIoControl(g_SuperCIHandle, IOCTL_SETUPFW, NULL, 0, NULL, NULL,&dwRet, NULL);
	}
	else
	{
			bRet	=	 DeviceIoControl(g_SuperCIHandle, IOCTL_UNSETFW, NULL, 0, NULL, NULL,&dwRet, NULL);
	}
	return TRUE;
}
//////////////////////////////////////////////////////////////////////////
//调用者负责使用delete PortStatusHeader
//借用下FIREWALL_ASKUSER这个结构体
BOOL	CNetworkCentre::GetPortRule(void **PortStatusHeader, int &iNumber)
{
	DWORD	dwRet=0;

	DWORD	dwBufferSize=0;
//	char 	strOutput[512];
	BOOL	bRet	=	TRUE;
	char	*pBuffer	=	NULL;
	do 
	{
		bRet = DeviceIoControl(g_SuperCIHandle, IOCTL_GETPORTSTATUS, NULL, 0, NULL, NULL,&dwRet, NULL);
		if (!bRet)
		{
			break;
		}

		dwBufferSize	=	dwRet;
		pBuffer	=	new char[dwBufferSize];

		ZeroMemory(pBuffer, dwBufferSize);
		bRet = DeviceIoControl(g_SuperCIHandle, IOCTL_GETPORTSTATUS, NULL, 0, pBuffer, dwBufferSize,&dwRet, NULL);
		if (!bRet)
		{

			break;
		}
		//成功了
		*PortStatusHeader	=	(void *)pBuffer;
		iNumber	=	dwBufferSize/sizeof(FIREWALL_ASKUSER);
		pBuffer	=NULL;

	} while (0);

	if (pBuffer)
	{
		delete	pBuffer;pBuffer=NULL;
	}
	return bRet;


}