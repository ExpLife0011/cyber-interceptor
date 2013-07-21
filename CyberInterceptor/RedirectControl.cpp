#include "comhdr.h"
#include <IPHlpApi.h>
#include "RedirectControl.h"
//////////////////////////////////////////////////////////////////////////


CRedirectControl::CRedirectControl(void)
{
	


}

CRedirectControl::~CRedirectControl(void)
{


}
//////////////////////////////////////////////////////////////////////////
bool CRedirectControl::RefreshLocalIP()
{
	 typedef DWORD  (__stdcall *PGAINFO)(PIP_ADAPTER_INFO,PULONG);  

	HMODULE hInst = LoadLibraryA("iphlpapi.dll"); 
	PGAINFO pGAInfo = (PGAINFO)GetProcAddress(hInst,"GetAdaptersInfo");  
	ULONG ulSize = 0;  
	PIP_ADAPTER_INFO pInfo=NULL,d=NULL;  
	DWORD dwret =0;

	vector<PIPINFO>::iterator it1;
	for (it1 = m_LocalIps.begin(); it1!=m_LocalIps.end(); it1++)
	{
		delete *it1;
	}
	m_LocalIps.clear();
	while ((dwret = pGAInfo(pInfo,&ulSize)) != ERROR_SUCCESS)  
	{  
		if (dwret!=ERROR_BUFFER_OVERFLOW)
		{
			return 0;
		}
		delete pInfo;  
		int esize = ulSize/sizeof(IP_ADAPTER_INFO);  
		if (ulSize%sizeof(IP_ADAPTER_INFO))  
		{  
			esize++;  
		}  
		pInfo= (PIP_ADAPTER_INFO) new(IP_ADAPTER_INFO[esize]);  
	} 
	int i=0;  
	for(d= pInfo; d != NULL; d= d->Next) //枚举网卡信息  
	{  
		
		//szNetInfo.Format("%d. %s",++i,d->IpAddressList.IpAddress.String);  
		IPINFO	*pIP	=	new IPINFO;
		pIP->localIP	=	inet_addr(d->IpAddressList.IpAddress.String);
		pIP->GatewayIP	=	inet_addr(d->GatewayList.IpAddress.String);
		m_LocalIps.push_back(pIP);

		//m_ComboBox.AddString(szNetInfo);  
	}  

	//最后不要忘了释放空间和动态链接库..  
	delete[] pInfo;  
	FreeLibrary(hInst);  
	return 1;

}
//////////////////////////////////////////////////////////////////////////
bool CRedirectControl::IsLocalIP(TCHAR *IP)
{

	RefreshLocalIP();
	vector<PIPINFO>::iterator it1;
	IPINFO *pValue=NULL;
	ULONG	ip	=	inet_addr(IP);
	for (it1 = m_LocalIps.begin(); it1!=m_LocalIps.end(); it1++)
	{
		pValue	=	*it1;
		if (ip==pValue->localIP)
		{
			return true;
		}
	}
	return false;

	
}

//////////////////////////////////////////////////////////////////////////

BOOL CRedirectControl::AddRedirectIP(TCHAR *fromIP, TCHAR *toIP )
{
	SET_REDIRECT_INFO *pSRI	=	new SET_REDIRECT_INFO;
	pSRI->from	=	inet_addr(fromIP);
	pSRI->to	=	inet_addr(toIP);
	pSRI->bLocal	=	IsLocalIP(toIP);
	
	DWORD	dwRet=0;
	BOOL bret = DeviceIoControl(g_SuperCIHandle, IOCTL_ADD_RIDIRECTINFO, pSRI, sizeof(SET_REDIRECT_INFO), NULL, NULL,&dwRet, NULL);
	if (!bret)
	{
		delete pSRI;
		return false;
	}
	bret	=true;
	m_RedirectInfoList.push_back(pSRI);
	return bret;

}
//////////////////////////////////////////////////////////////////////////
bool CRedirectControl::IsAlreadyAdded(TCHAR *fromIP, TCHAR *toIP )
{
	SET_REDIRECT_INFO *pSRI	=	NULL;

	LRedirect::iterator it1;
	bool	bfound	=	false;
	for (it1 = m_RedirectInfoList.begin(); it1!=m_RedirectInfoList.end(); it1 ++)
	{
		pSRI	=	*it1;
		if (
			(pSRI->from	==	inet_addr(fromIP))||\
			(pSRI->to	==	inet_addr(toIP))
			)
		{

			bfound	=	true;
			break;
		}
	}
	return bfound;

}
BOOL CRedirectControl::DelRedirectIP(TCHAR *fromIP, TCHAR *toIP )
{

	SET_REDIRECT_INFO *pSRI	=	NULL;

	LRedirect::iterator it1;
	bool	bfound	=	false;
	for (it1 = m_RedirectInfoList.begin(); it1!=m_RedirectInfoList.end(); it1 ++)
	{
		pSRI	=	*it1;
		if (
			(pSRI->from	==	inet_addr(fromIP))&&\
			 (pSRI->to	==	inet_addr(toIP))
			)
		{
			
			bfound	=	true;
			break;
		}
	}
	if (!bfound)
	{
		MessageBoxA(NULL,"Not Found","test",NULL);
		return false;
	}
	DWORD	dwRet=0;
	BOOL bret = DeviceIoControl(g_SuperCIHandle, IOCTL_DEL_RIDIRECTINFO, pSRI, sizeof(SET_REDIRECT_INFO), NULL, NULL,&dwRet, NULL);
	if (!bret)
	{
			MessageBoxA(NULL,"IOCTL_DEL_RIDIRECTINFO Fail","test",NULL);
			return bret;
	}
	bret	=	true;
	m_RedirectInfoList.erase(it1);
	delete pSRI;
	return bret;

}
//////////////////////////////////////////////////////////////////////////
BOOL	CRedirectControl::FixGatewayMac()
{

	
	vector<PIPINFO>::iterator it1;
	PIPINFO			 pValue=NULL;
	NETCARDS_INFO	*pNI,*ptmp=NULL;
	bool			bFound	=	false;
	DWORD			dwBufferSize=0;
	ULONG			ulLen=0;
	DWORD			dwRet	=	0;


	RefreshLocalIP();
	dwBufferSize	=	sizeof(NETCARDS_INFO)* m_LocalIps.size();
	ptmp = pNI	=	new NETCARDS_INFO[dwBufferSize];
	if (ptmp==NULL)
	{
		return false;
	}
	for (it1 = m_LocalIps.begin(); it1!=m_LocalIps.end(); it1++)
	{
			pValue	=	*it1;
			ulLen	=	MACADDRESSLEN;
			dwRet = SendARP(pValue->GatewayIP, NULL, pNI->GatewayMacAddr, &ulLen);
			if (dwRet!=NO_ERROR)
			{
				ZeroMemory(pNI, sizeof(NETCARDS_INFO));
				continue;
			}

			bFound	=	true;
			pNI->GatewayIpAddr	=	pValue->GatewayIP;
			pNI->IPAddr	=	pValue->localIP;
			pNI++;
			
	}

	if (!bFound)
	{
		delete ptmp;
		return false;
	}
	dwRet=0;
	BOOL bret = DeviceIoControl(g_SuperCIHandle, IOCTL_FIX_GATEWAYMAC, ptmp, dwBufferSize, NULL, NULL,&dwRet, NULL);
	delete ptmp;
	if (!bret)
	{
		return false;
	}

	return true;



}
int CRedirectControl::Clean(void)
{

	SET_REDIRECT_INFO *pSRI	=	NULL;

	LRedirect::iterator it1;

	for (it1 = m_RedirectInfoList.begin(); it1!=m_RedirectInfoList.end(); it1++)
	{
		pSRI	=	*it1;
		DWORD	dwRet=0;
		BOOL bret = DeviceIoControl(g_SuperCIHandle, IOCTL_DEL_RIDIRECTINFO, pSRI, sizeof(SET_REDIRECT_INFO), NULL, NULL,&dwRet, NULL);
		if (!bret)
		{
			return 0;	//如果这里进行到一步的时候，数据就不一致了
		}

		
	}
	for (it1 = m_RedirectInfoList.begin(); it1!=m_RedirectInfoList.end(); it1 ++)
	{
		pSRI	=	*it1;
		delete pSRI;
		
	}
	m_RedirectInfoList.clear();
	return 1;

}
