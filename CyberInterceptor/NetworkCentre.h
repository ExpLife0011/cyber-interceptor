#pragma once

typedef DWORD	(*PNotifyArrival)(PVOID par);

void ReleasePenddingCheckPortIrp();


class CNetworkCentre
{
	PVOID	m_pTcpBuffer;
	PVOID	m_pUdpBuffer;
	int		m_iTcpCount;
	int		m_iUdpCount;
public:
	CNetworkCentre(void);
	~CNetworkCentre(void);
	BOOL GetTcpInfo(void);
	BOOL GetUdpInfo(void);


	PVOID GetTcpBuffer(void)
	{
		return m_pTcpBuffer;
	}
	int GetTcpCount(void)
	{
		return m_iTcpCount;
	}


	PVOID GetUdpBuffer(void)
	{
		return m_pUdpBuffer;
	}
	int GetUdpCount(void)
	{
		return m_iUdpCount;
	}
	void	ReleaseTcpInfo()
	{
		if (m_pTcpBuffer)
		{
			delete	m_pTcpBuffer;m_pTcpBuffer=NULL;
		}

	}
	void	ReleaseUdpInfo()
	{
		if (m_pUdpBuffer)
		{
			delete	m_pUdpBuffer;m_pUdpBuffer=NULL;
		}
	}

	BOOL GetProcessPathByPid(int pid, PVOID	*pPath);

	BOOL	GetPortRule(void **PortStatusHeader, int &iNumber);
	BOOL	SetUpFW(BOOL bSet);
	
	BOOL	SetUpPenddingAskUserEvent(PNotifyArrival pHandler=NULL);

	BOOL	AskUserForPermission();
	
	PNotifyArrival	m_EventProcessHanlder;
};
