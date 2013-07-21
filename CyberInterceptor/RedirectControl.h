#pragma once


typedef list<PSET_REDIRECT_INFO> LRedirect;

class CRedirectControl
{
public:
	CRedirectControl(void);
	~CRedirectControl(void);

	BOOL AddRedirectIP(TCHAR* fromIP, TCHAR *toIP );

	BOOL DelRedirectIP(TCHAR *fromIP, TCHAR *toIP );

	bool IsAlreadyAdded(TCHAR *fromIP, TCHAR *toIP );
	BOOL FixGatewayMac();

	bool RefreshLocalIP();

	bool IsLocalIP(TCHAR *IP);

	PVOID	GetRedirectInfos()
	{
		return &m_RedirectInfoList;
	}
	//////////////////////////////////////////////////////////////////////////
	LRedirect	m_RedirectInfoList;
	vector<PIPINFO>	m_LocalIps;


	int Clean(void);
};
