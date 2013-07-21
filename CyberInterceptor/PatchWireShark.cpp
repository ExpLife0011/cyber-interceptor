// PatchWireShark.cpp : implementation file
//

#include "stdafx.h"
#include "SuperCI.h"
#include "PatchWireShark.h"
#include "comhdr.h"
#include <WinIoCtl.h>
//////////////////////////////////////////////////////////////////////////

CPatchWS	g_CPatchWS;
//////////////////////////////////////////////////////////////////////////
// CPatchWireShark dialog

IMPLEMENT_DYNAMIC(CPatchWireShark, CDialog)

CPatchWireShark::CPatchWireShark(CWnd* pParent /*=NULL*/)
	: CDialog(CPatchWireShark::IDD, pParent)
{

}

CPatchWireShark::~CPatchWireShark()
{
}

void CPatchWireShark::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);


	DDX_Control(pDX, IDC_COMBO_PRONAME, m_comboxProName);
}


BEGIN_MESSAGE_MAP(CPatchWireShark, CDialog)
	ON_BN_CLICKED(IDC_BUTTON1, &CPatchWireShark::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON_UNPATCH, &CPatchWireShark::OnBnClickedButtonUnpatch)
	ON_BN_CLICKED(IDC_BUTTON2, &CPatchWireShark::OnBnClickedButton2)
END_MESSAGE_MAP()


// CPatchWireShark message handlers

void CPatchWireShark::OnBnClickedButton1()
{
	
	DWORD	dwRet=0;
	bool	bret=FALSE;

	CString	csProName;
	m_comboxProName.GetLBText(m_comboxProName.GetCurSel(), csProName);
	if (csProName.CompareNoCase("tcpip")==0)
	{
		int iret = ::MessageBoxA(NULL,"Patching tcpip is not a good idea, r u sure?","warning",MB_OKCANCEL);
		if (iret==IDCANCEL)
		{
			return ;
		}

	}
	CString csProName2	=	csProName;
	if (csProName.Find('(')!=-1)
	{	
		
		csProName2	=	csProName.Left(csProName.Find('('));
	}
	
	bret = g_CPatchWS.doPatch(csProName2.GetBuffer(0));
	if (!bret)
	{
		AddLog("patch wireshark fail\r\n");
		return ;
	}
	AddLog("patch wireshark successfully\r\n");

	// TODO: Add your control notification handler code here
}
//////////////////////////////////////////////////////////////////////////

BOOL CPatchWireShark::OnInitDialog()
{
	CDialog::OnInitDialog();

	Protocol_Lists	pProList[64];

	DWORD	dwRet=0;
	DWORD	dwRetBuffer=0;
	DWORD	dwSel=0;
	bool bret = (bool)DeviceIoControl(g_CyberHandleASyn, IOCTL_GETPROTOCOLLIST , pProList, sizeof(pProList), pProList, sizeof(pProList), &dwRet, NULL);
	if (bret)
	{
		DWORD dwNumber	=	dwRet/(sizeof(Protocol_Lists));
		for (int i=0; i<dwNumber; i++)
		{
			if (stricmp(pProList[i].szName, "packetdriver")==0)
			{
				CString cs=pProList[i].szName;
				cs =cs+"(for winpcap)";
				dwSel = m_comboxProName.AddString(cs.GetBuffer(0));
			}
			else
			m_comboxProName.AddString(pProList[i].szName);
		}

		
		
	}
	
	m_comboxProName.SetCurSel(dwSel);
	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

void CPatchWireShark::OnBnClickedButtonUnpatch()
{
	DWORD	dwRet=0;
	DWORD	dwRetBuffer=0;
	CString	csProName;
	
	m_comboxProName.GetLBText(m_comboxProName.GetCurSel(), csProName);
	CString csProName2	=	csProName;
	bool bret = g_CPatchWS.UndoPatch(csProName2.GetBuffer(0));
	if (!bret)
	{
		AddLog("fail on restoring patchws\r\n");
		return ;
	}
		AddLog("do un-patchws successfully \r\n");
	// TODO: Add your control notification handler code here
}
//////////////////////////////////////////////////////////////////////////

int CPatchWireShark::AddLog(CString strLog)
{
	CString cs;
	GetDlgItem(IDC_EDIT_PATCHLOG)->GetWindowText(cs);
	cs=	cs+ strLog;
	GetDlgItem(IDC_EDIT_PATCHLOG)->SetWindowText(cs);
	return 0;
}

void CPatchWireShark::OnBnClickedButton2()
{
	static BOOL	bret=FALSE;

	if (!OnlyXpAnd2003OsVersionCheck())
	{
		AfxMessageBox("so far,i make this available only for xp and 2003");
		return ;
	}

	if (bret)
	{
		//already patch it ,restore it 
		bret	=	g_CPatchWS.PatchRestoreDontLoopback();
		if (bret)
		{
			//do it successfully
			bret	=	FALSE;//keep the state un patched
			AddLog("Restore escaping Successfully\r\n");
		}
		else
		{
			bret	=	TRUE;//keep the state still patched
				AddLog("Error occured when Restore DontLoopback\r\n");
		}

	}
	else
	{
		bret	=	g_CPatchWS.PatchDontLoopback();
		if (bret)
		{
			AddLog("\r\nGot it .now you can not sniffer the packet sent from this machine any more,if you want to restore ,just click the button again!\r\n\r\n");
		}
		else
		{
			AddLog("something went wrong\r\n");
			return ;
		}
	}
	
	return ;

	// TODO: Add your control notification handler code here
}

BOOL CPatchWireShark::PreTranslateMessage(MSG* pMsg)
{
	// TODO: Add your specialized code here and/or call the base class
	if(pMsg-> message   ==   WM_KEYDOWN) 
	{ 
		switch(pMsg-> wParam) 
		{ 
		case   VK_RETURN://ÆÁ±Î»Ø³µ 
			return   TRUE; 
		case   VK_ESCAPE://ÆÁ±ÎEsc 
			{
				ExitByESC();
				return   TRUE; 
			}

		} 
	} 
	return CDialog::PreTranslateMessage(pMsg);
}
