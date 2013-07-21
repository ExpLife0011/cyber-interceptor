// UdpTraffic.cpp : implementation file
//

#include "stdafx.h"
#include "SuperCI.h"
#include "UdpTraffic.h"
#include "comhdr.h"
#include "UdpTraffControl.h"
//////////////////////////////////////////////////////////////////////////
CUdpTrafficControl	g_UdpTrafficControl;
//////////////////////////////////////////////////////////////////////////
// CUdpTraffic dialog

IMPLEMENT_DYNAMIC(CUdpTraffic, CDialog)

CUdpTraffic::CUdpTraffic(CWnd* pParent /*=NULL*/)
	: CDialog(CUdpTraffic::IDD, pParent)
{

}

CUdpTraffic::~CUdpTraffic()
{
}

void CUdpTraffic::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_RECV, m_edtRecv);
	DDX_Control(pDX, IDC_EDIT_SEND, m_edtSend);
	DDX_Control(pDX, IDC_EDIT_DESTPORT, m_edtDstPort);
	DDX_Control(pDX, IDC_EDIT_DESTIP, m_edtDstIP);
	DDX_Control(pDX, IDC_STATIC_SENDSIZE, m_statSendSize);
}


BEGIN_MESSAGE_MAP(CUdpTraffic, CDialog)
	ON_BN_CLICKED(IDC_BUTTON_SENDUDP, &CUdpTraffic::OnBnClickedButtonSendudp)
	ON_WM_CREATE()
	ON_EN_CHANGE(IDC_EDIT_SEND, &CUdpTraffic::OnEnChangeEditSend)
END_MESSAGE_MAP()


// CUdpTraffic message handlers

BOOL CUdpTraffic::OnInitDialog()
{

	CDialog::OnInitDialog();

	m_edtRecv.SetWindowText("not implemented yet");
	m_edtSend.SetWindowText(_T("mmmmmm,test me"));
	CString csStr;
	m_edtSend.GetWindowText(csStr);
	CString csStr2;
	csStr2.Format("Send:(%d)   [Size shoule be less than MTU]", csStr.GetLength());
	m_statSendSize.SetWindowText(csStr2);

	return TRUE;
}
void CUdpTraffic::OnBnClickedButtonSendudp()
{
	//仅支持XP，2K3
	if (!OnlyXpAnd2003OsVersionCheck())
	{
		return ;
	}

	CString csSendBuffer;
	m_edtSend.GetWindowText(csSendBuffer);
	USHORT	dstport	;
	ULONG	dstIP;
	CString cs1,cs2;

	m_edtDstIP.GetWindowText(cs1);
	m_edtDstPort.GetWindowText(cs2);
	dstIP	=	inet_addr(cs1.GetBuffer(0));
	dstport	=	atoi((char *)cs2.GetBuffer(0));
	GetDlgItem(IDC_BUTTON_SENDUDP)->EnableWindow(FALSE);
	bool bret =g_UdpTrafficControl.SendUdpPacket(csSendBuffer.GetBuffer(0), csSendBuffer.GetLength(), dstIP, dstport);
	Sleep(1000);
	GetDlgItem(IDC_BUTTON_SENDUDP)->EnableWindow(TRUE);
	if (!bret)
	{
		AfxMessageBox("fail to send");
	}

	// TODO: Add your control notification handler code here
}

int CUdpTraffic::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CDialog::OnCreate(lpCreateStruct) == -1)
		return -1;

	// TODO:  Add your specialized creation code here

	return 0;
}

void CUdpTraffic::OnEnChangeEditSend()
{

	CString csStr;
	m_edtSend.GetWindowText(csStr);
	CString csStr2;
	csStr2.Format("Send:(%d)   [Size shoule be less than MTU]", csStr.GetLength());
	m_statSendSize.SetWindowText(csStr2);

	// TODO:  If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO:  Add your control notification handler code here
}

BOOL CUdpTraffic::PreTranslateMessage(MSG* pMsg)
{
	// TODO: Add your specialized code here and/or call the base class
	if(pMsg-> message   ==   WM_KEYDOWN) 
	{ 
		switch(pMsg-> wParam) 
		{ 
		case   VK_RETURN://屏蔽回车 
			return   TRUE; 
		case   VK_ESCAPE://屏蔽Esc 
			{
				ExitByESC();
				return   TRUE; 
			}

		} 
	} 
	return CDialog::PreTranslateMessage(pMsg);
}
