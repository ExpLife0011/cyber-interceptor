// TDIFW.cpp : implementation file
//

#include "stdafx.h"
#include "comhdr.h"
#include "SuperCI.h"
#include "TDIFW.h"
#include "NetworkCentre.h"
//////////////////////////////////////////////////////////////////////////

CNetworkCentre	g_CNetworkCentre;
CTDIFW			*g_pThis=NULL;
//////////////////////////////////////////////////////////////////////////


DWORD	CTDIFW::NotifyArrival2(PVOID par)
{

	FIREWALL_ASKUSER *pFAS	=	(FIREWALL_ASKUSER*)par;
	CString csStr,csPath;
	BOOL	bret=TRUE;
	PMIB_TCPTABLE_OWNER_PID	pTcbTable=NULL;
	PMIB_UDPTABLE_OWNER_PID	pUdpTable=NULL;

	int	iNumber=0;
	DWORD iIndex=0;

	csPath	=	"";
	bret	=	g_CNetworkCentre.GetTcpInfo();
	if (bret)
	{
		pTcbTable	=	(PMIB_TCPTABLE_OWNER_PID )g_CNetworkCentre.GetTcpBuffer();
		for (iIndex=0; iIndex<pTcbTable->dwNumEntries; iIndex++)
		{
			if (pFAS->uPort==ntohs(pTcbTable->table[iIndex].dwLocalPort))
			{
				PCHAR path=NULL;
				bret = g_CNetworkCentre.GetProcessPathByPid(pTcbTable->table[iIndex].dwOwningPid, (PVOID*)&path);
				if (bret)
				{
					csPath=path;
					delete path;
				}
			}

		}
	}
	if (pTcbTable)
	{
		if (csPath.GetLength()==0)
		{
			return 1;	//说明外部连入了一个不存在的端口
		}
	}

	csStr.Format("外部IP:%s连入端口:%d [进程：%s]\n是否允许？", inet_ntoa(*(in_addr*)&pFAS->SrcIP), pFAS->uPort,csPath);
	int iret = ::MessageBoxA(NULL,csStr,"warning",MB_OKCANCEL);
	if (iret==IDCANCEL)
	{
		pFAS->PStatus	=	PortDeny;
	}
	else
	{
			pFAS->PStatus	=	PortAccept;
	}
	CString cs1;
	if (pFAS->PStatus==PortAccept)
	{
		cs1	=	"放行";
	}
	if (pFAS->PStatus==PortDeny)
	{
		cs1 = "拒绝";
	}
	csStr.Format("IP为:%s连入本机端口%d\t规则:[%s]\r\n", inet_ntoa(*(in_addr*)&pFAS->SrcIP), pFAS->uPort ,cs1);
	AddLog(csStr);
	return 1;
}
//////////////////////////////////////////////////////////////////////////

DWORD	NotifyArrival(PVOID par)
{
	return	g_pThis->NotifyArrival2(par);

}
//////////////////////////////////////////////////////////////////////////
// CTDIFW dialog

IMPLEMENT_DYNAMIC(CTDIFW, CDialog)

CTDIFW::CTDIFW(CWnd* pParent /*=NULL*/)
	: CDialog(CTDIFW::IDD, pParent)
{
	g_pThis	=	this;

}

CTDIFW::~CTDIFW()
{
}

void CTDIFW::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_NETWORK, m_listctl_Network);
	DDX_Control(pDX, IDC_CHECK_TDIEVENTCONNECT, m_chk_tdiconnect);
	DDX_Control(pDX, IDC_EDIT_FWLOG, m_edtLog);
	DDX_Control(pDX, IDC_EDIT_PORTRULE, m_edtPortRule);
}


BEGIN_MESSAGE_MAP(CTDIFW, CDialog)
	ON_WM_CREATE()
	ON_WM_SIZE()
	ON_NOTIFY(NM_RCLICK, IDC_LIST_NETWORK, &CTDIFW::OnNMRClickListNetwork)
	ON_COMMAND(ID_LIST_32771, &CTDIFW::OnConnectionStatsRefresh)
	ON_NOTIFY(LVN_COLUMNCLICK, IDC_LIST_NETWORK, &CTDIFW::OnLvnColumnclickListNetwork)
	ON_BN_CLICKED(IDC_CHECK_TDIEVENTCONNECT, &CTDIFW::OnBnClickedCheckTdieventconnect)
	ON_BN_CLICKED(IDC_BUTTON_ReFreshPortRul, &CTDIFW::OnBnClickedButtonRefreshportrul)
	ON_COMMAND(ID_LIST_LOCATEFILE, &CTDIFW::OnListLocatefile)
END_MESSAGE_MAP()

#define PROTOCOL	(0)
#define LOCAL		(1)
#define REMOTE		(2)
#define CONNECTSTATUS		(3)
#define PID			(4)
#define PATH		(5)
// CTDIFW message handlers
BOOL CTDIFW::OnInitDialog()
{

	CDialog::OnInitDialog();
	DWORD dwStyle = m_listctl_Network.GetExtendedStyle();  
	dwStyle |= LVS_EX_FULLROWSELECT;// 选中某行使整行高亮（只适用与report 风格的listctrl ） 
	dwStyle |= LVS_EX_GRIDLINES;// 网格线（只适用与report 风格的listctrl ） 
	m_listctl_Network.SetExtendedStyle(dwStyle); // 设置扩展风格 
	
	m_listctl_Network.InsertColumn(PROTOCOL, _T("Protocol"), LVCFMT_LEFT );
	m_listctl_Network.InsertColumn(LOCAL, _T("Local Addr"), LVCFMT_LEFT );
	m_listctl_Network.InsertColumn(REMOTE, _T("Remote Addr"), LVCFMT_LEFT );
	m_listctl_Network.InsertColumn(CONNECTSTATUS, _T("State"), LVCFMT_LEFT);
	m_listctl_Network.InsertColumn(PID, _T("Pid"), LVCFMT_LEFT );
	m_listctl_Network.InsertColumn(PATH, _T("Path"), LVCFMT_LEFT);
	SetListWidth();


	g_CNetworkCentre.SetUpPenddingAskUserEvent(NotifyArrival);
	OnConnectionStatsRefresh();
	return TRUE;

}
int CTDIFW::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CDialog::OnCreate(lpCreateStruct) == -1)
		return -1;

	return 0;
}

int CTDIFW::SetListWidth(void)
{

	CRect rect;
	GetClientRect(&rect);
	rect.top += 2;
	rect.left +=8;
	rect.right-=50;
	rect.bottom=rect.bottom/2-5;
	m_listctl_Network.MoveWindow(&rect);
	m_listctl_Network.GetClientRect(&rect);
	int nColInterval = rect.Width()/14;
	int proto1,local1,remote1,status1,pid1,path1;
	proto1	=	nColInterval;
	local1	=	nColInterval*3;
	remote1	=	local1;
	status1	=	nColInterval*3/2;
	pid1	=	nColInterval*2;
	path1	=	rect.Width()-proto1-local1-remote1-status1-pid1;
	

	m_listctl_Network.SetColumnWidth(PROTOCOL, proto1);
	m_listctl_Network.SetColumnWidth(LOCAL,		local1);
	m_listctl_Network.SetColumnWidth(REMOTE,	remote1);
	m_listctl_Network.SetColumnWidth(CONNECTSTATUS,status1);
	m_listctl_Network.SetColumnWidth(PID,	pid1);
	m_listctl_Network.SetColumnWidth(PATH,	path1);
	return 0;
}

void CTDIFW::OnSize(UINT nType, int cx, int cy)
{
	CDialog::OnSize(nType, cx, cy);
	static	bool	inited	=	false;
	if (inited)
	{
			SetListWidth();
			inited	=	true;
	}

	// TODO: Add your message handler code here
}
//////////////////////////////////////////////////////////////////////////
void CTDIFW::OnNMRClickListNetwork(NMHDR *pNMHDR, LRESULT *pResult)
{
	//LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<NMITEMACTIVATE>(pNMHDR);
	// TODO: Add your control notification handler code here
	CMenu menu ,* pSubMenu; //定义下面要用到的cmenu对象
	menu.LoadMenu(IDR_MENU1); //装载自定义的右键菜单

	//获取第一个弹出菜单，所以第一个菜单必须有子菜单
	pSubMenu = menu.GetSubMenu(0);
	CPoint oPoint; //定义一个用于确定光标位置的位置
	GetCursorPos( &oPoint); //获取当前光标的位置，以便使得菜单可以跟随光标
	int istat=m_listctl_Network.GetSelectionMark();//用istat存放当前选定的是第几项
	pSubMenu->TrackPopupMenu (TPM_LEFTALIGN, oPoint.x, oPoint.y, this);
	*pResult = 0;
}
//////////////////////////////////////////////////////////////////////////
CString	FormatConnectStats(int istats)
{
	char	strState[128];
	switch (istats)
	{
	case MIB_TCP_STATE_CLOSED:
		strcpy_s(strState, sizeof(strState), "CLOSED");
		break;
	case MIB_TCP_STATE_TIME_WAIT:
		strcpy_s(strState, sizeof(strState), "TIME_WAIT");
		break;
	case MIB_TCP_STATE_LAST_ACK:
		strcpy_s(strState, sizeof(strState), "LAST_ACK");
		break;
	case MIB_TCP_STATE_CLOSING:
		strcpy_s(strState, sizeof(strState), "CLOSING");
		break;
	case MIB_TCP_STATE_CLOSE_WAIT:
		strcpy_s(strState, sizeof(strState), "CLOSE_WAIT");
		break;
	case MIB_TCP_STATE_FIN_WAIT1:
		strcpy_s(strState, sizeof(strState), "FIN_WAIT1");
		break;
	case MIB_TCP_STATE_ESTAB:
		strcpy_s(strState, sizeof(strState), "ESTABISHED");
		break;
	case MIB_TCP_STATE_SYN_RCVD:
		strcpy_s(strState, sizeof(strState), "SYN_RCVD");
		break;
	case MIB_TCP_STATE_SYN_SENT:
		strcpy_s(strState, sizeof(strState), "SYN_SENT");
		break;
	case MIB_TCP_STATE_LISTEN:
		strcpy_s(strState, sizeof(strState), "LISTENING");
		break;
	case MIB_TCP_STATE_DELETE_TCB:
		strcpy_s(strState, sizeof(strState), "DELETE");
		break;
	default:
			sprintf_s(strState, sizeof(strState), "Unknow %d", istats);
		break;
	}
	return	CString(strState);
}
void CTDIFW::OnConnectionStatsRefresh()
{
	
	// TODO: Add your command handler code here
	BOOL	bret=TRUE;
	PMIB_TCPTABLE_OWNER_PID	pTcbTable=NULL;
	PMIB_UDPTABLE_OWNER_PID	pUdpTable=NULL;
	CString	csStr,csStr2;
	int	iNumber=0;
	DWORD iIndex=0;
	int itemIdx=0;
	do 
	{
		bret	=	g_CNetworkCentre.GetTcpInfo();
		if (!bret)
		{
			AfxMessageBox("can not get TCP connections");
			break;
		}
		pTcbTable	=	(PMIB_TCPTABLE_OWNER_PID )g_CNetworkCentre.GetTcpBuffer();
		iIndex	=	0;
		m_listctl_Network.DeleteAllItems();
		while (iIndex<pTcbTable->dwNumEntries)
		{
			if (pTcbTable->table[iIndex].dwState==0)
			{
				iIndex++;
				continue;
			}
			m_listctl_Network.InsertItem(itemIdx, "TCP");

		//	m_listctl_Network.SetItemText(itemIdx, PROTOCOL, "TCP");
			MIB_TCPROW_OWNER_PID 	PP	=	pTcbTable->table[iIndex];

			csStr.Format("%-10s  :  %d", inet_ntoa(*(in_addr*)&pTcbTable->table[iIndex].dwLocalAddr), ntohs(pTcbTable->table[iIndex].dwLocalPort));
			m_listctl_Network.SetItemText(itemIdx, LOCAL, csStr);

			csStr.Format("%-10s  :  %d", inet_ntoa(*(in_addr*)&pTcbTable->table[iIndex].dwRemoteAddr), ntohs(pTcbTable->table[iIndex].dwRemotePort));
			m_listctl_Network.SetItemText(itemIdx, REMOTE, csStr);

			m_listctl_Network.SetItemText(itemIdx, CONNECTSTATUS, FormatConnectStats(pTcbTable->table[iIndex].dwState));

			csStr.Format("%d  (0x%x)",pTcbTable->table[iIndex].dwOwningPid, pTcbTable->table[iIndex].dwOwningPid);
			m_listctl_Network.SetItemText(itemIdx, PID, csStr);

			char *pPath=NULL;
			if (g_CNetworkCentre.GetProcessPathByPid(pTcbTable->table[iIndex].dwOwningPid, (PVOID*)&pPath))
			{
				m_listctl_Network.SetItemText(itemIdx, PATH, pPath);
				delete	pPath;

			}


			itemIdx++;
			iIndex++;
		}
		iIndex	=	0;
	
		bret	=	g_CNetworkCentre.GetUdpInfo();
		if (!bret)
		{
			AfxMessageBox("cant not get Udp Connections");
			break;
		}
		pUdpTable	=	(PMIB_UDPTABLE_OWNER_PID )g_CNetworkCentre.GetUdpBuffer();
// 		csStr2.Format("pUdpTable Number:%d,pTcbTable Number:%d\n", pUdpTable->dwNumEntries, pTcbTable->dwNumEntries);
// 		AfxMessageBox(csStr2);
		while (iIndex<pUdpTable->dwNumEntries)
		{
			m_listctl_Network.InsertItem(itemIdx, "UDP");
// 			m_listctl_Network.SetItemText(itemIdx, PROTOCOL, "UDP");

			csStr.Format("%-10s  :   %d", inet_ntoa(*(in_addr*)&pUdpTable->table[iIndex].dwLocalAddr), ntohs(pUdpTable->table[iIndex].dwLocalPort));
			m_listctl_Network.SetItemText(itemIdx, LOCAL, csStr);

			m_listctl_Network.SetItemText(itemIdx, REMOTE, "* : *");

			csStr.Format("%d  (0x%x)",pUdpTable->table[iIndex].dwOwningPid, pUdpTable->table[iIndex].dwOwningPid);
			m_listctl_Network.SetItemText(itemIdx, PID, csStr);
			char *pPath=NULL;
			if (g_CNetworkCentre.GetProcessPathByPid(pUdpTable->table[iIndex].dwOwningPid,(PVOID*)&pPath))
			{
				m_listctl_Network.SetItemText(itemIdx, PATH, pPath);
				delete	pPath;

			}

			itemIdx++;
			iIndex++;
		}
		iIndex	=	0;
		csStr2.Format("Statistic： TCP :%d    UDP :%d", pTcbTable->dwNumEntries, pUdpTable->dwNumEntries);
		GetDlgItem(IDC_STATIC_NETWORK)->SetWindowText(csStr2);

	} while (0);
}
int CALLBACK CompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{

	return 1;
}
void CTDIFW::OnLvnColumnclickListNetwork(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);

	// TODO: Add your control notification handler code here
	*pResult = 0;
}

void CTDIFW::OnBnClickedCheckTdieventconnect()
{
	//仅支持XP，2K3
	if (!OnlyXpAnd2003OsVersionCheck())
	{
		m_chk_tdiconnect.SetCheck(FALSE);
		return ;
	}
	// TODO: Add your control notification handler code here
	if (!g_CNetworkCentre.SetUpFW(m_chk_tdiconnect.GetCheck()))
	{
		AfxMessageBox("Setup Tdi_event_connect Fail!");
	}

}

//////////////////////////////////////////////////////////////////////////

int CTDIFW::AddLog(CString strLog)
{
	CString   strDate; 
	CTime   ttime   =   CTime::GetCurrentTime(); 
	strDate.Format( "[%02d:%02d:%02d] ",ttime.GetHour(),ttime.GetMinute(),ttime.GetSecond()); 

	CString cs;
	m_edtLog.GetWindowText(cs);
	cs=	cs+ strDate;
	cs=	cs+ strLog;
	m_edtLog.SetWindowText(cs);
	return 0;
}

void CTDIFW::OnBnClickedButtonRefreshportrul()
{

	FIREWALL_ASKUSER	*pBuffer=NULL;
	int		iNumber=0;
	BOOL	bRet	=g_CNetworkCentre.GetPortRule((PVOID*)&pBuffer, iNumber);

	if (!bRet)
	{
		AfxMessageBox("retrive tcp port rules fail ");
		return;
	}
	CString csPortRule;
	for (int i=0; i< iNumber; i++)
	{
		CString csStatus;
		if (pBuffer[i].PStatus==PortAccept)
		{
			csStatus="放行";
		}
		else if (pBuffer[i].PStatus==PortDeny)
		{
			csStatus="拒绝";
		}
		else
		{
			csStatus="未知";
		}
		CString cs1;
		cs1.Format("端口：%d\t规则：%s\r\n", pBuffer[i].uPort, csStatus);
		csPortRule	=	csPortRule	+	cs1;
	}
	delete	pBuffer; pBuffer=NULL;
	m_edtPortRule.SetWindowText(csPortRule);
	// TODO: Add your control notification handler code here
}
//////////////////////////////////////////////////////////////////////////

void CTDIFW::OnListLocatefile()
{
	// TODO: Add your command handler code here
	POSITION pos = m_listctl_Network.GetFirstSelectedItemPosition();
	if (pos == NULL) 
		TRACE0("No items were selected!\n");
	else 
	{ 
		while (pos) 
		{ 
			int nItem = m_listctl_Network.GetNextSelectedItem(pos);
			CString csPath;
			CString csPID;
			csPath	=	m_listctl_Network.GetItemText(nItem,PATH);
			csPID	=	m_listctl_Network.GetItemText(nItem,PID);
			if (csPID.GetLength()==0||csPID=="0"||csPID=="4")
			{
				continue;
			}
			if (csPath.GetLength()!=0)
			{
				CString csStr;
				csStr.Format("explorer /n,/select,%s", csPath);
				WinExec(csStr, 1);
			}
			// you could do your own processing on nItem here
		} 
	} 
}

BOOL CTDIFW::PreTranslateMessage(MSG* pMsg)
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
