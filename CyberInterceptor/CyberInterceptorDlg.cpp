
// SuperCIDlg.cpp : implementation file
//

#include "stdafx.h"
#include "SuperCI.h"
#include "SuperCIDlg.h"
#include "comhdr.h"
#include "Resource.h"


#include "REDIRECTOR.h"
#include "PatchWireShark.h"
#include "UdpTraffic.h"
#include "TDIFW.h"

#include "DriverLoader.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////////



HANDLE	g_CyberHandleASyn;
CDriverLoader	g_drvLoader;

CSuperCIDlg	*g_this=NULL;
//////////////////////////////////////////////////////////////////////////
CString fnDisplayError( DWORD dwErrorMsgId );
bool	UninitAPP()
{

	g_this->closeAllWindow();
	for ( int i=0; i<TAB_MAX; i++)
	{
		if (g_this->m_TabePages[i])
		{
			delete g_this->m_TabePages[i];
		}
		
	}


	ReleasePenddingCheckPortIrp();	//不释放这些pendding的话，不能卸载驱动
	if (g_CyberHandleASyn)
	{
		CloseHandle(g_CyberHandleASyn);g_CyberHandleASyn=NULL;
	}
	
	g_drvLoader.MyZwUnloadDriver(NULL, NULL);
	BOOL	bRet	=	TRUE;

	return true;
}
//////////////////////////////////////////////////////////////////////////

bool	InitAPP()
{

	if (!Only_Xp_2003_win7_OsVersionCheck())
	{
		return false;
	}

	int iret = MessageBoxA(NULL,"program's about to load driver, continue?","warning",MB_OKCANCEL);
	if (iret==IDCANCEL)
	{
		return true;
	}


	bool bret = g_drvLoader.MyZwLoadDriver("CyberInter", "CyberInter.sys");
	if (!bret)
	{
		return false;
	}


	g_CyberHandleASyn = CreateFileA( CYBERSYS_WIN32_DEVICE_NAME_A,  
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING|FILE_FLAG_OVERLAPPED,
		NULL);

	if ( g_CyberHandleASyn == INVALID_HANDLE_VALUE ) 
	{

		CString cs;
		cs.Format("CreateFileA  DeviceName:%s  fail,error:(%d),%s",CYBERSYS_WIN32_DEVICE_NAME_A, GetLastError(), fnDisplayError(GetLastError()));
		AfxMessageBox(cs);
		return false;
	}

	return 1;


}
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	BOOL OnInitDialog();
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

BOOL CAboutDlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	SendMessage(WM_SETICON, (WPARAM)FALSE, (LPARAM)LoadIcon(GetModuleHandle(NULL), (LPCTSTR)IDI_ICON1));
	return TRUE;

}
void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CSuperCIDlg dialog




CSuperCIDlg::CSuperCIDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CSuperCIDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDI_ICON1);

	ZeroMemory(m_TabePages, sizeof(m_TabePages));
	g_this	=	this;

}

void CSuperCIDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TAB_MAIN, m_tabMain);
}

BEGIN_MESSAGE_MAP(CSuperCIDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_NOTIFY(TCN_SELCHANGING, IDC_TAB_MAIN, &CSuperCIDlg::OnTcnSelchangingTabMain)
	ON_NOTIFY(TCN_SELCHANGE, IDC_TAB_MAIN, &CSuperCIDlg::OnTcnSelchangeTabMain)
	ON_WM_CLOSE()
	ON_WM_DESTROY()
END_MESSAGE_MAP()


// CSuperCIDlg message handlers

BOOL CSuperCIDlg::OnInitDialog()
{

	HANDLE	hMute	=	CreateEvent(NULL, NULL,NULL,"kindof-43dd88bc-a897-4ed3-988d-91dcc2edb0f4");
	if (hMute)
	{
		if (ERROR_ALREADY_EXISTS==GetLastError())
		{
			AfxMessageBox("There is another instance already exist. the current Program is exiting !");
			ExitProcess(0);
		}

	}


	CDialog::OnInitDialog();

	if (!InitAPP())
	{
		AfxMessageBox(_T("InitAPP fail"));
		UninitAPP();
		ExitProcess(0);
		return FALSE;
	}

	g_RedirectCtrltor.FixGatewayMac();
	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	//ShowWindow(SW_MINIMIZE);

	SendMessage(WM_SETICON, (WPARAM)FALSE, (LPARAM)LoadIcon(GetModuleHandle(NULL), (LPCTSTR)IDI_ICON2));
	CRect rc;
	GetClientRect(rc);
	rc.top += 2;
	rc.left -=2;
	rc.right+=2;
	m_tabMain.MoveWindow(&rc);
	
	m_tabMain.GetClientRect(rc);
	rc.top += 25;
// 	rc.bottom -= 8;
// 	rc.left += 8;
// 	rc.right -= 8;
	
	m_tabMain.InsertItem(TAB_TDIFW,		_T("Network Firewall"));
	m_tabMain.InsertItem(TAB_REDIRECT,	_T("IP Redirector"));
	m_tabMain.InsertItem(TAB_UDPTRAFFIC, _T("Miniport UDP Traffic"));
	m_tabMain.InsertItem(TAB_PATCHWS,	_T("Enhance Sniffer"));

	m_tabMain.SetMinTabWidth(50);
	m_TabePages[TAB_TDIFW]		=	new CTDIFW ; 
	m_TabePages[TAB_REDIRECT]	=	new CREDIRECTOR;
	m_TabePages[TAB_UDPTRAFFIC]	=	new CUdpTraffic;
	m_TabePages[TAB_PATCHWS]	=	new CPatchWireShark;	


	m_TabePages[TAB_TDIFW]->Create(IDD_DIALOG_TDIFW, &m_tabMain);
	m_TabePages[TAB_REDIRECT]->Create(IDD_DIALOG_REDIRECT, &m_tabMain);
	m_TabePages[TAB_UDPTRAFFIC]->Create(IDD_DIALOG_UDPTRAFFIC, &m_tabMain);
	m_TabePages[TAB_PATCHWS]->Create(IDD_DIALOG_PATCHWS, &m_tabMain);

	
	m_TabePages[TAB_REDIRECT]->MoveWindow(&rc);
	m_TabePages[TAB_UDPTRAFFIC]->MoveWindow(&rc);
	m_TabePages[TAB_PATCHWS]->MoveWindow(&rc);
//	rc.bottom	+=50;
	m_TabePages[TAB_TDIFW]->MoveWindow(&rc);
	ShowOrHideAllTabWindow(SW_HIDE);
	m_CurSelTab = TAB_TDIFW;
	m_tabMain.SetCurSel(m_CurSelTab);
	m_TabePages[m_CurSelTab]->ShowWindow(SW_SHOW);
	
	((CUdpTraffic*)m_TabePages[TAB_UDPTRAFFIC])->m_edtDstPort.SetWindowText(_T("12345"));
	((CUdpTraffic*)m_TabePages[TAB_UDPTRAFFIC])->m_edtDstIP.SetWindowText(_T("8.8.8.8"));


		// TODO: Add extra initialization here

	SetWindowPos(&CWnd::wndNoTopMost, 0, 0, 0, 0, SWP_NOMOVE|SWP_NOSIZE);
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CSuperCIDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CSuperCIDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CSuperCIDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


int CSuperCIDlg::ShowOrHideAllTabWindow(int Show)
{
	for ( int i=0; i<TAB_MAX; i++)
	{
		m_TabePages[i]->ShowWindow(Show);
	}

	return 0;
}

void CSuperCIDlg::OnTcnSelchangingTabMain(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: Add your control notification handler code here

	*pResult = 0;
}

void CSuperCIDlg::OnTcnSelchangeTabMain(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: Add your control notification handler code here
	m_CurSelTab = m_tabMain.GetCurSel();
	if (m_CurSelTab<0 && m_CurSelTab>=TAB_MAX)
	{
		return ;
	}
	ShowOrHideAllTabWindow(SW_HIDE);
	m_TabePages[m_CurSelTab]->ShowWindow(SW_SHOW);
	*pResult = 0;
}
//////////////////////////////////////////////////////////////////////////

void CSuperCIDlg::closeAllWindow()
{
	for ( int i=0; i<TAB_MAX; i++)
	{
		if (m_TabePages[i])
		{
			m_TabePages[i]->DestroyWindow();
		}
		
	}
	

}
void CSuperCIDlg::OnClose()
{
	// TODO: Add your message handler code here and/or call default


	CDialog::OnClose();

	//UninitAPP();

}

#include <lmerr.h>
#include <tchar.h>

#define ERRMSGBUFFERSIZE 256

CString fnDisplayError( DWORD dwErrorMsgId )
{
	DWORD ret;        // Temp space to hold a return value.
	HINSTANCE hInst;  // Instance handle for DLL.
	HLOCAL pBuffer;   // Buffer to hold the textual error description.

	if ( HRESULT_FACILITY(dwErrorMsgId) == FACILITY_MSMQ )
	{ // MSMQ errors only (see winerror.h for facility info).
		// Load the MSMQ library containing the error message strings.
		hInst = LoadLibrary( TEXT("MQUTIL.DLL") );
		if(hInst != 0)
		{ // hInst not NULL if the library was successfully loaded.
			// Get the text string for a message definition
			ret = FormatMessage( 
				FORMAT_MESSAGE_ALLOCATE_BUFFER | // Function will handle memory allocation.
				FORMAT_MESSAGE_FROM_HMODULE | // Using a module's message table.
				FORMAT_MESSAGE_IGNORE_INSERTS, 
				hInst, // Handle to the DLL.
				dwErrorMsgId, // Message identifier.
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language.
				(LPTSTR)&pBuffer, // Buffer that will hold the text string.
				ERRMSGBUFFERSIZE, // Allocate at least this many chars for pBuffer.
				NULL // No insert values.
				);
		} // hInst not NULL if the library was successfully loaded.

	} // MSMQ errors only.

	else if ( dwErrorMsgId >= NERR_BASE && dwErrorMsgId <= MAX_NERR )
	{ // Could be a network error.
		// Load the library containing network messages.
		hInst = LoadLibrary( TEXT("NETMSG.DLL") );
		if(hInst != 0)
		{ // Not NULL if successfully loaded.
			// Get a text string for the message definition.
			ret = FormatMessage(  
				FORMAT_MESSAGE_ALLOCATE_BUFFER | // The function will allocate memory for the message.
				FORMAT_MESSAGE_FROM_HMODULE | // Message definition is in a module.
				FORMAT_MESSAGE_IGNORE_INSERTS,  // No inserts used.
				hInst, // Handle to the module containing the definition.
				dwErrorMsgId, // Message identifier.
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language.
				(LPTSTR)&pBuffer, // Buffer to hold the text string.
				ERRMSGBUFFERSIZE, // Smallest size that will be allocated for pBuffer.
				NULL // No inserts.
				);
		} // Not NULL if successfully loaded.

	} // Could be a network error.
	else
	{ // Unknown message source.
		// Get the message string from the system.
		ret = FormatMessage(  
			FORMAT_MESSAGE_ALLOCATE_BUFFER | // The function will allocate space for pBuffer.
			FORMAT_MESSAGE_FROM_SYSTEM | // System wide message.
			FORMAT_MESSAGE_IGNORE_INSERTS, // No inserts.
			NULL, // Message is not in a module.
			dwErrorMsgId, // Message identifier.
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language.
			(LPTSTR)&pBuffer, // Buffer to hold the text string.
			ERRMSGBUFFERSIZE, // The function will allocate at least this much for pBuffer.
			NULL // No inserts.
			);
	}


	// Display the string.

	if( ret )
	{
		_tprintf( _TEXT("\tERRORMESSAGE: %s\n"), (LPTSTR)pBuffer );
	}
	else
	{
		_tprintf( _TEXT("\tERRORNUMBER: %d\n"), dwErrorMsgId );
	}

	CString	csstr=	(TCHAR*)pBuffer;
	// Free the buffer.
	LocalFree( pBuffer );
	return csstr;

}
void CSuperCIDlg::OnDestroy()
{
	
	CDialog::OnDestroy();
	UninitAPP();
	// TODO: Add your message handler code here
}
void	ExitByESC()
{
	int iret=MessageBoxA(NULL,"Program's about to exit, continue?","warning",MB_OKCANCEL);
	if (iret==IDCANCEL)
	{
		return;
	}
	UninitAPP();
	ExitProcess(1);

}
BOOL CSuperCIDlg::PreTranslateMessage(MSG* pMsg)
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
