// REDIRECTOR.cpp : implementation file
//

#include "stdafx.h"
#include "SuperCI.h"
#include "REDIRECTOR.h"

#include "comhdr.h"

//////////////////////////////////////////////////////////////////////////
CRedirectControl	g_RedirectCtrltor;
//////////////////////////////////////////////////////////////////////////
// CREDIRECTOR dialog

IMPLEMENT_DYNAMIC(CREDIRECTOR, CDialog)

CREDIRECTOR::CREDIRECTOR(CWnd* pParent /*=NULL*/)
	: CDialog(CREDIRECTOR::IDD, pParent)
{
	

}

CREDIRECTOR::~CREDIRECTOR()
{
}

void CREDIRECTOR::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, m_combox_RedirectInfo);
}


BEGIN_MESSAGE_MAP(CREDIRECTOR, CDialog)
	ON_BN_CLICKED(IDC_BUTTON_ADDREDIR, &CREDIRECTOR::OnBnClickedButtonAddredir)
	ON_BN_CLICKED(IDC_BUTTON_DELDIR, &CREDIRECTOR::OnBnClickedButtonDeldir)
	ON_BN_CLICKED(IDC_BUTTON_ExmportDirect, &CREDIRECTOR::OnBnClickedButtonExmportdirect)
	ON_CBN_SELCHANGE(IDC_COMBO1, &CREDIRECTOR::OnCbnSelchangeCombo1)
	ON_BN_CLICKED(IDC_BUTTON_ImportDirect, &CREDIRECTOR::OnBnClickedButtonImportdirect)
	ON_BN_CLICKED(IDC_BUTTON_CLean, &CREDIRECTOR::OnBnClickedButtonClean)
END_MESSAGE_MAP()


// CREDIRECTOR message handlers

int SplitCString(CString str,CString delim, CStringArray & urlarr)
{
	CString   strTemp;


	int   nIndex=0,   nLast=0;   

	while   (nIndex   !=   -1)   
	{   
		nIndex   =   str.Find(delim,   nLast);   
		if(nIndex   !=   -1)   
		{   
			strTemp   =   str.Mid(nLast,   nIndex   -   nLast);   
			nLast   =   nIndex   +   delim.GetLength();   
		}   
		else   
		{   
			strTemp   =   str.Mid(nLast,   str.GetLength()   -   nLast);

		}   



		TRACE0(strTemp);   //   你可以在这将它插入到数组中去. 
		// AfxMessageBox(strTemp);
		urlarr.Add(strTemp);
	} 
	return 1;
}

void CREDIRECTOR::OnBnClickedButtonAddredir()
{
	// TODO: Add your control notification handler code here
	CString	cs1,cs2,cs3;
	GetDlgItem(IDC_EDIT_FROMIP)->GetWindowText(cs1);
	GetDlgItem(IDC_EDIT_TOIP)->GetWindowText(cs2);
	if (cs2.GetLength()==0||cs1.GetLength()==0)
	{
		AfxMessageBox("Nothing");
		return;
	}
	if (g_RedirectCtrltor.IsAlreadyAdded(cs1.GetBuffer(0),cs2.GetBuffer(0)))
	{
		AfxMessageBox("Already Added");
		return ;
	}
	BOOL bret = g_RedirectCtrltor.AddRedirectIP(cs1.GetBuffer(0),cs2.GetBuffer(0));
	
	if (bret)
	{
		RefreshCombox();
	}

}
//////////////////////////////////////////////////////////////////////////
//删除某个
void CREDIRECTOR::OnBnClickedButtonDeldir()
{
	// TODO: Add your control notification handler code here
	
	//添加的时候关联了对应的项，
	CString	cs1,cs2,cs3;
	GetDlgItem(IDC_EDIT_FROMIP)->GetWindowText(cs1);
	GetDlgItem(IDC_EDIT_TOIP)->GetWindowText(cs2);

	g_RedirectCtrltor.DelRedirectIP(cs1.GetBuffer(0), cs2.GetBuffer(0));
	RefreshCombox();

}
//////////////////////////////////////////////////////////////////////////

BOOL CREDIRECTOR::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  Add extra initialization here
	GetDlgItem(IDC_EDIT_FROMIP)->SetWindowText("1.1.1.1");
	GetDlgItem(IDC_EDIT_TOIP)->SetWindowText("8.8.8.8");
	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}
//导出
void CREDIRECTOR::OnBnClickedButtonExmportdirect()
{
	// TODO: Add your control notification handler code here
	char szbuffer2[1024];
	CString PathName;
	ZeroMemory(szbuffer2, 1024);
	CString csStr;
	if (!OnlyXpAnd2003OsVersionCheck())
	{
		return ;
	}
	GetCurrentDirectoryA(1023, szbuffer2);
	CFileDialog FileDlgOpen(FALSE);
	if(IDOK == FileDlgOpen.DoModal())
	{
		PathName = FileDlgOpen.GetPathName();
		
	}
	else
	{
		return ;
	}



	FILE *fp=NULL;
	fopen_s(&fp, PathName.GetBuffer(0), "w");
	if (fp==NULL)
	{
		csStr.Format("Fail 2 open Exmport file %s (%s)", PathName,fnDisplayError(GetLastError()));
		AfxMessageBox(csStr);
		return ;
	}

	LRedirect *p	=	(LRedirect*)g_RedirectCtrltor.GetRedirectInfos();
	if (p==NULL)
	{
		return ;
	}
	
	LRedirect::iterator it1;
	SET_REDIRECT_INFO *pValue=NULL;
	CString csWriteBuffer="";

	for (it1 = p->begin(); it1!=p->end(); it1++)
	{
		CString cs1,cs2,cs3;
		pValue	=	*it1;
		cs1	=	inet_ntoa(*(in_addr*)&pValue->from);
		cs2	=	inet_ntoa(*(in_addr*)&pValue->to);
		cs3.Format("%s-%s\r\n", cs1, cs2);
		csWriteBuffer+=cs3;
	}
	if (csWriteBuffer.GetLength()==0)
	{
		AfxMessageBox("Nothing to Export");
		fclose(fp);
	}
	int iwriteBytes=fwrite(csWriteBuffer.GetBuffer(0), 1, csWriteBuffer.GetLength(), fp);
	if (iwriteBytes!=csWriteBuffer.GetLength())
	{
			AfxMessageBox("fail 2 Export");
	}
	fclose(fp);
	AfxMessageBox("Exported!");

}
//////////////////////////////////////////////////////////////////////////

void CREDIRECTOR::RefreshCombox()
{
	LRedirect *p	=	(LRedirect*)g_RedirectCtrltor.GetRedirectInfos();
	if (p==NULL)
	{
		return ;
	}
	LRedirect::iterator it1;
	SET_REDIRECT_INFO *pValue=NULL;
	int icount = m_combox_RedirectInfo.GetCount();
	CString csStr;

	for (int i = m_combox_RedirectInfo.GetCount()-1; i >= 0; i--)
	{
		m_combox_RedirectInfo.DeleteString( i );
	}

	for (it1 = p->begin(); it1!=p->end(); it1++)
	{
		CString cs1,cs2,cs3;
		pValue	=	*it1;
		cs1	=	inet_ntoa(*(in_addr*)&pValue->from);
		cs2	=	inet_ntoa(*(in_addr*)&pValue->to);
		cs3.Format(_T("[Redirect IP]::from %-25s to %25s"), cs1, cs2);
		int i= m_combox_RedirectInfo.AddString(cs3);
		m_combox_RedirectInfo.SetItemDataPtr(i, pValue);
	}
	if (m_combox_RedirectInfo.GetCount()>0)
	{
		m_combox_RedirectInfo.SetCurSel(m_combox_RedirectInfo.GetCount()-1);
	}
	else
	{
		m_combox_RedirectInfo.SetCurSel(0);
	}
	
	

}

void CREDIRECTOR::OnCbnSelchangeCombo1()
{
	int iSel	=	m_combox_RedirectInfo.GetCurSel();
	SET_REDIRECT_INFO	*pValue	=	(SET_REDIRECT_INFO	*)m_combox_RedirectInfo.GetItemDataPtr(iSel);
	if (pValue==NULL)
	{
		return ;
	}
	CString cs1,cs2;
	cs1	=	inet_ntoa(*(in_addr*)&pValue->from);
	cs2	=	inet_ntoa(*(in_addr*)&pValue->to);
	GetDlgItem(IDC_EDIT_FROMIP)->SetWindowText(cs1);
	GetDlgItem(IDC_EDIT_TOIP)->SetWindowText(cs2);
	// TODO: Add your control notification handler code here
}
//导入重定向数据
void CREDIRECTOR::OnBnClickedButtonImportdirect()
{
	// TODO: Add your control notification handler code here
	if (!OnlyXpAnd2003OsVersionCheck())
	{
		return ;
	}
	CString OpenFilter = "";
	CString PathName;
	CString csStr;
	CFileDialog FileDlgOpen(TRUE);
	if(IDOK == FileDlgOpen.DoModal())
	{
		PathName = FileDlgOpen.GetPathName();

	}
	else
	{
		return ;
	}


	FILE *fp=NULL;
	fopen_s(&fp, PathName.GetBuffer(0), "rb");
	
	if (fp==NULL)
	{
		csStr.Format("Fail 2 open Import file %s (%s)", PathName,fnDisplayError(GetLastError()));
		AfxMessageBox(csStr);
		return ;
	}

	//把文件的位置指针移到文件尾
	fseek(fp,0L,SEEK_END);
	//获取文件长度;
	DWORD dwlength=ftell(fp);
	char *pReadBuffer = new char[dwlength+1];
	ZeroMemory(pReadBuffer, dwlength+1);
	fseek(fp,0L,SEEK_SET);
	fread(pReadBuffer,1, dwlength, fp);
	CString csFileBuffer = pReadBuffer;
	delete pReadBuffer;
	fclose(fp);
	if (dwlength==0)
	{
		return ;
	}
	CStringArray	csRedirectInfo;
	SplitCString(csFileBuffer,"\r\n", csRedirectInfo);

	for (int k=0; k<csRedirectInfo.GetSize(); k++)
	{
		CStringArray	csRedirect;
		SplitCString(csRedirectInfo.GetAt(k),"-", csRedirect);
		if (csRedirect.GetSize()<2)
		{
			continue;
		}
		CString csFrom, csTo;

		csFrom	=	csRedirect.GetAt(0);

		csTo	=	csRedirect.GetAt(1);

		if (g_RedirectCtrltor.IsAlreadyAdded(csFrom.GetBuffer(0),csTo.GetBuffer(0)))
		{
			continue;
		}
		BOOL bret = g_RedirectCtrltor.AddRedirectIP(csFrom.GetBuffer(0),csTo.GetBuffer(0));
		if (!bret)
		{
			AfxMessageBox("fail 2 add");
			break;
		}

	}
	AfxMessageBox("Imported!");
	RefreshCombox();

}

void CREDIRECTOR::OnBnClickedButtonClean()
{
	g_RedirectCtrltor.Clean();
	m_combox_RedirectInfo.Clear();
	RefreshCombox();
	// TODO: Add your control notification handler code here
}

BOOL CREDIRECTOR::PreTranslateMessage(MSG* pMsg)
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
