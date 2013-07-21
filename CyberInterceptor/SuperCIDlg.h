
// SuperCIDlg.h : header file
//

#pragma once
#include "afxcmn.h"


// CSuperCIDlg dialog
class CSuperCIDlg : public CDialog
{
// Construction
public:
	CSuperCIDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_SUPERCI_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CTabCtrl m_tabMain;
	CDialog * m_TabePages[10];
	int		m_CurSelTab;

	int ShowOrHideAllTabWindow(int Show);
	afx_msg void OnTcnSelchangingTabMain(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnTcnSelchangeTabMain(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnClose();

	void closeAllWindow();

	afx_msg void OnDestroy();
	virtual BOOL PreTranslateMessage(MSG* pMsg);
};
