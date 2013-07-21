#pragma once
#include "afxcmn.h"
#include "afxwin.h"


// CTDIFW dialog

class CTDIFW : public CDialog
{
	DECLARE_DYNAMIC(CTDIFW)

public:
	CTDIFW(CWnd* pParent = NULL);   // standard constructor
	virtual ~CTDIFW();
	

// Dialog Data
	enum { IDD = IDD_DIALOG_TDIFW };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual BOOL OnInitDialog();
	DECLARE_MESSAGE_MAP()
public:
	DWORD	NotifyArrival2(PVOID par);
	int AddLog(CString strLog);
	BOOL	SetUpFW(BOOL bSet);
	CListCtrl m_listctl_Network;
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	int SetListWidth(void);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnNMRClickListNetwork(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnConnectionStatsRefresh();
	afx_msg void OnLvnColumnclickListNetwork(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedCheckTdieventconnect();
	CButton m_chk_tdiconnect;
	CEdit m_edtLog;
	afx_msg void OnBnClickedButtonRefreshportrul();
	CEdit m_edtPortRule;
	afx_msg void OnListLocatefile();
	virtual BOOL PreTranslateMessage(MSG* pMsg);
};
