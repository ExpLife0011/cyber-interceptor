#pragma once
#include "afxwin.h"


// CREDIRECTOR dialog

class CREDIRECTOR : public CDialog
{
	DECLARE_DYNAMIC(CREDIRECTOR)

public:
	CREDIRECTOR(CWnd* pParent = NULL);   // standard constructor
	virtual ~CREDIRECTOR();

// Dialog Data
	enum { IDD = IDD_DIALOG_REDIRECT };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	CComboBox m_combox_RedirectInfo;
	afx_msg void OnBnClickedButtonAddredir();
	afx_msg void OnBnClickedButtonDeldir();
	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedButtonExmportdirect();

	void RefreshCombox();

	afx_msg void OnCbnSelchangeCombo1();
	afx_msg void OnBnClickedButtonImportdirect();
	afx_msg void OnBnClickedButtonClean();
	virtual BOOL PreTranslateMessage(MSG* pMsg);
};
