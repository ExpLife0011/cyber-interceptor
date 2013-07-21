#pragma once
#include "afxwin.h"


// CPatchWireShark dialog

class CPatchWireShark : public CDialog
{
	DECLARE_DYNAMIC(CPatchWireShark)

public:
	CPatchWireShark(CWnd* pParent = NULL);   // standard constructor
	virtual ~CPatchWireShark();

// Dialog Data
	enum { IDD = IDD_DIALOG_PATCHWS };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	virtual BOOL OnInitDialog();

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButtonUnpatch();
	int AddLog(CString strLog);

	afx_msg void OnBnClickedButton2();
	CComboBox m_comboxProName;
	virtual BOOL PreTranslateMessage(MSG* pMsg);
};
