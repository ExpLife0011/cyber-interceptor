#pragma once
#include "afxwin.h"


// CUdpTraffic dialog

class CUdpTraffic : public CDialog
{
	DECLARE_DYNAMIC(CUdpTraffic)

public:
	CUdpTraffic(CWnd* pParent = NULL);   // standard constructor
	virtual ~CUdpTraffic();

// Dialog Data
	enum { IDD = IDD_DIALOG_UDPTRAFFIC };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual BOOL OnInitDialog();

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonSendudp();

	 


	CEdit m_edtRecv;
	CEdit m_edtSend;
	CEdit m_edtDstPort;
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	CEdit m_edtDstIP;
	CStatic m_statSendSize;
	afx_msg void OnEnChangeEditSend();
	virtual BOOL PreTranslateMessage(MSG* pMsg);
};
