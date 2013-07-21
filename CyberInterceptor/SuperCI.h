
// SuperCI.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// CSuperCIApp:
// See SuperCI.cpp for the implementation of this class
//

class CSuperCIApp : public CWinAppEx
{
public:
	CSuperCIApp();

// Overrides
	public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CSuperCIApp theApp;
CString fnDisplayError( DWORD dwErrorMsgId );
void	ExitByESC();