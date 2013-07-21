#ifndef __COMHDR__
#define __COMHDR__


#define TAB_TDIFW		(0)

#define TAB_REDIRECT	(1)

#define TAB_UDPTRAFFIC	(2)

#define TAB_PATCHWS		(3)


#define TAB_MAX		TAB_PATCHWS+1


#include <Windows.h>
#include <vector>
#include <list>
#include <tchar.h>
#include <Iphlpapi.h>


#pragma comment(lib,"Iphlpapi.lib")

using namespace std;


typedef struct _STRING {
	 USHORT Length;
	 USHORT MaximumLength;
	PCHAR Buffer;
} STRING;

typedef STRING *PSTRING;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef struct __IPINFO__
{
	ULONG	localIP;
	ULONG	GatewayIP;

}IPINFO, *PIPINFO;


#include "..\public\public.h"

#include "RedirectControl.h"
#include "UdpTraffControl.h"
#include "PatchWS.h"
#include "NetworkCentre.h"
#include "CommFun.h"


extern HANDLE	g_CyberHandleASyn;

extern CRedirectControl	g_RedirectCtrltor;

#endif